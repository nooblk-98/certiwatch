"""Static and executable offline checks on the CI privacy and publish contract.

These do not execute GitHub Actions. They assert the workflow files keep the
properties the runtime tests cannot: PR jobs stay offline and secret-free,
private state never enters an Actions cache/artifact, production publishes only
from main, and a preview reaches Cloudflare only through a separate,
credential-free build and a default-branch publisher that validates the
artifact first.

They also execute the publisher's own shell and Python validation against
synthetic bundles, so the negative cases below test the code that runs in CI
rather than a copy of it.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import textwrap
import warnings
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "ssl-check.yml"
VERIFY = WORKFLOWS / "verify.yml"
PR_VERIFY = WORKFLOWS / "pr-verify.yml"
RELEASE_NOTES = WORKFLOWS / "release.yml"
BUILD = WORKFLOWS / "preview-build.yml"
PUBLISH = WORKFLOWS / "preview-publish.yml"

PREVIEW_BRANCHES = (
    "dev",
    "develop",
    "development",
    "development/*",
    "development/*/*",
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def strip_comments(text: str) -> str:
    lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    return "\n".join(lines)


def job_block(path: Path, job: str) -> str:
    content = read(path)
    match = re.search(rf"(?m)^  {re.escape(job)}:\n", content)
    assert match, f"{path.name}: {job} job is missing"
    start = match.end()
    following = re.search(r"(?m)^  [a-z0-9-]+:\n", content[start:])
    end = start + following.start() if following else len(content)
    return content[start:end]


def step_block(path: Path, name: str) -> str:
    content = read(path)
    match = re.search(rf"(?m)^      - name: {re.escape(name)}$", content)
    assert match, f"{path.name}: step {name!r} is missing"
    start = match.start()
    following = re.search(r"(?m)^      - name: ", content[match.end():])
    end = match.end() + following.start() if following else len(content)
    return content[start:end]


def run_script(path: Path, step: str) -> str:
    """Return the dedented contents of a step's `run: |` block."""
    block = step_block(path, step)
    match = re.search(r"(?ms)^        run: \|\n(.*)\Z", block)
    assert match, f"{path.name}: step {step!r} has no literal run block"
    return textwrap.dedent(match.group(1))


def trigger_block(path: Path) -> str:
    content = read(path)
    return content.split("on:\n", 1)[1].split("\njobs:\n", 1)[0]


def trigger_branches(path: Path) -> list[str]:
    """Branch entries of the first `branches:` list under `on:`."""
    triggers = trigger_block(path)
    match = re.search(r"(?m)^    branches:\n((?:      - .+\n)+)", triggers)
    assert match, f"{path.name}: no branch list on the trigger"
    return [
        line.split("- ", 1)[1].strip().strip('"').strip("'")
        for line in match.group(1).splitlines()
    ]


def used_actions(path: Path) -> list[str]:
    return re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", read(path))


def preview_validator_source() -> str:
    block = step_block(PUBLISH, "Validate preview bundle")
    match = re.search(r"(?ms)^          python3 - <<'PY'\n(.*?)^          PY$", block)
    assert match, "the preview validator heredoc is missing"
    return textwrap.dedent(match.group(1))


def test_only_the_expected_workflows_remain() -> None:
    assert {path.name for path in WORKFLOWS.glob("*.yml")} == {
        "ssl-check.yml",
        "verify.yml",
        "pr-verify.yml",
        "preview-build.yml",
        "preview-publish.yml",
    }
    assert not RELEASE_NOTES.exists()
    assert "copilot-release-notes-action" not in "".join(
        read(path) for path in WORKFLOWS.glob("*.yml")
    )


def test_every_action_is_pinned_to_a_commit() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        for ref in used_actions(path):
            if ref.startswith("./"):
                continue  # Local reusable workflow.
            assert re.search(r"@[0-9a-f]{40}$", ref), (
                f"{path.name}: action {ref!r} is not pinned to a full commit SHA"
            )


def test_reusable_verify_is_offline_and_has_no_state_inputs() -> None:
    verify = read(VERIFY)
    assert "workflow_call" in verify
    assert "secrets." not in verify
    assert "alert_state_store.py" not in verify
    assert "history.json" not in verify
    assert "src/ssl/scripts/check_ssl.py" not in verify
    assert "src/domain/scripts/check_domains.py" not in verify
    assert "python -m pytest -q -p no:cacheprovider" in verify
    assert "node --test tests/dashboard.test.mjs" in verify
    assert "python3 scripts/test_build_dist.py" in verify
    assert "src/validate_conf.py --config certiwatch.toml --no-dns" in verify


def test_dedicated_pr_workflow_uses_reusable_verify() -> None:
    pr = read(PR_VERIFY)
    assert "pull_request:" in pr
    assert "uses: ./.github/workflows/verify.yml" in pr
    assert "secrets." not in pr
    assert "pages deploy" not in pr.lower()
    assert "alert_state_store" not in pr
    assert "history.json" not in pr
    assert "persist-credentials" not in pr
    # A pull request is never a preview trigger.
    assert "preview-build" not in pr


def test_production_triggers_are_main_schedule_and_dispatch() -> None:
    triggers = trigger_block(WORKFLOW)
    assert "pull_request:" not in triggers
    assert "pull_request_target" not in triggers
    assert "workflow_run" not in triggers
    assert trigger_branches(WORKFLOW) == ["main"]
    for retired in ("dev", "develop", "development", "development/*"):
        assert retired not in triggers
    assert re.search(r'(?m)^\s+- cron: "30 0 \* \* \*"$', triggers)
    assert "workflow_dispatch:" in triggers
    # Feature branches, tags and other refs are not deployment triggers.
    assert re.search(r"(?m)^\s+tags:", triggers) is None


def test_only_the_publisher_may_listen_to_workflow_runs() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        content = read(path)
        assert "contents: write" not in content, path.name
        assert "pull_request_target" not in content, path.name
        if path != PUBLISH:
            assert "workflow_run:" not in trigger_block(path), path.name
    assert "workflow_run:" in read(PUBLISH)
    # Nothing outside the publisher gets repository write access.
    permissions = strip_comments(read(PUBLISH))
    assert "contents: read" in permissions
    assert "actions: read" in permissions


def test_concurrency_never_cancels_a_production_run() -> None:
    content = read(WORKFLOW)
    assert "group: certiwatch-${{ github.ref }}" in content
    assert "cancel-in-progress: false" in content


def test_production_is_main_only_and_depends_on_verify() -> None:
    publish = job_block(WORKFLOW, "publish")
    assert "if: github.ref == 'refs/heads/main'" in publish
    assert "needs: verify" in publish
    assert "github.event_name != 'pull_request'" not in publish
    assert "pages deploy" in publish.lower()


def test_production_uses_environment_only_credentials() -> None:
    publish = strip_comments(job_block(WORKFLOW, "publish"))
    assert "environment:" in publish
    assert "name: certiwatch-production" in publish
    for name in (
        "CERTIWATCH_PRODUCTION_PAGES_API_TOKEN",
        "CERTIWATCH_PRODUCTION_PAGES_ACCOUNT_ID",
        "CERTIWATCH_PRODUCTION_DISCORD_WEBHOOK",
        "CERTIWATCH_PRODUCTION_STATE_KV_TOKEN",
    ):
        assert f"secrets.{name}" in publish, name
    # The trusted, non-secret account id is the cross-check anchor.
    assert "vars.CERTIWATCH_PRODUCTION_ACCOUNT_ID" in publish
    assert '"$PAGES_ACCOUNT" != "$TRUSTED_ACCOUNT"' in publish


def test_no_workflow_reads_retired_repository_secrets() -> None:
    retired = (
        "secrets.CLOUDFLARE_API_TOKEN",
        "secrets.CLOUDFLARE_ACCOUNT_ID",
        "secrets.CLOUDFLARE_PREVIEW_API_TOKEN",
        "secrets.CLOUDFLARE_PREVIEW_ACCOUNT_ID",
        "secrets.CERTIWATCH_DISCORD_WEBHOOK",
        "secrets.CERTIWATCH_STATE_KV_TOKEN",
        "vars.CLOUDFLARE_PAGES_PROJECT",
        "vars.CERTIWATCH_STATE_KV_NAMESPACE",
        "vars.CERTIWATCH_ALERTS_ENABLED",
    )
    for path in WORKFLOWS.glob("*.yml"):
        content = read(path)
        for name in retired:
            assert name not in content, f"{path.name} still reads {name}"


def test_preview_build_is_secret_free_and_never_deploys() -> None:
    content = strip_comments(read(BUILD))
    assert "secrets." not in content
    assert "environment:" not in content
    assert "pages deploy" not in content.lower()
    assert "persist-credentials: false" in content
    assert "contents: read" in content
    assert "actions: write" not in content
    # The build runs on exactly the supported development branches.
    assert tuple(trigger_branches(BUILD)) == PREVIEW_BRANCHES
    assert "pull_request" not in trigger_block(BUILD)


def test_preview_build_uploads_only_the_bundle() -> None:
    upload = step_block(BUILD, "Upload preview bundle")
    assert (
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
        in upload
    )
    assert "name: certiwatch-preview-bundle" in upload
    assert "path: dist/" in upload
    assert "if-no-files-found: error" in upload
    assert "retention-days: 3" in upload
    assert "include-hidden-files: false" in upload
    # No history, KV state or alert transport in a preview build.
    build = strip_comments(job_block(BUILD, "build"))
    assert "history.json" not in build
    assert "monitor_state.py" not in build
    assert "alert_state_store" not in build
    assert "CERTIWATCH_DISCORD_WEBHOOK" not in build
    assert "actions/cache" not in build


def test_preview_publish_gates_the_source_run_and_branch() -> None:
    publish = job_block(PUBLISH, "publish")
    condition = publish.split("    if:", 1)[1].split("    environment:", 1)[0]
    for clause in (
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.event == 'push'",
        "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
        "github.event.workflow_run.path == '.github/workflows/preview-build.yml'",
        "github.event.workflow_run.repository.full_name == github.repository",
        "github.event.workflow_run.head_repository.full_name == github.repository",
        "github.event.workflow_run.head_branch == 'dev'",
        "github.event.workflow_run.head_branch == 'develop'",
        "github.event.workflow_run.head_branch == 'development'",
        "startsWith(github.event.workflow_run.head_branch, 'development/')",
    ):
        assert clause in condition, clause
    assert "pull_request" not in condition
    # The event filter and the code gate must cover the same branches, or a
    # push could build a preview that never publishes, or vice versa.
    workflows = trigger_block(PUBLISH)
    assert "workflows:" in workflows
    assert 'workflows: ["CertiWatch preview build"]' in workflows
    assert tuple(trigger_branches(PUBLISH)) == PREVIEW_BRANCHES


def test_preview_publish_uses_main_only_environment_and_no_production_secrets() -> None:
    publish = strip_comments(job_block(PUBLISH, "publish"))
    assert "name: certiwatch-preview" in publish
    # The environment policy must allow main only; the job runs from the
    # default branch, so a development ref can never claim these secrets.
    assert "name: certiwatch-preview" in publish
    assert "CERTIWATCH_PREVIEW_PAGES_API_TOKEN" in publish
    assert "CERTIWATCH_PREVIEW_PAGES_ACCOUNT_ID" in publish
    for production_secret in (
        "secrets.CERTIWATCH_PRODUCTION_PAGES_API_TOKEN",
        "secrets.CERTIWATCH_PRODUCTION_PAGES_ACCOUNT_ID",
        "secrets.CERTIWATCH_PRODUCTION_DISCORD_WEBHOOK",
        "secrets.CERTIWATCH_PRODUCTION_STATE_KV_TOKEN",
    ):
        assert production_secret not in publish, production_secret
    # The preview never reads production state or alerts. (The validator names
    # history.json only to reject it.)
    assert "path: history.json" not in publish
    assert "alert_state_store" not in publish
    assert "monitor_state.py" not in publish
    assert "actions/cache" not in publish
    assert "CERTIWATCH_STATE_KV" not in publish
    assert "CERTIWATCH_DISCORD" not in publish


def test_preview_publish_never_checks_out_or_executes_branch_code() -> None:
    content = read(PUBLISH)
    # No checkout at all: not the source branch, not even the default branch.
    assert "actions/checkout" not in content
    assert "git checkout" not in content
    assert "persist-credentials" not in content
    # The source commit is used only as display text, never as a ref.
    for line in content.splitlines():
        if "head_sha" in line and not line.lstrip().startswith("#"):
            assert "HEAD_SHA:" in line, line
    # No repository script or package install runs in the credentialed job.
    assert "scripts/" not in content
    assert "pip install" not in content
    assert "npm " not in content
    assert "pytest" not in content
    validator = step_block(PUBLISH, "Validate preview bundle")
    assert "python3 - <<'PY'" in validator
    assert "python3 scripts/" not in validator


def test_preview_publish_binds_the_exact_artifact() -> None:
    archive = step_block(PUBLISH, "Inspect and extract preview artifact")
    # No extraction action: the untrusted ZIP is handled by our own code.
    assert "actions/download-artifact" not in read(PUBLISH)
    assert "GH_TOKEN: ${{ github.token }}" in archive
    assert "REPO: ${{ github.repository }}" in archive
    assert "RUN_ID: ${{ github.event.workflow_run.id }}" in archive
    assert "API_URL: ${{ github.api_url }}" in archive
    assert "inputs." not in archive
    # Metadata, compressed bound, central directory and extraction all live in
    # the one step, before any Cloudflare credential.
    for token in (
        "/actions/runs/",
        "/artifacts",
        "total_count",
        "size_in_bytes",
        "MAX_ARCHIVE",
        "zipfile.ZipFile",
        "infolist",
        "duplicate archive member",
        "MAX_RATIO",
        "stream_to_path",
    ):
        assert token in archive, token
    content = read(PUBLISH)
    assert content.index("Inspect and extract preview artifact") < content.index(
        "Verify preview credentials and destination"
    )
    publish = strip_comments(content)
    assert "actions: read" in publish


def test_preview_requires_explicit_distinct_project_and_shared_account() -> None:
    resolve = strip_comments(step_block(PUBLISH, "Resolve preview target"))
    check = strip_comments(step_block(PUBLISH, "Verify preview credentials and destination"))
    # A preview project is required and may never default to production.
    assert 'project="${PAGES_PROJECT:-}"' in resolve
    assert "PAGES_PROJECT:-certiwatch" not in resolve
    assert "CERTIWATCH_PREVIEW_PROJECT" in resolve
    assert '"$project" = "$production_project"' in resolve
    # Same account is now required, not forbidden.
    assert '"$PAGES_ACCOUNT" != "$TRUSTED_ACCOUNT"' in check
    assert "CLOUDFLARE_PRODUCTION_ACCOUNT_ID" not in check
    # Every value interpolated into the deploy command is allowlisted.
    command = "\n".join(
        line.strip()
        for line in step_block(PUBLISH, "Deploy preview to Cloudflare Pages").splitlines()
        if line.strip().startswith("command:")
    )
    assert "${{ env.CERTIWATCH_PAGES_PROJECT }}" in command
    assert "${{ env.CERTIWATCH_PAGES_BRANCH }}" in command
    assert "${{ vars." not in command
    assert "${{ github." not in command
    # The deploy source is a fixed path, not an environment-supplied one.
    assert "pages deploy preview-bundle" in command
    assert "PREVIEW_BUNDLE_DIR" not in command


def test_preview_alias_is_always_a_non_production_alias() -> None:
    resolve = strip_comments(step_block(PUBLISH, "Resolve preview target"))
    assert "FULL_REF: ${{ format('refs/heads/{0}', github.event.workflow_run.head_branch) }}" in resolve
    assert 'branch="preview-${slug}-${digest}"' in resolve
    assert "sha256sum" in resolve
    assert "cut -c1-8" in resolve
    # The hash covers the full ref, not the sanitised slug.
    assert 'printf \'%s\' "$FULL_REF"' in resolve
    assert '[ "$branch" = "main" ]' in resolve
    command = step_block(PUBLISH, "Deploy preview to Cloudflare Pages")
    assert "--branch=main" not in command
    assert "--project-name=main" not in command


def test_production_deploy_uses_validated_project() -> None:
    publish = job_block(WORKFLOW, "publish")
    assert "Resolve Pages project" in publish
    assert "GITHUB_ENV" in publish
    command = "\n".join(
        line.strip()
        for line in publish.splitlines()
        if line.strip().startswith("command:")
    )
    assert "--branch=main" in command
    assert "${{ env.CERTIWATCH_PAGES_PROJECT }}" in command
    assert "${{ vars." not in command


def test_public_history_uses_cache_only_for_production() -> None:
    publish = job_block(WORKFLOW, "publish")
    assert "actions/cache/restore@" in publish
    assert "actions/cache/save@" in publish
    assert "path: history.json" in publish
    assert "certiwatch-history-" in publish
    assert "actions/cache" not in read(BUILD)
    assert "actions/cache" not in read(PUBLISH)


def test_private_state_uses_kv_not_cache_or_artifact() -> None:
    publish = job_block(WORKFLOW, "publish")
    assert "scripts/alert_state_store.py pull" in publish
    assert "CERTIWATCH_STATE_KV_NAMESPACE" in publish
    assert "CERTIWATCH_STATE_KV_TOKEN" in publish
    assert "actions/upload-artifact" not in publish
    assert "path: .certiwatch" not in publish
    assert "path: .certiwatch/" not in publish


def test_remote_checkpoint_is_chosen_before_discord() -> None:
    publish = job_block(WORKFLOW, "publish")
    assert "checkpoint=kv" in publish
    assert '--checkpoint "$checkpoint"' in publish
    assert "transport=discord" in publish
    assert publish.index("checkpoint=kv") < publish.index('--checkpoint "$checkpoint"')


def test_bundle_is_built_before_deploy_and_wrangler_is_pinned() -> None:
    publish = job_block(WORKFLOW, "publish")
    assert publish.index("python3 scripts/build_dist.py --out dist") < publish.index(
        "Deploy to Cloudflare Pages"
    )
    assert (
        "cloudflare/wrangler-action@9acf94ace14e7dc412b076f2c5c20b8ce93c79cd"
        in publish
    )
    preview = read(PUBLISH)
    assert (
        "cloudflare/wrangler-action@9acf94ace14e7dc412b076f2c5c20b8ce93c79cd"
        in preview
    )
    # The publisher pins the CLI version it installs instead of floating on
    # the latest 3.x release.
    assert 'wranglerVersion: "3.114.17"' in preview


def test_build_side_limits_match_the_publisher() -> None:
    bound = run_script(BUILD, "Bound the bundle before upload")
    assert '"$files" -gt 1500' in bound
    assert '"$bytes" -gt 26214400' in bound
    validator = preview_validator_source()
    assert "MAX_FILES = 1500" in validator
    assert "MAX_TOTAL = 25 * 1024 * 1024" in validator
    assert "MAX_FILE = 8 * 1024 * 1024" in validator


# --- Executable publisher checks -------------------------------------------


def bundle_files(*, badges: int = 1) -> dict[str, bytes]:
    """Minimal static bundle that satisfies the publisher's validators."""
    files: dict[str, bytes] = {
        "index.html": b"<!DOCTYPE html>\n<html><body>ok</body></html>\n",
        "app.js": b"console.log('ok')\n",
        "style.css": b"body{}\n",
        "_headers": b"/*\n  X-Test: 1\n",
        "ssl_results.json": json.dumps(
            {
                "generated_at": "2026-11-21T00:00:00Z",
                "results": [
                    {"domain": "example.com", "status": "valid", "days_left": 30}
                ],
            }
        ).encode(),
        "domain_results.json": json.dumps(
            {
                "generated_at": "2026-11-21T00:00:00Z",
                "results": [
                    {"domain": "example.com", "status": "active", "days_left": 300}
                ],
            }
        ).encode(),
        "status.json": json.dumps(
            {
                "schema_version": 1,
                "generated_at": "2026-11-21T00:00:00Z",
                "domains": [],
            }
        ).encode(),
        "expiries.ics": b"BEGIN:VCALENDAR\nEND:VCALENDAR\n",
    }
    manifest: dict[str, dict] = {}
    for index in range(badges):
        digest = hashlib.sha256(str(index).encode()).hexdigest()[:32]
        name = f"badges/example-{index}-{digest}.svg"
        svg = f"<svg xmlns='http://www.w3.org/2000/svg'><!--{index}--></svg>\n".encode()
        files[name] = svg
        manifest[f"example-{index}.com"] = {
            "path": f"/{name}",
            "status": "ok",
            "color": "green",
            "sha256": hashlib.sha256(svg).hexdigest(),
        }
    files["badges/manifest.json"] = json.dumps(
        {
            "schema_version": 1,
            "generated_at": "2026-11-21T00:00:00Z",
            "badges": manifest,
        }
    ).encode()
    return files


def write_bundle(root: Path, *, badges: int = 1) -> Path:
    """Write a bundle where the publisher's validator expects it."""
    dist = root / "preview-bundle"
    for name, data in bundle_files(badges=badges).items():
        path = dist / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return dist


def archive_source() -> str:
    block = step_block(PUBLISH, "Inspect and extract preview artifact")
    match = re.search(r"(?ms)^          python3 - <<'PY'\n(.*?)^          PY$", block)
    assert match, "the artifact inspection heredoc is missing"
    return textwrap.dedent(match.group(1))


def archive_module() -> dict:
    namespace: dict = {"__name__": "preview_artifact_under_test"}
    exec(compile(archive_source(), "<preview-artifact>", "exec"), namespace)
    return namespace


def write_zip(path: Path, pairs, compression: int = zipfile.ZIP_DEFLATED) -> None:
    """Write a ZIP from (name or ZipInfo, bytes) pairs."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(path, "w", compression) as archive:
            for name, data in pairs:
                archive.writestr(name, data)


def run_validator(cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", preview_validator_source()],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def test_validator_accepts_a_well_formed_bundle(tmp_path: Path) -> None:
    write_bundle(tmp_path)
    result = run_validator(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Validated" in result.stdout
    assert "bundle sha256:" in result.stdout


def mutate_extra_file(dist: Path) -> None:
    (dist / "extra.html").write_text("<html>extra</html>\n", encoding="utf-8")


def mutate_functions_directory(dist: Path) -> None:
    (dist / "functions").mkdir()
    (dist / "functions" / "index.js").write_text("export default {}\n")


def mutate_worker(dist: Path) -> None:
    (dist / "_worker.js").write_text("export default {}\n")


def mutate_redirects(dist: Path) -> None:
    (dist / "_redirects").write_text("/* https://example.org 301\n")


def mutate_history(dist: Path) -> None:
    (dist / "history.json").write_text('{"snapshots": []}\n')


def mutate_nested_badge_directory(dist: Path) -> None:
    (dist / "badges" / "nested").mkdir()
    (dist / "badges" / "nested" / "x.svg").write_text("<svg/>\n")


def mutate_badge_substitution(dist: Path) -> None:
    badge = next((dist / "badges").glob("*.svg"))
    badge.write_text("<svg>tampered</svg>\n")


def mutate_badge_manifest_missing(dist: Path) -> None:
    (dist / "badges" / "manifest.json").unlink()


def mutate_badge_unlisted(dist: Path) -> None:
    (dist / "badges" / "unlisted.svg").write_text("<svg/>\n")


def mutate_symlink(dist: Path) -> None:
    (dist / "app.js").unlink()
    os.symlink("/etc/passwd", dist / "app.js")


def mutate_empty_file(dist: Path) -> None:
    (dist / "style.css").write_text("")


def mutate_missing_required(dist: Path) -> None:
    (dist / "status.json").unlink()


def mutate_no_ssl_verdict(dist: Path) -> None:
    target = dist / "ssl_results.json"
    data = json.loads(target.read_text())
    data["results"][0]["status"] = "connect_error"
    target.write_text(json.dumps(data))


def mutate_bad_html(dist: Path) -> None:
    (dist / "index.html").write_text("<html>not a doctype</html>\n")


def mutate_oversized(dist: Path) -> None:
    (dist / "app.js").write_bytes(b"x" * (8 * 1024 * 1024 + 1))


NEGATIVE_BUNDLES = (
    ("extra file", mutate_extra_file, "outside the static allowlist"),
    ("pages functions", mutate_functions_directory, "unexpected directory"),
    ("pages worker", mutate_worker, "worker scripts are not permitted"),
    ("redirects", mutate_redirects, "redirects are not permitted"),
    ("history leak", mutate_history, "must not contain public history"),
    ("nested badge directory", mutate_nested_badge_directory, "unexpected directory"),
    ("badge content substitution", mutate_badge_substitution, "does not match the manifest"),
    ("badge manifest removed", mutate_badge_manifest_missing, "missing required files"),
    ("unlisted badge", mutate_badge_unlisted, "outside the static allowlist"),
    ("symlinked file", mutate_symlink, "symlink"),
    ("empty file", mutate_empty_file, "empty file"),
    ("missing required file", mutate_missing_required, "missing required files"),
    ("no observed certificate", mutate_no_ssl_verdict, "no observed certificate verdict"),
    ("non-html index", mutate_bad_html, "not an HTML document"),
    ("oversized file", mutate_oversized, "limit is"),
)


def test_validator_rejects_unsafe_bundles(tmp_path: Path) -> None:
    for label, mutate, expected in NEGATIVE_BUNDLES:
        case = tmp_path / re.sub(r"[^a-z0-9]+", "-", label.lower())
        case.mkdir()
        dist = write_bundle(case)
        mutate(dist)
        result = run_validator(case)
        assert result.returncode != 0, f"{label} was accepted"
        assert expected in result.stderr, f"{label}: {result.stderr}"


def test_validator_rejects_an_oversized_total(tmp_path: Path) -> None:
    dist = write_bundle(tmp_path, badges=4)
    for badge in sorted((dist / "badges").glob("*.svg")):
        badge.write_bytes(b"x" * (7 * 1024 * 1024))
    manifest = json.loads((dist / "badges" / "manifest.json").read_text())
    for entry in manifest["badges"].values():
        entry["sha256"] = hashlib.sha256(b"x" * (7 * 1024 * 1024)).hexdigest()
    (dist / "badges" / "manifest.json").write_text(json.dumps(manifest))
    result = run_validator(tmp_path)
    assert result.returncode != 0
    assert "exceeds" in result.stderr


# --- Archive boundary -------------------------------------------------------


def artifact_document(**overrides) -> dict:
    entry = {
        "name": "certiwatch-preview-bundle",
        "id": 42,
        "expired": False,
        "size_in_bytes": 4096,
    }
    entry.update(overrides)
    return {"total_count": 1, "artifacts": [entry]}


def test_artifact_metadata_requires_one_expected_bounded_record() -> None:
    select = archive_module()["select_artifact"]
    assert select(artifact_document(), "certiwatch-preview-bundle")["id"] == 42

    rejected = (
        ("no artifact", {"total_count": 0, "artifacts": []}),
        ("two artifacts", {"total_count": 2, "artifacts": [artifact_document()["artifacts"][0]] * 2}),
        ("wrong name", artifact_document(name="another-bundle")),
        ("expired", artifact_document(expired=True)),
        ("unknown expiry", artifact_document(expired=None)),
        ("missing id", artifact_document(id=None)),
        ("boolean id", artifact_document(id=True)),
        ("zero size", artifact_document(size_in_bytes=0)),
        ("string size", artifact_document(size_in_bytes="4096")),
        ("oversized", artifact_document(size_in_bytes=32 * 1024 * 1024 + 1)),
    )
    for label, document in rejected:
        with pytest.raises(SystemExit) as error:
            select(document, "certiwatch-preview-bundle")
        assert "preview artifact rejected" in str(error.value), label


def test_download_stream_limit_counts_real_bytes(tmp_path: Path) -> None:
    stream_to_path = archive_module()["stream_to_path"]
    dest = tmp_path / "exact.bin"
    total, digest = stream_to_path(io.BytesIO(b"x" * 1024), dest, 1024)
    assert total == 1024
    assert dest.stat().st_size == 1024
    assert len(digest) == 64

    too_big = tmp_path / "too-big.bin"
    with pytest.raises(SystemExit) as error:
        stream_to_path(io.BytesIO(b"x" * 1025), too_big, 1024)
    assert "exceeded" in str(error.value)
    assert not too_big.exists()


def test_archive_extracts_a_valid_bundle_for_the_validator(tmp_path: Path) -> None:
    files = bundle_files()
    archive = tmp_path / "artifact.zip"
    write_zip(archive, files.items())
    out = tmp_path / "preview-bundle"

    stats = archive_module()["inspect_and_extract"](archive, out)
    assert stats["members"] == len(files)
    assert (out / "index.html").read_bytes() == files["index.html"]
    result = run_validator(tmp_path)
    assert result.returncode == 0, result.stderr


def expect_archive_rejected(archive: Path, out: Path, expected: str) -> None:
    try:
        archive_module()["inspect_and_extract"](archive, out)
    except SystemExit as error:
        assert expected in str(error), str(error)
    else:
        raise AssertionError("the archive was accepted")
    assert not out.exists(), "a rejected archive extracted files"


def test_archive_rejects_unsafe_members(tmp_path: Path) -> None:
    base = bundle_files()

    def entries(**changes) -> list:
        files = dict(base)
        files.update(changes)
        return list(files.items())

    def duplicate_pairs() -> list:
        pairs = list(base.items())
        pairs.append(("app.js", b"console.log('second')\n"))
        return pairs

    def info_entry(name: str, data: bytes, mode: int) -> tuple:
        info = zipfile.ZipInfo(name)
        info.external_attr = mode << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        return info, data

    cases = (
        ("duplicate member", duplicate_pairs(), "duplicate archive member"),
        ("parent traversal", entries(**{"../index.html": b"x"}), "escapes the bundle root"),
        ("absolute path", entries(**{"/index.html": b"x"}), "absolute or non-POSIX"),
        ("backslash path", entries(**{"badges\\x.svg": b"x"}), "absolute or non-POSIX"),
        ("directory member", entries(**{"badges/": b""}), "not permitted"),
        ("symlink member", [info_entry("app.js", b"/etc/passwd", stat.S_IFLNK | 0o777)], "symlink member"),
        ("fifo member", [info_entry("app.js", b"x", stat.S_IFIFO | 0o644)], "not a regular file"),
        ("unknown file", entries(**{"extra.html": b"x"}), "outside the static allowlist"),
        ("empty member", entries(**{"app.js": b""}), "empty member"),
        ("missing required", list((k, v) for k, v in base.items() if k != "status.json"), "missing required files"),
        ("oversized declared", entries(**{"app.js": b"x" * (8 * 1024 * 1024 + 1)}), "limit is"),
        ("compression ratio", entries(**{"app.js": b"\0" * (8 * 1024 * 1024)}), "unsafe compression ratio"),
    )
    for index, (label, pairs, expected) in enumerate(cases):
        case = tmp_path / f"case-{index}"
        case.mkdir()
        archive = case / "artifact.zip"
        write_zip(archive, pairs)
        expect_archive_rejected(archive, case / "preview-bundle", expected)


def test_archive_rejects_an_oversized_aggregate(tmp_path: Path) -> None:
    files = dict(bundle_files(badges=4))
    for name in list(files):
        if name.startswith("badges/") and name != "badges/manifest.json":
            files[name] = b"x" * (7 * 1024 * 1024)
    archive = tmp_path / "artifact.zip"
    # Stored members keep the compression-ratio guard out of the way so this
    # case exercises the aggregate declared-size limit itself.
    write_zip(archive, files.items(), compression=zipfile.ZIP_STORED)
    expect_archive_rejected(archive, tmp_path / "preview-bundle", "declare more than")


def test_archive_rejects_too_many_members(tmp_path: Path) -> None:
    files = {
        f"badges/example-{index}-{hashlib.sha256(str(index).encode()).hexdigest()[:32]}.svg": b"<svg/>"
        for index in range(1501)
    }
    archive = tmp_path / "artifact.zip"
    write_zip(archive, files.items())
    expect_archive_rejected(archive, tmp_path / "preview-bundle", "limit is 1500")


def test_archive_rejects_unsupported_compression(tmp_path: Path) -> None:
    archive = tmp_path / "lzma.zip"
    write_zip(archive, [("index.html", b"<html></html>")], compression=zipfile.ZIP_LZMA)
    expect_archive_rejected(archive, tmp_path / "out", "unsupported compression method")


def test_archive_rejects_malformed_and_truncated_zips(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.zip"
    malformed.write_bytes(b"PK\x03\x04" + b"\0" * 100)
    expect_archive_rejected(malformed, tmp_path / "out-a", "not a readable ZIP")

    valid = tmp_path / "valid.zip"
    write_zip(valid, bundle_files().items())
    truncated = tmp_path / "truncated.zip"
    truncated.write_bytes(valid.read_bytes()[:-20])
    expect_archive_rejected(truncated, tmp_path / "out-b", "not a readable ZIP")


def run_resolve_step(tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    script = run_script(PUBLISH, "Resolve preview target")
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GITHUB_ENV": str(tmp_path / "github-env"),
        "PRODUCTION_PROJECT": "certiwatch",
        "PAGES_PROJECT": "certiwatch-preview",
        "HEAD_BRANCH": "dev",
        "FULL_REF": "refs/heads/dev",
    }
    environment.update(env)
    Path(environment["GITHUB_ENV"]).write_text("")
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_resolve_step_accepts_supported_branches(tmp_path: Path) -> None:
    for branch in (
        "dev",
        "develop",
        "development",
        "development/api",
        "development/team/feature",
    ):
        result = run_resolve_step(
            tmp_path,
            {
                "HEAD_BRANCH": branch,
                "FULL_REF": f"refs/heads/{branch}",
            },
        )
        assert result.returncode == 0, (branch, result.stderr)
        written = (tmp_path / "github-env").read_text()
        alias = re.search(r"CERTIWATCH_PAGES_BRANCH=(\S+)", written).group(1)
        assert alias.startswith("preview-"), alias
        assert alias != "main"
        assert len(alias) <= 64
        (tmp_path / "github-env").write_text("")


def test_resolve_step_rejects_disallowed_branches(tmp_path: Path) -> None:
    for branch in (
        "main",
        "feature/x",
        "development/a/b/c",
        "release/1.0",
        "dev/../main",
    ):
        result = run_resolve_step(
            tmp_path,
            {"HEAD_BRANCH": branch, "FULL_REF": f"refs/heads/{branch}"},
        )
        assert result.returncode != 0, f"{branch} was accepted"
        assert (tmp_path / "github-env").read_text() == ""


def test_resolve_step_rejects_production_project_or_missing_project(tmp_path: Path) -> None:
    result = run_resolve_step(tmp_path, {"PAGES_PROJECT": "certiwatch"})
    assert result.returncode != 0
    assert "must differ" in result.stdout
    result = run_resolve_step(tmp_path, {"PAGES_PROJECT": ""})
    assert result.returncode != 0
    assert "is required" in result.stdout
    result = run_resolve_step(tmp_path, {"PAGES_PROJECT": "Bad_Name"})
    assert result.returncode != 0
    assert "lowercase" in result.stdout


def run_credential_step(
    tmp_path: Path, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    script = run_script(PUBLISH, "Verify preview credentials and destination")
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PAGES_TOKEN": "token",
        "PAGES_ACCOUNT": "account-1",
        "TRUSTED_ACCOUNT": "account-1",
    }
    environment.update(env)
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_credential_step_requires_the_shared_account_and_both_secrets(
    tmp_path: Path,
) -> None:
    assert run_credential_step(tmp_path, {}).returncode == 0
    different = run_credential_step(tmp_path, {"PAGES_ACCOUNT": "account-2"})
    assert different.returncode != 0
    assert "same Cloudflare account" in different.stdout
    missing_token = run_credential_step(tmp_path, {"PAGES_TOKEN": ""})
    assert missing_token.returncode != 0
    missing_account = run_credential_step(tmp_path, {"PAGES_ACCOUNT": ""})
    assert missing_account.returncode != 0
    assert "needs CERTIWATCH_PREVIEW" in missing_account.stdout
    missing_trusted = run_credential_step(tmp_path, {"TRUSTED_ACCOUNT": ""})
    assert missing_trusted.returncode != 0
    assert "CERTIWATCH_PRODUCTION_ACCOUNT_ID" in missing_trusted.stdout


def test_readme_documents_same_account_migration_and_public_previews() -> None:
    readme = read(ROOT / "README.md")
    for token in (
        "certiwatch-production",
        "certiwatch-preview",
        "CERTIWATCH_PRODUCTION_ACCOUNT_ID",
        "CERTIWATCH_PREVIEW_PROJECT",
        "CERTIWATCH_PREVIEW_PAGES_API_TOKEN",
        "development/*/*",
        "same Cloudflare account",
        "preview-",
    ):
        assert token in readme, token
    assert "Delete all of those old repository-level secrets" in readme
    assert "Protect `main`" in readme
    assert "Preview results are public" in readme
