"""Static, offline checks on the CI privacy and publish contract.

These do not execute GitHub Actions. They assert the workflow files keep the
properties the runtime tests cannot: PR jobs stay offline and secret-free,
private state never enters an Actions cache/artifact, production publishes only
from main, and previews deploy only the named development branches with
environment-scoped credentials.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "ssl-check.yml"
VERIFY = WORKFLOWS / "verify.yml"
PR_VERIFY = WORKFLOWS / "pr-verify.yml"
RELEASE_NOTES = WORKFLOWS / "release.yml"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def strip_comments(text: str) -> str:
    lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    return "\n".join(lines)


def job_block(job: str) -> str:
    content = read(WORKFLOW)
    match = re.search(rf"(?m)^  {re.escape(job)}:\n", content)
    assert match, f"{job} job is missing"
    start = match.end()
    following = re.search(r"(?m)^  [a-z0-9-]+:\n", content[start:])
    end = start + following.start() if following else len(content)
    return content[start:end]


def trigger_block() -> str:
    content = read(WORKFLOW)
    return content.split("on:\n", 1)[1].split("\njobs:\n", 1)[0]


def deploy_command_lines(job: str) -> list[str]:
    return [
        line.strip()
        for line in job_block(job).splitlines()
        if line.strip().startswith("command:")
    ]


def used_actions(path: Path) -> list[str]:
    return re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", read(path))


def test_only_the_deployment_and_verification_workflows_remain() -> None:
    assert {path.name for path in WORKFLOWS.glob("*.yml")} == {
        "ssl-check.yml",
        "verify.yml",
        "pr-verify.yml",
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


def test_triggers_are_main_and_named_development_branches() -> None:
    triggers = trigger_block()
    assert "pull_request:" not in triggers
    assert "pull_request_target" not in triggers
    assert "workflow_run" not in triggers
    for branch in (
        "main",
        "dev",
        "develop",
        "development",
        '"development/*"',
        '"development/*/*"',
    ):
        assert re.search(rf"(?m)^      - {re.escape(branch)}$", triggers), branch
    # An unbounded prefix would not be expressible as an environment policy.
    assert "development/**" not in triggers
    assert re.search(r'(?m)^\s+- cron: "30 0 \* \* \*"$', triggers)
    assert "workflow_dispatch:" in triggers
    # Feature branches, tags and other refs are not deployment triggers.
    assert re.search(r"(?m)^\s+tags:", triggers) is None


def test_workflow_has_read_only_permissions() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        content = read(path)
        assert "contents: write" not in content, path.name
        assert "pull_request_target" not in content, path.name
        assert "workflow_run" not in content, path.name


def test_concurrency_never_cancels_a_production_run() -> None:
    content = read(WORKFLOW)
    assert "group: certiwatch-${{ github.ref }}" in content
    assert "cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}" in content


def test_production_is_main_only_and_depends_on_verify() -> None:
    publish = job_block("publish")
    assert "if: github.ref == 'refs/heads/main'" in publish
    assert "needs: verify" in publish
    assert "github.event_name != 'pull_request'" not in publish
    assert "pages deploy" in publish.lower()


def test_production_uses_environment_only_credentials() -> None:
    publish = strip_comments(job_block("publish"))
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


def test_preview_is_push_only_on_development_branches() -> None:
    preview = strip_comments(job_block("publish-preview"))
    assert "github.event_name == 'push'" in preview
    for ref in (
        "github.ref == 'refs/heads/dev'",
        "github.ref == 'refs/heads/develop'",
        "github.ref == 'refs/heads/development'",
        "startsWith(github.ref, 'refs/heads/development/')",
    ):
        assert ref in preview, ref
    assert "needs: verify" in preview
    assert "pages deploy" in preview.lower()
    # A manual dispatch may verify but never deploy a preview.
    assert "workflow_dispatch" not in preview


def test_preview_uses_environment_scoped_credentials_only() -> None:
    preview = strip_comments(job_block("publish-preview"))
    assert "environment:" in preview
    assert "name: certiwatch-preview" in preview
    assert "secrets.CLOUDFLARE_PREVIEW_API_TOKEN" in preview
    assert "secrets.CLOUDFLARE_PREVIEW_ACCOUNT_ID" in preview
    # Never fall back to production credentials if a preview secret is
    # missing; the job fails in its explicit credential check instead.
    for production_secret in (
        "secrets.CERTIWATCH_PRODUCTION_PAGES_API_TOKEN",
        "secrets.CERTIWATCH_PRODUCTION_PAGES_ACCOUNT_ID",
        "secrets.CERTIWATCH_PRODUCTION_DISCORD_WEBHOOK",
        "secrets.CERTIWATCH_PRODUCTION_STATE_KV_TOKEN",
        "secrets.CLOUDFLARE_API_TOKEN",
        "secrets.CLOUDFLARE_ACCOUNT_ID",
    ):
        assert production_secret not in preview, production_secret


def test_preview_never_touches_production_state_or_alerts() -> None:
    preview = strip_comments(job_block("publish-preview"))
    assert "history.json" not in preview
    assert "alert_state_store" not in preview
    assert "monitor_state.py" not in preview
    assert "CERTIWATCH_DISCORD_WEBHOOK" not in preview
    assert "CERTIWATCH_STATE_KV" not in preview
    assert "actions/cache" not in preview
    assert "upload-artifact" not in preview
    assert "CLOUDFLARE_ACCOUNT_ID" not in preview.replace(
        "CLOUDFLARE_PREVIEW_ACCOUNT_ID", ""
    )


def test_preview_checks_credentials_and_validates_deploy_values() -> None:
    preview = strip_comments(job_block("publish-preview"))
    assert "Verify preview credentials and account separation" in preview
    assert "Resolve preview target" in preview
    assert "GITHUB_ENV" in preview
    # The branch is mapped with an allowlist, not passed through raw.
    assert "REF_NAME" in preview
    assert "tr -cd 'a-z0-9._-'" in preview
    command = "\n".join(deploy_command_lines("publish-preview"))
    assert "${{ env.CERTIWATCH_PAGES_BRANCH }}" in command
    assert "${{ env.CERTIWATCH_PAGES_PROJECT }}" in command
    assert "github.ref" not in command
    assert "${{ vars." not in command


def test_preview_requires_explicit_distinct_project_and_account() -> None:
    preview = strip_comments(job_block("publish-preview"))
    # The preview project is required; there is no same-project fallback.
    assert 'vars.CERTIWATCH_PREVIEW_PROJECT' in preview
    assert 'project="${PAGES_PROJECT:-}"' in preview
    assert "PAGES_PROJECT:-certiwatch" not in preview
    # Account and project separation checks against trusted production values.
    assert "vars.CERTIWATCH_PRODUCTION_ACCOUNT_ID" in preview
    assert "vars.CERTIWATCH_PRODUCTION_PAGES_PROJECT" in preview
    assert '"$PREVIEW_ACCOUNT" = "$production_account"' in preview
    assert '"$PREVIEW_PROJECT" = "$production_project"' in preview
    # Cloudflare Pages edit tokens are account-scoped; the isolation boundary
    # is a separate account, not a project-scoped token.
    workflow = read(WORKFLOW)
    assert "Pages edit are account-scoped" in workflow
    assert "real isolation boundary" in workflow


def test_preview_alias_has_deterministic_collision_resistance() -> None:
    preview = strip_comments(job_block("publish-preview"))
    assert "FULL_REF: ${{ github.ref }}" in preview
    assert "sha256sum" in preview
    assert "cut -c1-8" in preview
    assert 'branch="${slug}-${digest}"' in preview
    # The hash is of the full ref, not the sanitised slug.
    assert 'printf \'%s\' "$FULL_REF"' in preview


def test_production_deploy_uses_validated_project() -> None:
    publish = job_block("publish")
    assert "Resolve Pages project" in publish
    assert "GITHUB_ENV" in publish
    command = "\n".join(deploy_command_lines("publish"))
    assert "--branch=main" in command
    assert "${{ env.CERTIWATCH_PAGES_PROJECT }}" in command
    assert "${{ vars." not in command


def test_no_raw_ref_or_variable_is_interpolated_into_a_command() -> None:
    for job in ("publish", "publish-preview"):
        command = "\n".join(deploy_command_lines(job))
        assert "${{ github." not in command
        assert "${{ vars." not in command
        assert "${{ secrets." not in command


def test_public_history_uses_cache_only_for_production() -> None:
    publish = job_block("publish")
    assert "actions/cache/restore@" in publish
    assert "actions/cache/save@" in publish
    assert "path: history.json" in publish
    assert "certiwatch-history-" in publish
    assert "actions/cache" not in strip_comments(job_block("publish-preview"))


def test_private_state_uses_kv_not_cache_or_artifact() -> None:
    publish = job_block("publish")
    assert "scripts/alert_state_store.py pull" in publish
    assert "CERTIWATCH_STATE_KV_NAMESPACE" in publish
    assert "CERTIWATCH_STATE_KV_TOKEN" in publish
    assert "actions/upload-artifact" not in publish
    assert "path: .certiwatch" not in publish
    assert "path: .certiwatch/" not in publish


def test_remote_checkpoint_is_chosen_before_discord() -> None:
    publish = job_block("publish")
    assert "checkpoint=kv" in publish
    assert '--checkpoint "$checkpoint"' in publish
    assert "transport=discord" in publish
    assert publish.index("checkpoint=kv") < publish.index('--checkpoint "$checkpoint"')


def test_no_redundant_post_run_private_state_put() -> None:
    publish = job_block("publish")
    assert "scripts/alert_state_store.py push" not in publish
    assert "checkpoint=kv" in publish
    assert "--checkpoint" in publish


def test_bundle_is_built_before_deploy_and_wrangler_is_pinned() -> None:
    for job, step in (
        ("publish", "Deploy to Cloudflare Pages"),
        ("publish-preview", "Deploy preview to Cloudflare Pages"),
    ):
        block = job_block(job)
        build_at = block.index("python3 scripts/build_dist.py --out dist")
        deploy_at = block.index(step)
        assert build_at < deploy_at, job
        assert (
            "cloudflare/wrangler-action@9acf94ace14e7dc412b076f2c5c20b8ce93c79cd"
            in block
        ), job


def test_checkout_never_persists_credentials() -> None:
    for job in ("publish", "publish-preview"):
        assert "persist-credentials: false" in job_block(job), job
    assert "persist-credentials: false" in read(VERIFY)


def test_readme_documents_activation_gates_and_public_previews() -> None:
    readme = read(ROOT / "README.md")
    for token in (
        "certiwatch-production",
        "certiwatch-preview",
        "CERTIWATCH_PRODUCTION_ACCOUNT_ID",
        "CERTIWATCH_PREVIEW_PROJECT",
        "development/*/*",
        "two levels under `development/`",
    ):
        assert token in readme, token
    assert "Delete all of those old repository-level secrets" in readme
    assert "Protect `main`" in readme
    assert "Preview results are public" in readme
