"""Static, offline checks on the CI privacy and publish contract.

These do not execute GitHub Actions. They assert the workflow files keep the
properties the runtime tests cannot: PR jobs stay offline and secret-free,
private state never enters an Actions cache/artifact, and main is the only
publishing branch.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ssl-check.yml"
VERIFY = ROOT / ".github" / "workflows" / "verify.yml"
PR_VERIFY = ROOT / ".github" / "workflows" / "pr-verify.yml"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def publish_job() -> str:
    content = read(WORKFLOW)
    marker = "\n  publish:\n"
    assert marker in content, "publish job is missing"
    return marker + content.split(marker, 1)[1]


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


def test_publish_is_main_only_and_depends_on_verify() -> None:
    publish = publish_job()
    assert (
        "if: github.event_name != 'pull_request' && github.ref == 'refs/heads/main'"
        in publish
    )
    assert "needs: verify" in publish
    workflow = read(WORKFLOW)
    assert "uses: ./.github/workflows/verify.yml" in workflow
    assert "pull_request:" not in workflow, "production workflow must not run PRs"


def test_public_history_uses_cache_only_on_main() -> None:
    publish = publish_job()
    assert "actions/cache/restore@v4" in publish
    assert "actions/cache/save@v4" in publish
    assert "path: history.json" in publish
    assert "certiwatch-history-" in publish


def test_private_state_uses_kv_not_cache_or_artifact() -> None:
    publish = publish_job()
    assert "scripts/alert_state_store.py pull" in publish
    assert "CERTIWATCH_STATE_KV_NAMESPACE" in publish
    assert "CERTIWATCH_STATE_KV_TOKEN" in publish
    assert "actions/upload-artifact" not in publish
    assert "path: .certiwatch" not in publish
    assert "path: .certiwatch/" not in publish


def test_remote_checkpoint_is_chosen_before_discord() -> None:
    publish = publish_job()
    assert "checkpoint=kv" in publish
    assert '--checkpoint "$checkpoint"' in publish
    assert "transport=discord" in publish
    # The checkpoint variable is computed before monitor_state is invoked.
    assert publish.index("checkpoint=kv") < publish.index('--checkpoint "$checkpoint"')


def test_no_redundant_post_run_private_state_put() -> None:
    publish = publish_job()
    assert "scripts/alert_state_store.py push" not in publish
    assert "checkpoint=kv" in publish
    assert "--checkpoint" in publish


def test_bundle_is_built_before_deploy_and_wrangler_is_pinned() -> None:
    publish = publish_job()
    build_at = publish.index("python3 scripts/build_dist.py --out dist")
    deploy_at = publish.index("Deploy to Cloudflare Pages")
    assert build_at < deploy_at
    assert "cloudflare/wrangler-action@9acf94ace14e7dc412b076f2c5c20b8ce93c79cd" in publish
