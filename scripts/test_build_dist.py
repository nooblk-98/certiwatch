#!/usr/bin/env python3
"""Tests for scripts/build_dist.py.

Runs the builder against throwaway fixtures and asserts the publishing
contract: the bundle is exactly the allowlist, missing/empty/malformed inputs
fail, an all-unreachable TLS run never replaces published data, symlinked
inputs are refused, and no destination the builder does not own is deleted.

Usage:
    python3 scripts/test_build_dist.py

Exit codes:
    0  every case passed
    1  at least one case failed
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_public_feeds as feeds  # noqa: E402

BUILDER = SCRIPT_DIR / "build_dist.py"

REQUIRED = ["_headers", "domain_results.json", "index.html", "ssl_results.json"]
OPTIONAL = ["app.js", "style.css"]
FEEDS = ["badges/manifest.json", "expiries.ics", "status.json"]

GENERATED_AT = "2026-11-21T00:00:00+00:00"


def result_doc(statuses: list[str]) -> str:
    return json.dumps(
        {
            "generated_at": GENERATED_AT,
            "total_domains": len(statuses),
            "results": [
                {"domain": f"host{i}.example", "status": status}
                for i, status in enumerate(statuses)
            ],
        },
        indent=2,
    ) + "\n"


RESULT_JSON = result_doc(["valid"])
HISTORY_JSON = json.dumps(
    {
        "snapshots": [
            {
                "date": "2026-11-20",
                "ssl": [
                    {
                        "domain": "host0.example",
                        "days_left": 30,
                        "status": "valid",
                        "fingerprint_sha256": None,
                    }
                ],
                "domains": [],
            }
        ]
    },
    indent=2,
) + "\n"


def expected_bundle(
    statuses: tuple[str, ...] = ("valid",),
    *,
    optional: bool = False,
    history: bool = False,
) -> list[str]:
    domains = [f"host{index}.example" for index in range(len(statuses))]
    names = [
        *REQUIRED,
        *FEEDS,
        *(f"badges/{feeds.badge_filename(domain)}" for domain in domains),
    ]
    if optional:
        names.extend(OPTIONAL)
    if history:
        names.append("history.json")
    return sorted(names)


def write_fixture(
    root: Path,
    optional: bool = False,
    history: bool = False,
    **overrides: str | None,
) -> None:
    files: dict[str, str] = {
        "index.html": "<!doctype html><title>fixture</title>\n",
        "ssl_results.json": RESULT_JSON,
        "domain_results.json": RESULT_JSON,
        "pages/_headers": "/ssl_results.json\n  Cache-Control: no-cache, must-revalidate\n",
    }
    if optional:
        files["app.js"] = "console.log('fixture');\n"
        files["style.css"] = "body{color:#000}\n"
    if history:
        files["history.json"] = HISTORY_JSON
    files.update(overrides)

    for rel, text in files.items():
        if text is None:
            continue
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def run(source: Path, out: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(BUILDER), "--source", str(source), "--out", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )


def bundle_files(out: Path) -> list[str]:
    return sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_build_error(result: subprocess.CompletedProcess[str], code: int, needle: str) -> None:
    expect(result.returncode == code, f"expected exit {code}, got {result.returncode}: {result.stderr}")
    expect(needle in result.stderr, f"{needle!r} not in stderr: {result.stderr}")


# ── Bundle shape ─────────────────────────────────────────────────────────────


def case_required_only(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source)
    result = run(source, out)
    expect(result.returncode == 0, f"expected success, got {result.returncode}: {result.stderr}")
    expect(bundle_files(out) == expected_bundle(), f"unexpected bundle: {bundle_files(out)}")
    expect("Files: 8" in result.stdout, f"manifest not reported:\n{result.stdout}")
    headers = (out / "_headers").read_text(encoding="utf-8")
    expect("must-revalidate" in headers, "_headers content lost")


def case_optional_assets(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, optional=True)
    result = run(source, out)
    expect(result.returncode == 0, f"expected success, got {result.returncode}: {result.stderr}")
    expect(
        bundle_files(out) == expected_bundle(optional=True),
        f"unexpected bundle: {bundle_files(out)}",
    )


def case_ignores_unlisted(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, **{"src/secret.py": "print('internal')\n", "README.md": "# notes\n"})
    result = run(source, out)
    expect(result.returncode == 0, f"expected success, got {result.returncode}: {result.stderr}")
    expect(bundle_files(out) == expected_bundle(), f"unlisted file shipped: {bundle_files(out)}")


# ── Missing or malformed input ───────────────────────────────────────────────


def case_missing_required(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, **{"pages/_headers": None})
    (source / "pages" / "_headers").unlink(missing_ok=True)
    result = run(source, out)
    expect_build_error(result, 1, "pages/_headers")
    expect(not out.exists(), "failed build created an output directory")


def case_missing_index(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, **{"index.html": None})
    (source / "index.html").unlink(missing_ok=True)
    expect_build_error(run(source, out), 1, "index.html")


def case_empty_required(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, **{"index.html": ""})
    expect_build_error(run(source, out), 1, "index.html")


def case_invalid_json(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, **{"ssl_results.json": "{not json"})
    expect_build_error(run(source, out), 1, "ssl_results.json")


def case_empty_results(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    empty = json.dumps({"generated_at": GENERATED_AT, "results": []})
    write_fixture(source, **{"domain_results.json": empty})
    expect_build_error(run(source, out), 1, "empty dashboard")


# ── Unreachable-run gate ─────────────────────────────────────────────────────


def case_all_unreachable_ssl_fails(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    statuses = ["dns_error", "timeout", "no_https", "ssl_error", "error"]
    write_fixture(source, **{"ssl_results.json": result_doc(statuses)})
    result = run(source, out)
    expect_build_error(result, 1, "no certificate was read")
    expect("dns_error=1" in result.stderr, f"status counts missing: {result.stderr}")
    expect(not out.exists(), "unreachable run created a bundle")


def case_mixed_unreachable_publishes(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, **{"ssl_results.json": result_doc(["dns_error", "expired", "invalid"])})
    result = run(source, out)
    expect(result.returncode == 0, f"expected success, got {result.returncode}: {result.stderr}")
    expect(
        bundle_files(out) == expected_bundle(("dns_error", "expired", "invalid")),
        f"unexpected bundle: {bundle_files(out)}",
    )


def case_certificate_failures_publish(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, **{"ssl_results.json": result_doc(["expired", "invalid", "valid"])})
    result = run(source, out)
    expect(result.returncode == 0, f"real certificate failures must publish: {result.stderr}")
    expect(
        bundle_files(out) == expected_bundle(("expired", "invalid", "valid")),
        f"unexpected bundle: {bundle_files(out)}",
    )


def case_empty_rows_gate(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    payload = json.dumps({"generated_at": GENERATED_AT, "results": [{"domain": "x"}, "junk"]})
    write_fixture(source, **{"ssl_results.json": payload})
    expect_build_error(run(source, out), 1, "no certificate was read")


# ── Output destination safety ────────────────────────────────────────────────


def case_refuses_source_as_output(tmp: Path) -> None:
    source = tmp / "src"
    write_fixture(source)
    result = run(source, source)
    expect_build_error(result, 2, "source tree as output")
    expect((source / "index.html").exists(), "source tree was modified")


def case_in_tree_only_dist(tmp: Path) -> None:
    source = tmp / "src"
    write_fixture(source)
    out = source / "build"
    out.mkdir()
    (out / "keep.txt").write_text("tracked work\n", encoding="utf-8")
    result = run(source, out)
    expect_build_error(result, 2, "only allowed in-tree output is 'dist'")
    expect((out / "keep.txt").read_text(encoding="utf-8") == "tracked work\n", "existing file deleted")


def case_in_tree_dist_allowed(tmp: Path) -> None:
    source = tmp / "src"
    write_fixture(source)
    out = source / "dist"
    result = run(source, out)
    expect(result.returncode == 0, f"dist inside source must be allowed: {result.stderr}")
    expect(bundle_files(out) == expected_bundle(), f"unexpected bundle: {bundle_files(out)}")


def case_unmanaged_nonempty_destination(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source)
    out.mkdir(parents=True)
    (out / "stale.html").write_text("not ours\n", encoding="utf-8")
    expect_build_error(run(source, out), 2, "not a previous CertiWatch bundle")
    expect((out / "stale.html").exists(), "unmanaged destination was deleted")

    (out / "stale.html").unlink()
    (out / "nested").mkdir()
    expect_build_error(run(source, out), 2, "not a previous CertiWatch bundle")

    # Even an allowlisted name is not enough without the bundle's _headers.
    (out / "nested").rmdir()
    (out / "index.html").write_text("someone else's site\n", encoding="utf-8")
    expect_build_error(run(source, out), 2, "has no _headers")
    expect((out / "index.html").exists(), "foreign index.html was deleted")


def case_refuses_parent_of_source(tmp: Path) -> None:
    source = tmp / "src"
    write_fixture(source)
    (tmp / "keep.txt").write_text("outside the checkout\n", encoding="utf-8")
    result = run(source, tmp)
    expect_build_error(result, 2, "parent of the source tree")
    expect((tmp / "keep.txt").exists(), "parent directory content deleted")


def case_managed_bundle_replaced(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, optional=True)
    expect(run(source, out).returncode == 0, "first build failed")
    expect(
        bundle_files(out) == expected_bundle(optional=True),
        f"unexpected first bundle: {bundle_files(out)}",
    )

    (source / "app.js").unlink()
    (source / "style.css").unlink()
    result = run(source, out)
    expect(result.returncode == 0, f"managed bundle must be replaceable: {result.stderr}")
    expect(bundle_files(out) == expected_bundle(), f"stale assets survived: {bundle_files(out)}")


def case_destination_symlink_refused(tmp: Path) -> None:
    source = tmp / "src"
    write_fixture(source)
    real = tmp / "elsewhere"
    real.mkdir()
    out = tmp / "dist"
    out.symlink_to(real, target_is_directory=True)
    expect_build_error(run(source, out), 2, "not a plain directory")


# ── Symlinked inputs ─────────────────────────────────────────────────────────


def case_symlinked_input_refused(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source)
    real = tmp / "real-ssl.json"
    real.write_text(RESULT_JSON, encoding="utf-8")
    (source / "ssl_results.json").unlink()
    (source / "ssl_results.json").symlink_to(real)
    expect_build_error(run(source, out), 2, "is a symlink")
    expect(not out.exists(), "symlinked input produced a bundle")


def case_symlinked_parent_refused(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source)
    (source / "pages").rename(source / "pages-real")
    (source / "pages").symlink_to(source / "pages-real", target_is_directory=True)
    expect_build_error(run(source, out), 2, "is a symlink")
    expect(not out.exists(), "symlinked parent produced a bundle")


# ── History and generated feeds ─────────────────────────────────────────────


def case_repository_headers_cover_public_types(_tmp: Path) -> None:
    headers = (SCRIPT_DIR.parent / "pages" / "_headers").read_text(encoding="utf-8")
    for needle in (
        "/ssl_results.json",
        "/domain_results.json",
        "/status.json",
        "/history.json",
        "/expiries.ics",
        "/badges/*",
        "text/calendar",
        "image/svg+xml",
    ):
        expect(needle in headers, f"pages/_headers is missing {needle!r}")


def case_public_history_is_published(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, history=True)
    result = run(source, out)
    expect(result.returncode == 0, f"expected success, got {result.returncode}: {result.stderr}")
    expect(
        bundle_files(out) == expected_bundle(history=True),
        f"unexpected bundle: {bundle_files(out)}",
    )
    published = json.loads((out / "history.json").read_text(encoding="utf-8"))
    expect(published["snapshots"][0]["date"] == "2026-11-20", "history content changed")


def case_invalid_history_is_refused(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    payload = json.dumps({"snapshots": []})
    write_fixture(source, **{"history.json": payload})
    result = run(source, out)
    expect_build_error(result, 1, "snapshots")
    expect(not out.exists(), "invalid history produced a bundle")


def case_private_history_metadata_is_refused(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    payload = json.dumps(
        {
            "snapshots": [
                {
                    "date": "2026-11-20",
                    "ssl": [
                        {
                            "domain": "host0.example",
                            "days_left": 30,
                            "status": "valid",
                            "fingerprint_sha256": None,
                            "owner": "ops@example.com",
                        }
                    ],
                    "domains": [],
                }
            ]
        }
    )
    write_fixture(source, **{"history.json": payload})
    expect_build_error(run(source, out), 1, "unexpected keys")


def case_duplicate_history_dates_are_refused(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    payload = json.dumps(
        {
            "snapshots": [
                {"date": "2026-11-20", "ssl": [], "domains": []},
                {"date": "2026-11-20", "ssl": [], "domains": []},
            ]
        }
    )
    write_fixture(source, **{"history.json": payload})
    expect_build_error(run(source, out), 1, "duplicate snapshot date")


def case_repeat_build_accepts_its_own_feeds(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, history=True)
    expect(run(source, out).returncode == 0, "first build failed")
    second = run(source, out)
    expect(second.returncode == 0, f"second build failed: {second.stderr}")
    expect(
        bundle_files(out) == expected_bundle(history=True),
        f"repeat build changed the bundle: {bundle_files(out)}",
    )


def case_foreign_badge_file_is_refused(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source)
    expect(run(source, out).returncode == 0, "first build failed")
    foreign = out / "badges" / "evil.svg"
    foreign.write_text("<svg/>\n", encoding="utf-8")
    result = run(source, out)
    expect_build_error(result, 2, "not a previous CertiWatch bundle")
    expect(foreign.exists(), "foreign badge was deleted")


def case_feed_failure_keeps_previous_bundle(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source)
    expect(run(source, out).returncode == 0, "first build failed")
    before = (out / "status.json").read_bytes()

    bad = json.dumps(
        {
            "generated_at": GENERATED_AT,
            "results": [{"domain": "bad_host.example", "status": "valid"}],
        }
    )
    (source / "ssl_results.json").write_text(bad, encoding="utf-8")
    result = run(source, out)
    expect_build_error(result, 1, "public feeds")
    expect((out / "status.json").read_bytes() == before, "failed feed replaced the old bundle")


def case_symlinked_history_refused(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source)
    real = tmp / "real-history.json"
    real.write_text(HISTORY_JSON, encoding="utf-8")
    (source / "history.json").symlink_to(real)
    expect_build_error(run(source, out), 2, "is a symlink")


CASES = [
    ("required-only bundle is exactly the allowlist", case_required_only),
    ("optional app.js/style.css join the allowlist when present", case_optional_assets),
    ("unlisted repository files never ship", case_ignores_unlisted),
    ("missing pages/_headers fails and writes no bundle", case_missing_required),
    ("missing index.html fails", case_missing_index),
    ("empty required file fails", case_empty_required),
    ("invalid result JSON fails", case_invalid_json),
    ("empty results list fails", case_empty_results),
    ("all-unreachable TLS run is refused", case_all_unreachable_ssl_fails),
    ("unreachable rows alongside a real verdict publish", case_mixed_unreachable_publishes),
    ("expired/invalid certificates still publish", case_certificate_failures_publish),
    ("rows without a readable status count as unobserved", case_empty_rows_gate),
    ("source tree as output is refused", case_refuses_source_as_output),
    ("in-tree output is limited to dist", case_in_tree_only_dist),
    ("in-tree dist is allowed", case_in_tree_dist_allowed),
    ("unmanaged non-empty destination is refused intact", case_unmanaged_nonempty_destination),
    ("parent of the source tree is refused", case_refuses_parent_of_source),
    ("managed bundle is replaced, not merged", case_managed_bundle_replaced),
    ("symlinked destination is refused", case_destination_symlink_refused),
    ("symlinked input file is refused", case_symlinked_input_refused),
    ("symlinked parent directory is refused", case_symlinked_parent_refused),
    ("repository headers cover every public type", case_repository_headers_cover_public_types),
    ("public history is published", case_public_history_is_published),
    ("invalid history is refused", case_invalid_history_is_refused),
    ("private history metadata is refused", case_private_history_metadata_is_refused),
    ("duplicate history dates are refused", case_duplicate_history_dates_are_refused),
    ("repeat build accepts its own generated feeds", case_repeat_build_accepts_its_own_feeds),
    ("foreign badge file is refused intact", case_foreign_badge_file_is_refused),
    ("feed failure keeps the previous bundle", case_feed_failure_keeps_previous_bundle),
    ("symlinked history is refused", case_symlinked_history_refused),
]


def main() -> int:
    failures = 0
    for name, case in CASES:
        with tempfile.TemporaryDirectory() as tmp_name:
            try:
                case(Path(tmp_name))
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
            else:
                print(f"ok   {name}")

    print(f"\n{len(CASES) - failures}/{len(CASES)} cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
