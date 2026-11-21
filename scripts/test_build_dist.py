#!/usr/bin/env python3
"""Tests for scripts/build_dist.py.

Runs the builder against throwaway fixtures and asserts that the published
bundle is exactly the allowlist, that missing or empty required inputs fail,
and that a failed build leaves no stale bundle behind.

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

BUILDER = Path(__file__).resolve().parent / "build_dist.py"

REQUIRED = ["_headers", "domain_results.json", "index.html", "ssl_results.json"]
OPTIONAL = ["app.js", "style.css"]

RESULT_JSON = {
    "generated_at": "2026-11-21T00:00:00+00:00",
    "total_domains": 1,
    "results": [{"domain": "example.com", "status": "valid"}],
}


def write_fixture(root: Path, optional: bool = False, **overrides: str) -> None:
    files = {
        "index.html": "<!doctype html><title>fixture</title>\n",
        "ssl_results.json": json.dumps(RESULT_JSON, indent=2) + "\n",
        "domain_results.json": json.dumps(RESULT_JSON, indent=2) + "\n",
        "pages/_headers": "/ssl_results.json\n  Cache-Control: no-cache, must-revalidate\n",
    }
    if optional:
        files["app.js"] = "console.log('fixture');\n"
        files["style.css"] = "body{color:#000}\n"
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


def case_required_only(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source)
    result = run(source, out)
    expect(result.returncode == 0, f"expected success, got {result.returncode}: {result.stderr}")
    expect(bundle_files(out) == REQUIRED, f"unexpected bundle: {bundle_files(out)}")
    expect("Files: 4" in result.stdout, f"manifest not reported:\n{result.stdout}")
    headers = (out / "_headers").read_text(encoding="utf-8")
    expect("must-revalidate" in headers, "_headers content lost")


def case_optional_assets(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, optional=True)
    result = run(source, out)
    expect(result.returncode == 0, f"expected success, got {result.returncode}: {result.stderr}")
    expect(bundle_files(out) == sorted(REQUIRED + OPTIONAL), f"unexpected bundle: {bundle_files(out)}")


def case_missing_required(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, **{"pages/_headers": None})
    (source / "pages" / "_headers").unlink(missing_ok=True)
    result = run(source, out)
    expect(result.returncode == 1, f"expected exit 1, got {result.returncode}")
    expect("pages/_headers" in result.stderr, f"missing file not named: {result.stderr}")
    expect(not out.exists(), "failed build created an output directory")


def case_missing_index(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, **{"index.html": None})
    (source / "index.html").unlink(missing_ok=True)
    result = run(source, out)
    expect(result.returncode == 1, f"expected exit 1, got {result.returncode}")
    expect("index.html" in result.stderr, f"missing file not named: {result.stderr}")


def case_empty_required(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, **{"index.html": ""})
    result = run(source, out)
    expect(result.returncode == 1, f"expected exit 1, got {result.returncode}")
    expect("index.html" in result.stderr, f"empty file not named: {result.stderr}")


def case_invalid_json(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, **{"ssl_results.json": "{not json"})
    result = run(source, out)
    expect(result.returncode == 1, f"expected exit 1, got {result.returncode}")
    expect("ssl_results.json" in result.stderr, f"bad file not named: {result.stderr}")


def case_empty_results(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    empty = json.dumps({"generated_at": "2026-11-21T00:00:00+00:00", "results": []})
    write_fixture(source, **{"domain_results.json": empty})
    result = run(source, out)
    expect(result.returncode == 1, f"expected exit 1, got {result.returncode}")
    expect("empty dashboard" in result.stderr, f"wrong reason: {result.stderr}")


def case_ignores_unlisted(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source, **{"src/secret.py": "print('internal')\n", "README.md": "# notes\n"})
    result = run(source, out)
    expect(result.returncode == 0, f"expected success, got {result.returncode}: {result.stderr}")
    expect(bundle_files(out) == REQUIRED, f"unlisted file shipped: {bundle_files(out)}")


def case_replaces_stale_bundle(tmp: Path) -> None:
    source, out = tmp / "src", tmp / "dist"
    write_fixture(source)
    out.mkdir(parents=True)
    (out / "stale.html").write_text("old deploy\n", encoding="utf-8")
    result = run(source, out)
    expect(result.returncode == 0, f"expected success, got {result.returncode}: {result.stderr}")
    expect(bundle_files(out) == REQUIRED, f"stale file survived: {bundle_files(out)}")


def case_refuses_source_as_output(tmp: Path) -> None:
    source = tmp / "src"
    write_fixture(source)
    result = run(source, source)
    expect(result.returncode == 2, f"expected exit 2, got {result.returncode}")
    expect((source / "index.html").exists(), "source tree was modified")


CASES = [
    ("required-only bundle is exactly the allowlist", case_required_only),
    ("optional app.js/style.css join the allowlist when present", case_optional_assets),
    ("missing pages/_headers fails and writes no bundle", case_missing_required),
    ("missing index.html fails", case_missing_index),
    ("empty required file fails", case_empty_required),
    ("invalid result JSON fails", case_invalid_json),
    ("empty results list fails", case_empty_results),
    ("unlisted repository files never ship", case_ignores_unlisted),
    ("stale output directory is replaced, not merged", case_replaces_stale_bundle),
    ("source tree as output is refused", case_refuses_source_as_output),
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
