"""Offline tests for scripts/build_public_feeds.py.

The feeds are checked as a public contract: exact file layout, summary fields,
deterministic badge names, escaped SVG/ICS text, RFC 5545 line folding and
CRLF, host-key validation, and the output-destination safety rules. No network
access and no real certificates are involved.

Usage:
    python -m pytest -q tests/test_build_public_feeds.py
    python3 scripts/build_public_feeds.py --help
"""

from __future__ import annotations

import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "build_public_feeds.py"

if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

import build_public_feeds as feeds  # noqa: E402

GEN_SSL = "2026-04-26 01:10 UTC"
GEN_DOM = "2026-04-26 01:11 UTC"
GEN_ISO = "2026-04-26T01:11:00Z"


# ── Fixtures ─────────────────────────────────────────────────────────────────


def ssl_row(
    domain: str = "example.com",
    status: str = "valid",
    days: int | None = 60,
    expires: str | None = "2026-06-25",
    provider: str | None = "Let's Encrypt",
    **extra,
) -> dict:
    row = {
        "domain": domain,
        "status": status,
        "provider": provider,
        "issued_on": "2026-03-27",
        "expires_on": expires,
        "days_left": days,
        "error": None,
        "checked_at": GEN_SSL,
    }
    row.update(extra)
    return row


def registration_row(
    domain: str = "example.com",
    status: str = "active",
    days: int | None = 200,
    expiry: str | None = "2027-05-01",
    registrar: str | None = "Example Registrar",
    **extra,
) -> dict:
    row = {
        "domain": domain,
        "registrar": registrar,
        "purchase_date": "N/A",
        "expiry_date": expiry,
        "days_left": days,
        "status": status,
    }
    row.update(extra)
    return row


def write_docs(root: Path, ssl_doc: dict, dom_doc: dict) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "ssl_results.json").write_text(json.dumps(ssl_doc), encoding="utf-8")
    (root / "domain_results.json").write_text(json.dumps(dom_doc), encoding="utf-8")


def write_source(
    root: Path,
    ssl_rows: list[dict] | None = None,
    registration_rows: list[dict] | None = None,
    ssl_generated: str = GEN_SSL,
    dom_generated: str = GEN_DOM,
) -> None:
    write_docs(
        root,
        {"generated_at": ssl_generated, "results": ssl_rows or []},
        {"generated_at": dom_generated, "results": registration_rows or []},
    )


def run_cli(source: Path, out: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--source", str(source), "--out", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )


def read_status(out: Path) -> dict:
    return json.loads((out / "status.json").read_text(encoding="utf-8"))


def read_manifest(out: Path) -> dict:
    return json.loads((out / "badges" / "manifest.json").read_text(encoding="utf-8"))


def output_files(out: Path) -> set[str]:
    return {path.relative_to(out).as_posix() for path in out.rglob("*") if path.is_file()}


def unfold(ics: str) -> str:
    return ics.replace("\r\n ", "")


def ics_events(ics: str) -> list[str]:
    unfolded = unfold(ics)
    return unfolded.split("BEGIN:VEVENT")[1:]


# ── Contract and determinism ─────────────────────────────────────────────────


def test_builds_the_exact_public_layout(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(
        source,
        [ssl_row("Example.COM."), ssl_row("api.example.com", days=200)],
        [registration_row("example.com"), registration_row("api.example.com")],
    )

    result = run_cli(source, out)
    assert result.returncode == 0, result.stderr

    expected_badges = {
        f"badges/{feeds.badge_filename(domain)}"
        for domain in ("api.example.com", "example.com")
    }
    assert output_files(out) == {
        "status.json",
        "expiries.ics",
        "badges/manifest.json",
        *expected_badges,
    }

    status = read_status(out)
    assert status["schema_version"] == 1
    assert status["generated_at"] == GEN_ISO
    assert status["overall_status"] == "ok"
    assert status["checks"] == {
        "certificates": {"generated_at": "2026-04-26T01:10:00Z", "rows": 2},
        "registrations": {"generated_at": "2026-04-26T01:11:00Z", "rows": 2},
    }
    assert status["links"] == {
        "calendar": "/expiries.ics",
        "badges": "/badges/manifest.json",
    }
    assert status["summary"]["domains"] == {
        "total": 2,
        "ok": 2,
        "warning": 0,
        "critical": 0,
        "unknown": 0,
    }
    assert [item["domain"] for item in status["domains"]] == [
        "api.example.com",
        "example.com",
    ]
    entry = status["domains"][1]
    assert entry["status"] == "ok"
    assert entry["badge"] == f"/badges/{feeds.badge_filename('example.com')}"
    assert (out / entry["badge"].lstrip("/")).is_file()
    assert set(entry["certificate"]) == {
        "status",
        "category",
        "expires_on",
        "days_left",
        "provider",
    }
    assert set(entry["registration"]) == {
        "status",
        "category",
        "expires_on",
        "days_left",
        "registrar",
    }
    assert entry["certificate"]["provider"] == "Let's Encrypt"
    assert entry["registration"]["registrar"] == "Example Registrar"
    assert "Overall: ok" in result.stdout

    manifest = read_manifest(out)
    assert manifest["schema_version"] == 1
    assert manifest["generated_at"] == GEN_ISO
    assert set(manifest["badges"]) == {"api.example.com", "example.com"}
    badge = manifest["badges"]["example.com"]
    assert badge["path"] == entry["badge"]
    assert badge["status"] == "ok"
    assert badge["color"] == "#2f855a"
    assert len(badge["sha256"]) == 64


def test_output_is_byte_deterministic(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_source(
        source,
        [ssl_row("b.example", days=40), ssl_row("a.example", days=400)],
        [registration_row("a.example"), registration_row("b.example")],
    )

    first, second = tmp_path / "first", tmp_path / "second"
    assert run_cli(source, first).returncode == 0
    assert run_cli(source, second).returncode == 0

    first_files = {
        rel: (first / rel).read_bytes() for rel in sorted(output_files(first))
    }
    second_files = {
        rel: (second / rel).read_bytes() for rel in sorted(output_files(second))
    }
    assert first_files == second_files


def test_badge_names_are_collision_resistant(tmp_path: Path) -> None:
    # Both domains produce the same readable slug, so only the hash separates
    # them; they must never overwrite each other.
    assert feeds.badge_filename("exa-mple.com") != feeds.badge_filename("exa.mple.com")
    assert feeds.badge_filename("exa-mple.com").startswith("exa-mple-com-")

    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(
        source,
        [ssl_row("exa-mple.com"), ssl_row("exa.mple.com")],
        [registration_row("exa-mple.com"), registration_row("exa.mple.com")],
    )
    assert run_cli(source, out).returncode == 0

    paths = {entry["badge"] for entry in read_status(out)["domains"]}
    assert len(paths) == 2
    assert all((out / path.lstrip("/")).is_file() for path in paths)


# ── Status classification ────────────────────────────────────────────────────


def test_summary_counts_categories_and_overall_status(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(
        source,
        [
            ssl_row("ok.example", days=60),
            ssl_row("expired.example", status="expired", days=-3),
            ssl_row("invalid.example", status="invalid", days=None, expires=None),
            ssl_row("down.example", status="dns_error", days=None, expires=None),
            ssl_row("mystery.example", status="mystery", days=None, expires=None),
        ],
        [
            registration_row("ok.example", days=200),
            registration_row(
                "expired.example", status="expired", days=-2, expiry="2026-04-24"
            ),
            registration_row("invalid.example", status="warning", days=20),
            registration_row("down.example", status="urgent", days=5),
            registration_row("mystery.example", status="mystery", days=None),
        ],
    )

    result = run_cli(source, out)
    assert result.returncode == 0, result.stderr
    status = read_status(out)

    assert status["overall_status"] == "critical"
    assert status["summary"]["certificates"] == {
        "total": 5,
        "valid": 1,
        "expired": 1,
        "invalid": 1,
        "error": 1,
        "unknown": 1,
    }
    assert status["summary"]["registrations"] == {
        "total": 5,
        "active": 1,
        "warning": 1,
        "urgent": 1,
        "expired": 1,
        "unknown": 1,
    }
    assert status["summary"]["domains"] == {
        "total": 5,
        "ok": 1,
        "warning": 1,
        "critical": 2,
        "unknown": 1,
    }
    by_domain = {entry["domain"]: entry for entry in status["domains"]}
    assert by_domain["ok.example"]["status"] == "ok"
    assert by_domain["expired.example"]["status"] == "critical"
    assert by_domain["invalid.example"]["status"] == "critical"
    assert by_domain["down.example"]["status"] == "warning"
    assert by_domain["mystery.example"]["status"] == "unknown"
    assert by_domain["mystery.example"]["certificate"]["category"] == "unknown"
    assert by_domain["mystery.example"]["registration"]["category"] == "unknown"


def test_a_domain_missing_from_one_check_is_a_warning(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(
        source,
        [ssl_row("only-cert.example")],
        [registration_row("only-registration.example")],
    )
    assert run_cli(source, out).returncode == 0

    status = read_status(out)
    assert status["summary"]["domains"]["total"] == 2
    assert status["summary"]["domains"]["warning"] == 2
    assert status["overall_status"] == "warning"
    by_domain = {entry["domain"]: entry for entry in status["domains"]}
    assert by_domain["only-cert.example"]["registration"] is None
    assert by_domain["only-registration.example"]["certificate"] is None


def test_certificate_window_maps_to_dashboard_categories(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(
        source,
        [
            ssl_row("today.example", days=0),
            ssl_row("urgent.example", days=7),
            ssl_row("warn.example", days=30),
            ssl_row("fine.example", days=31),
        ],
        [
            registration_row("today.example"),
            registration_row("urgent.example"),
            registration_row("warn.example"),
            registration_row("fine.example"),
        ],
    )
    assert run_cli(source, out).returncode == 0

    by_domain = {entry["domain"]: entry for entry in read_status(out)["domains"]}
    assert by_domain["today.example"]["certificate"]["category"] == "today"
    assert by_domain["today.example"]["status"] == "critical"
    assert by_domain["urgent.example"]["certificate"]["category"] == "urgent"
    assert by_domain["urgent.example"]["status"] == "warning"
    assert by_domain["warn.example"]["certificate"]["category"] == "warning"
    assert by_domain["warn.example"]["status"] == "warning"
    assert by_domain["fine.example"]["certificate"]["category"] == "valid"
    assert by_domain["fine.example"]["status"] == "ok"


# ── SVG badges ───────────────────────────────────────────────────────────────


def test_badge_is_escaped_well_formed_svg(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(source, [ssl_row("example.com")], [registration_row("example.com")])
    assert run_cli(source, out).returncode == 0

    path = out / read_status(out)["domains"][0]["badge"].lstrip("/")
    raw = path.read_bytes()
    assert raw.startswith(b'<?xml version="1.0" encoding="UTF-8"?>')
    root = ET.fromstring(raw)
    assert root.tag == "{http://www.w3.org/2000/svg}svg"
    texts = [node.text for node in root.iter() if node.tag.endswith("}text")]
    assert texts == ["example.com", "ok"]
    assert b"onload" not in raw
    assert b"<script" not in raw
    assert b"foreignObject" not in raw
    assert b"href" not in raw

    assert feeds.xml_escape('a&b<c>"\'') == "a&amp;b&lt;c&gt;&quot;&#x27;"


def test_badge_status_maps_to_colour(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(
        source,
        [ssl_row("ok.example"), ssl_row("bad.example", status="expired", days=-1)],
        [registration_row("ok.example"), registration_row("bad.example")],
    )
    assert run_cli(source, out).returncode == 0

    manifest = read_manifest(out)
    assert manifest["badges"]["ok.example"]["status"] == "ok"
    assert manifest["badges"]["ok.example"]["color"] == "#2f855a"
    assert manifest["badges"]["bad.example"]["status"] == "critical"
    assert manifest["badges"]["bad.example"]["color"] == "#c53030"

    svg = (out / manifest["badges"]["ok.example"]["path"].lstrip("/")).read_text(
        encoding="utf-8"
    )
    assert 'role="img"' in svg
    assert "aria-label=" in svg


# ── ICS feed ─────────────────────────────────────────────────────────────────


def test_ics_is_rfc5545_shaped(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(
        source,
        [ssl_row("example.com", days=7, expires="2026-05-03")],
        [registration_row("example.com", days=187, expiry="2026-10-31")],
    )
    assert run_cli(source, out).returncode == 0

    raw = (out / "expiries.ics").read_bytes()
    assert raw.endswith(b"\r\n")
    assert b"\n" not in raw.replace(b"\r\n", b"")
    assert b"\r" not in raw.replace(b"\r\n", b"")
    assert all(len(line) <= 75 for line in raw.split(b"\r\n"))

    ics = raw.decode("utf-8")
    unfolded = unfold(ics)
    assert "BEGIN:VCALENDAR" in unfolded
    assert "VERSION:2.0" in unfolded
    assert "PRODID:-//CertiWatch//Public Expiry Feed//EN" in unfolded
    assert "CALSCALE:GREGORIAN" in unfolded
    assert "METHOD:PUBLISH" in unfolded
    assert unfolded.count("BEGIN:VEVENT") == 2
    assert unfolded.count("END:VEVENT") == 2
    assert unfolded.endswith("END:VCALENDAR\r\n")

    events = ics_events(ics)
    assert any("SUMMARY:SSL certificate expires: example.com" in event for event in events)
    assert any("SUMMARY:Domain registration expires: example.com" in event for event in events)
    assert all("DTSTAMP:20260426T011100Z" in event for event in events)
    assert any("DTSTART;VALUE=DATE:20260503" in event for event in events)
    assert any("DTEND;VALUE=DATE:20260504" in event for event in events)
    assert any("DTSTART;VALUE=DATE:20261031" in event for event in events)
    assert any("DTEND;VALUE=DATE:20261101" in event for event in events)
    assert len({line for line in unfolded.splitlines() if line.startswith("UID:")}) == 2


def test_ics_escapes_and_folds_long_text(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(
        source,
        [ssl_row("example.com", provider="X" * 300)],
        [
            registration_row(
                "example.com",
                registrar="Acme, Inc.; Ops\\Dept\nSuite 1",
            )
        ],
    )
    assert run_cli(source, out).returncode == 0

    raw = (out / "expiries.ics").read_bytes()
    assert all(len(line) <= 75 for line in raw.split(b"\r\n"))
    assert b"\r\n " in raw, "expected at least one folded continuation line"

    unfolded = unfold(raw.decode("utf-8"))
    assert r"Registrar: Acme\, Inc.\; Ops\\Dept Suite 1." in unfolded
    assert "Acme, Inc.; Ops" not in unfolded
    assert feeds.ics_escape("a,b;c\\d\ne") == "a\\,b\\;c\\\\d\\ne"


def test_missing_expiry_is_omitted_from_calendar_but_kept_in_status(
    tmp_path: Path,
) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(
        source,
        [ssl_row("down.example", status="dns_error", days=None, expires=None, provider=None)],
        [
            registration_row(
                "down.example", status="unknown", days=None, expiry="N/A", registrar=None
            )
        ],
    )
    assert run_cli(source, out).returncode == 0

    ics = (out / "expiries.ics").read_text(encoding="utf-8")
    assert "BEGIN:VEVENT" not in ics
    status = read_status(out)
    entry = status["domains"][0]
    assert entry["certificate"]["expires_on"] is None
    assert entry["registration"]["expires_on"] is None
    assert entry["status"] == "warning"


# ── Input safety ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad_domain",
    [
        "",
        "http://example.com",
        "example.com/path",
        "user@example.com",
        "example.com?x=1",
        "../example.com",
        "../../etc/passwd",
        "bad_host.example",
        "-bad.example",
        "bad-.example",
        "example..com",
        "exam ple.com",
        "example.com:99999",
        "example.com:abc",
        "example.com:0",
        "[::1",
        "2001:db8::1",
    ],
)
def test_invalid_domain_keys_are_rejected(tmp_path: Path, bad_domain: str) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(
        source,
        [ssl_row(bad_domain)],
        [registration_row("example.com")],
    )

    result = run_cli(source, out)
    assert result.returncode == 1, result.stderr
    assert "domain" in result.stderr.lower()
    assert not out.exists()


def test_duplicate_domains_are_rejected_even_across_case(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(
        source,
        [ssl_row("Example.com"), ssl_row("example.com")],
        [registration_row("example.com")],
    )

    result = run_cli(source, out)
    assert result.returncode == 1, result.stderr
    assert "duplicate domain" in result.stderr
    assert not out.exists()


def test_valid_host_forms_are_canonicalised(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(
        source,
        [ssl_row("Example.COM.", provider="Example CA")],
        [registration_row("example.com:443")],
    )
    assert run_cli(source, out).returncode == 0

    status = read_status(out)
    assert [entry["domain"] for entry in status["domains"]] == ["example.com"]
    assert status["domains"][0]["certificate"] is not None
    assert status["domains"][0]["registration"] is not None

    # A non-default port stays part of the key and is escaped nowhere.
    source2, out2 = tmp_path / "src2", tmp_path / "feeds2"
    write_source(
        source2,
        [ssl_row("example.com:8443")],
        [registration_row("example.com")],
    )
    assert run_cli(source2, out2).returncode == 0
    assert {entry["domain"] for entry in read_status(out2)["domains"]} == {
        "example.com",
        "example.com:8443",
    }


def test_no_raw_error_or_private_config_reaches_the_output(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(
        source,
        [
            ssl_row(
                "example.com",
                error="/home/runner/work/_temp/secret-token Authorization: Bearer abc",
                token="should-never-ship",
                config_path="ssl.conf",
            )
        ],
        [
            registration_row(
                "example.com",
                error="cookie=session-value",
                cookie="should-never-ship",
            )
        ],
    )
    assert run_cli(source, out).returncode == 0

    combined = "\n".join(
        (out / rel).read_text(encoding="utf-8")
        for rel in output_files(out)
        if rel.endswith((".json", ".ics", ".svg"))
    )
    for secret in (
        "secret-token",
        "Authorization",
        "Bearer",
        "should-never-ship",
        "cookie=session-value",
        "ssl.conf",
        "/home/runner",
    ):
        assert secret not in combined
    assert set(read_status(out)["domains"][0]) == {
        "domain",
        "status",
        "badge",
        "certificate",
        "registration",
    }


# ── Fail-closed input handling ───────────────────────────────────────────────


def test_missing_result_file_fails(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(source, [ssl_row()], [registration_row()])
    (source / "ssl_results.json").unlink()

    result = run_cli(source, out)
    assert result.returncode == 1
    assert "ssl_results.json" in result.stderr
    assert not out.exists()


@pytest.mark.parametrize(
    ("ssl_doc", "dom_doc", "needle"),
    [
        ("{not json", {"generated_at": GEN_DOM, "results": [registration_row()]}, "not valid JSON"),
        ([], {"generated_at": GEN_DOM, "results": [registration_row()]}, "top level"),
        (
            {"generated_at": GEN_SSL, "results": []},
            {"generated_at": GEN_DOM, "results": [registration_row()]},
            "empty",
        ),
        (
            {"generated_at": "", "results": [ssl_row()]},
            {"generated_at": GEN_DOM, "results": [registration_row()]},
            "generated_at",
        ),
        (
            {"generated_at": GEN_SSL, "results": [ssl_row()]},
            {"results": [registration_row()]},
            "generated_at",
        ),
        (
            {"generated_at": GEN_SSL, "results": ["junk"]},
            {"generated_at": GEN_DOM, "results": [registration_row()]},
            "object",
        ),
        (
            {"generated_at": GEN_SSL, "results": [ssl_row(status="valid", days="60")]},
            {"generated_at": GEN_DOM, "results": [registration_row()]},
            "days_left",
        ),
        (
            {"generated_at": GEN_SSL, "results": [ssl_row(expires="03/05/2026")]},
            {"generated_at": GEN_DOM, "results": [registration_row()]},
            "expires_on",
        ),
        (
            {"generated_at": "not-a-date", "results": [ssl_row()]},
            {"generated_at": GEN_DOM, "results": [registration_row()]},
            "timestamp",
        ),
    ],
)
def test_malformed_input_fails_closed(
    tmp_path: Path, ssl_doc, dom_doc, needle: str
) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    source.mkdir(parents=True)
    if isinstance(ssl_doc, str):
        (source / "ssl_results.json").write_text(ssl_doc, encoding="utf-8")
    else:
        (source / "ssl_results.json").write_text(json.dumps(ssl_doc), encoding="utf-8")
    (source / "domain_results.json").write_text(json.dumps(dom_doc), encoding="utf-8")

    result = run_cli(source, out)
    assert result.returncode == 1, result.stderr
    assert needle in result.stderr
    assert not out.exists()


def test_symlinked_input_is_refused(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(source, [ssl_row()], [registration_row()])
    real = tmp_path / "real-ssl.json"
    real.write_text((source / "ssl_results.json").read_text(encoding="utf-8"), encoding="utf-8")
    (source / "ssl_results.json").unlink()
    (source / "ssl_results.json").symlink_to(real)

    result = run_cli(source, out)
    assert result.returncode == 2, result.stderr
    assert "symlink" in result.stderr
    assert not out.exists()


# ── Output safety ────────────────────────────────────────────────────────────


def test_source_tree_cannot_be_the_output(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_source(source, [ssl_row()], [registration_row()])
    result = run_cli(source, source)

    assert result.returncode == 2
    assert "source tree as output" in result.stderr
    assert (source / "ssl_results.json").exists()


def test_parent_of_source_cannot_be_replaced(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_source(source, [ssl_row()], [registration_row()])
    (tmp_path / "keep.txt").write_text("outside the checkout\n", encoding="utf-8")

    result = run_cli(source, tmp_path)
    assert result.returncode == 2
    assert "parent of the source tree" in result.stderr
    assert (tmp_path / "keep.txt").exists()


def test_unmanaged_nonempty_destination_is_left_intact(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(source, [ssl_row()], [registration_row()])
    out.mkdir()
    (out / "notes.txt").write_text("someone else's data\n", encoding="utf-8")

    result = run_cli(source, out)
    assert result.returncode == 2
    assert "not a previous feed bundle" in result.stderr
    assert (out / "notes.txt").read_text(encoding="utf-8") == "someone else's data\n"


def test_a_feed_directory_without_manifest_is_refused(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(source, [ssl_row()], [registration_row()])
    out.mkdir()
    (out / "status.json").write_text("{}\n", encoding="utf-8")

    result = run_cli(source, out)
    assert result.returncode == 2
    assert "badges/manifest.json" in result.stderr
    assert (out / "status.json").exists()


def test_rebuild_replaces_stale_badges(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(
        source,
        [ssl_row("one.example"), ssl_row("two.example")],
        [registration_row("one.example"), registration_row("two.example")],
    )
    assert run_cli(source, out).returncode == 0
    assert len([path for path in (out / "badges").glob("*.svg")]) == 2

    write_source(
        source,
        [ssl_row("one.example")],
        [registration_row("one.example")],
    )
    result = run_cli(source, out)
    assert result.returncode == 0, result.stderr
    assert [path.name for path in (out / "badges").glob("*.svg")] == [
        feeds.badge_filename("one.example")
    ]
    assert [entry["domain"] for entry in read_status(out)["domains"]] == ["one.example"]


def test_failed_rebuild_keeps_the_previous_bundle(tmp_path: Path) -> None:
    source, out = tmp_path / "src", tmp_path / "feeds"
    write_source(source, [ssl_row()], [registration_row()])
    assert run_cli(source, out).returncode == 0
    before = (out / "status.json").read_bytes()

    (source / "ssl_results.json").write_text("{broken", encoding="utf-8")
    result = run_cli(source, out)
    assert result.returncode == 1
    assert (out / "status.json").read_bytes() == before


def test_symlinked_destination_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_source(source, [ssl_row()], [registration_row()])
    real = tmp_path / "elsewhere"
    real.mkdir()
    out = tmp_path / "feeds"
    out.symlink_to(real, target_is_directory=True)

    result = run_cli(source, out)
    assert result.returncode == 2
    assert "not a plain directory" in result.stderr
