"""Tests for the domain expiry checker and the .lk rate limiter."""

from __future__ import annotations

import datetime
import email.message
import json
import urllib.error

import pytest

import check_LK_domains as lk
import check_domains as cd


# ── Parsing helpers ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text, expected",
    [
        ("2026-12-08", datetime.datetime(2026, 12, 8)),
        ("2026/12/08", datetime.datetime(2026, 12, 8)),
        ("08-12-2026", datetime.datetime(2026, 12, 8)),
        ("08/12/2026", datetime.datetime(2026, 12, 8)),
        ("8-Dec-2026", datetime.datetime(2026, 12, 8)),
        ("Tuesday, 8th December, 2026", datetime.datetime(2026, 12, 8)),
        ("2026-12-08T10:30:00Z", datetime.datetime(2026, 12, 8, 10, 30)),
        ("2026-12-08 10:30:00", datetime.datetime(2026, 12, 8, 10, 30)),
        ("not a date", None),
        ("", None),
    ],
)
def test_parse_date(text, expected):
    assert cd.parse_date(text) == expected


@pytest.mark.parametrize(
    "days, status",
    [
        (None, "unknown"),
        (-1, "expired"),
        (0, "expired"),
        (1, "urgent"),
        (7, "urgent"),
        (8, "warning"),
        (30, "warning"),
        (31, "active"),
    ],
)
def test_days_to_status(days, status):
    assert cd.days_to_status(days) == status


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("GoDaddy.com, LLC", "GoDaddy"),
        ("Namecheap, Inc.", "Namecheap"),
        ("Cloudflare, Inc.", "Cloudflare"),
        ("Some Registrar Ltd", "Some Registrar Ltd"),
        ("N/A", "N/A"),
    ],
)
def test_normalize_registrar(raw, expected):
    assert cd.normalize_registrar(raw) == expected


def test_extract_registrar_from_rdap():
    payload = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "MarkMonitor Inc."],
                    ],
                ],
            }
        ]
    }
    assert cd.extract_registrar(payload) == "MarkMonitor Inc."


def test_extract_expiry_from_rdap_uses_latest_expiry_event():
    payload = {
        "events": [
            {"eventAction": "registration", "eventDate": "2020-10-31T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-10-31T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-10-31T00:00:00Z"},
        ]
    }
    assert cd.extract_expiry_from_rdap(payload) == datetime.datetime(2027, 10, 31)


def test_parse_expiry_from_whois_picks_latest_date():
    text = "\n".join(
        [
            "Registrar: Example Registrar",
            "Registry Expiry Date: 2026-10-31T00:00:00Z",
            "Renewal date: 2028-01-01",
        ]
    )
    assert cd.parse_expiry_from_whois(text) == "2028-01-01"


# ── .lk integration and throttling ────────────────────────────────────────────


def test_lk_lookup_does_not_add_a_second_fixed_delay(monkeypatch):
    monkeypatch.setattr(cd, "get_lk_expiry_date", lambda domain, verbose=False: "2026-12-08")

    def unexpected_throttle():
        raise AssertionError("check_domain must not throttle the .lk helper twice")

    monkeypatch.setattr(cd, "throttle_request", unexpected_throttle)

    result = cd.check_domain("example.lk")

    assert result["domain"] == "example.lk"
    assert result["registrar"] == "domains.lk"
    assert result["expiry_date"] == "2026-12-08"
    assert result["status"] in {"urgent", "warning", "active"}


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def test_adaptive_limiter_spaces_requests_and_recovers():
    clock = FakeClock()
    limiter = lk.AdaptiveRateLimiter(0.8, 5.0, clock=clock, sleep=clock.sleep)

    limiter.wait()
    assert clock.now == 0.0  # first request is not delayed

    limiter.wait()
    assert clock.now == pytest.approx(0.8)

    limiter.note_success()
    assert limiter.current_delay == pytest.approx(0.8)  # never below the floor

    limiter.note_throttled(1.5)
    assert limiter.current_delay == pytest.approx(1.6)

    limiter.wait()
    assert clock.now == pytest.approx(2.4)

    for _ in range(6):
        limiter.note_throttled()
    assert limiter.current_delay == pytest.approx(5.0)  # capped

    for _ in range(200):
        limiter.note_success()
    assert limiter.current_delay == pytest.approx(0.8)  # decays back, not below


def test_lk_lookup_honours_retry_after_and_reports_success(monkeypatch, json_response):
    recorded = {"waits": 0, "throttled": [], "success": 0}

    class Recorder:
        def wait(self):
            recorded["waits"] += 1

        def note_success(self):
            recorded["success"] += 1

        def note_throttled(self, retry_after=None):
            recorded["throttled"].append(retry_after)

    monkeypatch.setattr(lk, "_LIMITER", Recorder())

    headers = email.message.Message()
    headers["Retry-After"] = "1"
    calls = {"count": 0}
    payload = {
        "result": {
            "domainAvailability": {
                "isAvailable": False,
                "domainInfo": {"expireDate": "Tuesday, 8th December, 2026"},
            }
        }
    }

    def fake_urlopen(req, timeout=None):
        calls["count"] += 1
        if calls["count"] == 1:
            raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", headers, None)
        return json_response(payload)

    monkeypatch.setattr(lk.urllib.request, "urlopen", fake_urlopen)

    assert lk.get_expiry_date("example.lk") == "Tuesday, 8th December, 2026"
    assert calls["count"] == 2
    assert recorded["throttled"] == [1.0]
    assert recorded["success"] == 1
    assert recorded["waits"] == 2


def test_lk_lookup_extracts_expiry_and_success(monkeypatch, json_response):
    monkeypatch.setattr(lk, "_LIMITER", type("Noop", (), {"wait": lambda self: None, "note_success": lambda self: None, "note_throttled": lambda self, value=None: None})())
    payload = {
        "result": {
            "domainAvailability": {
                "isAvailable": False,
                "domainInfo": {"expireDate": "2026-12-08"},
            }
        }
    }
    monkeypatch.setattr(lk.urllib.request, "urlopen", lambda req, timeout=None: json_response(payload))

    assert lk.get_expiry_date("https://www.example.lk/path") == "2026-12-08"


# ── Result writing ────────────────────────────────────────────────────────────


def test_domain_write_json_atomic_replaces_file_and_leaves_no_temp(tmp_path):
    target = tmp_path / "domain_results.json"
    target.write_text('{"old": true}\n', encoding="utf-8")

    cd.write_json_atomic(str(target), {"generated_at": "now", "results": []})

    assert json.loads(target.read_text(encoding="utf-8")) == {
        "generated_at": "now",
        "results": [],
    }
    assert [p.name for p in tmp_path.iterdir()] == ["domain_results.json"]


def test_domain_write_json_atomic_keeps_previous_file_on_failure(tmp_path, monkeypatch):
    target = tmp_path / "domain_results.json"
    target.write_text('{"old": true}\n', encoding="utf-8")

    def broken_dump(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(cd.json, "dump", broken_dump)

    with pytest.raises(RuntimeError, match="disk full"):
        cd.write_json_atomic(str(target), {"generated_at": "new", "results": []})

    assert json.loads(target.read_text(encoding="utf-8")) == {"old": True}
    assert [p.name for p in tmp_path.iterdir()] == ["domain_results.json"]
