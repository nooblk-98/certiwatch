"""The checkers consume the unified config and publish only tags/group."""

from __future__ import annotations

import json

import pytest

import check_domains as cd
import check_ssl as cs
import config as cfg
from config import ConfigError

CONFIG = """
version = 1
[defaults]
thresholds = [30, 14, 7, 1]
[[targets]]
domain = "www.example.com"
registration = true
ssl_port = 8443
tags = ["public", "core"]
group = "corporate"
owner = "ops@example.com"
notes = "private note"
[[targets]]
domain = "mail.example.com"
ssl_port = 993
tags = ["mail"]
"""


def write_config(tmp_path):
    path = tmp_path / "certiwatch.toml"
    path.write_text(CONFIG, encoding="utf-8")
    return path


def test_ssl_checker_uses_unified_endpoints_and_public_metadata(tmp_path):
    endpoints = cs.load_monitor_endpoints(write_config(tmp_path))

    assert [(endpoint, target.host) for endpoint, target in endpoints] == [
        ("www.example.com:8443", "www.example.com"),
        ("mail.example.com:993", "mail.example.com"),
    ]
    metadata = cs.apply_public_metadata({}, endpoints[0][1])
    assert metadata["tags"] == ["public", "core"]
    assert metadata["group"] == "corporate"
    assert "owner" not in metadata
    assert "notes" not in metadata


def test_domain_checker_uses_registration_targets_only(tmp_path):
    domains = cd.load_monitor_domains(write_config(tmp_path))

    assert len(domains) == 1
    domain, target = domains[0]
    assert domain == "example.com"
    assert target.registration is True
    metadata = cd.apply_public_metadata({}, target)
    assert metadata["tags"] == ["public", "core"]
    assert "owner" not in metadata


def test_ssl_main_writes_public_metadata_to_results(tmp_path, monkeypatch):
    config = write_config(tmp_path)
    output = tmp_path / "ssl_results.json"

    def fake_check(endpoint: str, *, target=None) -> dict:
        return {
            "domain": endpoint,
            "status": "valid",
            "days_left": 10,
            "provider": "Test CA",
            "expires_on": "2026-12-01",
            "fingerprint_sha256": "AA:BB",
        }

    monkeypatch.setattr(cs, "check_ssl", fake_check)

    assert cs.main(["--config", str(config), "--output", str(output)]) == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    tags = {row["domain"]: row["tags"] for row in payload["results"]}
    assert tags["www.example.com:8443"] == ["public", "core"]
    assert tags["mail.example.com:993"] == ["mail"]
    assert all(row["status"] == "valid" for row in payload["results"])
    serialised = json.dumps(payload)
    assert "ops@example.com" not in serialised
    assert "private note" not in serialised


def test_domain_check_attaches_dns_for_registration_target(monkeypatch):
    target = cfg.Target(
        host="example.com",
        registration=True,
        check_dns=True,
        dns_name="Example.COM.",
    )
    monkeypatch.setattr(
        cd,
        "_check_domain_registration",
        lambda domain: {"domain": domain, "status": "active", "days_left": 100},
    )
    monkeypatch.setattr(
        cd,
        "diagnose_dns",
        lambda name: {
            "checked": True,
            "name": name,
            "ns": {"status": "present", "records": ["ns1.example."], "error": None},
            "caa": {"status": "absent", "records": [], "error": None},
            "dnssec": {
                "status": "absent",
                "validated": False,
                "records": [],
                "signature_count": 0,
                "error": None,
            },
            "error": None,
        },
    )

    result = cd.check_domain("example.com", target=target)

    assert result["dns"]["name"] == "example.com"
    assert result["dns"]["ns"]["status"] == "present"


def test_domain_main_writes_public_metadata_to_results(tmp_path, monkeypatch):
    config = write_config(tmp_path)
    output = tmp_path / "domain_results.json"
    monkeypatch.setattr(
        cd,
        "check_domain",
        lambda domain, *, target=None: {
            "domain": domain,
            "registrar": "Test Registrar",
            "expiry_date": "2027-01-01",
            "status": "active",
            "days_left": 100,
        },
    )

    assert cd.main(["--config", str(config), "--output", str(output)]) == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["results"][0]["domain"] == "example.com"
    assert payload["results"][0]["tags"] == ["public", "core"]
    serialised = json.dumps(payload)
    assert "ops@example.com" not in serialised
    assert "private note" not in serialised


def test_invalid_toml_fails_instead_of_falling_back(tmp_path, monkeypatch):
    (tmp_path / "certiwatch.toml").write_text("version = [\n", encoding="utf-8")
    (tmp_path / "ssl.conf").write_text("legacy.example.com\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ConfigError):
        cs.load_monitor_endpoints()

    # A legacy-only directory still works.
    (tmp_path / "certiwatch.toml").unlink()
    assert [endpoint for endpoint, _ in cs.load_monitor_endpoints()] == [
        "legacy.example.com"
    ]
