"""Tests for the unified certiwatch.toml loader and JSON Schema."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import config as cfg

SAMPLE_TOML = """
version = 1

[defaults]
ssl_port = 443
thresholds = [30, 14, 7, 1]
history_limit = 90

[alerts]
discord = false

[[targets]]
domain = "Example.COM."
ssl = true
registration = true
tags = ["public", "core"]
group = "corporate"
owner = "ops@example.com"
notes = "Primary site; private metadata"

[[targets]]
domain = "mail.example.com"
ssl = true
registration = false
ssl_port = 993
tags = ["mail"]
"""


def write_config(tmp_path: Path, text: str = SAMPLE_TOML) -> Path:
    path = tmp_path / "certiwatch.toml"
    path.write_text(text, encoding="utf-8")
    return path


# ── Parsing and defaults ─────────────────────────────────────────────────────


def test_load_config_applies_defaults_and_normalises_targets(tmp_path):
    loaded = cfg.load_config(write_config(tmp_path))

    assert loaded.version == 1
    assert loaded.thresholds == (30, 14, 7, 1)
    assert loaded.ssl_port == 443
    assert loaded.history_limit == 90
    assert loaded.alerts.discord is False
    assert loaded.source == "toml"

    first, second = loaded.targets
    assert first.host == "example.com"
    assert first.port == 443
    assert first.ssl is True
    assert first.registration is True
    assert first.tags == ("public", "core")
    assert first.group == "corporate"
    assert first.owner == "ops@example.com"
    assert first.notes == "Primary site; private metadata"
    assert first.ssl_endpoint == "example.com"
    assert first.registration_domain == "example.com"

    assert second.host == "mail.example.com"
    assert second.port == 993
    assert second.ssl_endpoint == "mail.example.com:993"
    assert second.registration is False


def test_diagnostic_defaults_are_conservative(tmp_path):
    loaded = cfg.load_config(write_config(tmp_path))
    target = loaded.targets[0]

    assert target.tls_mode == "direct"
    assert target.starttls_protocol is None
    assert target.is_https is True
    assert target.dns_name_value == "example.com"
    assert target.check_dns is True
    assert target.check_hsts is True
    assert target.check_legacy_tls is False


def test_starttls_and_dns_diagnostics_are_per_entry(tmp_path):
    path = write_config(
        tmp_path,
        """
version = 1
[defaults]
check_dns = false
check_hsts = false
check_legacy_tls = true
[[targets]]
domain = "mail.example.com:993"
tls_mode = "starttls"
starttls_protocol = "imap"
dns_name = "Example.COM."
https = false
check_dns = true
check_hsts = true
""",
    )

    target = cfg.load_config(path).targets[0]

    assert target.port == 993
    assert target.tls_mode == "starttls"
    assert target.starttls_protocol == "imap"
    assert target.is_https is False
    assert target.dns_name_value == "example.com"
    assert target.check_dns is True
    assert target.check_hsts is True
    assert target.check_legacy_tls is True


def test_starttls_protocol_is_rejected_for_direct_tls(tmp_path):
    path = write_config(
        tmp_path,
        """
version = 1
[[targets]]
domain = "example.com"
starttls_protocol = "smtp"
""",
    )

    with pytest.raises(cfg.ConfigError, match="starttls_protocol"):
        cfg.load_config(path)


def test_https_cannot_be_combined_with_starttls(tmp_path):
    path = write_config(
        tmp_path,
        """
version = 1
[[targets]]
domain = "mail.example.com:587"
tls_mode = "starttls"
starttls_protocol = "smtp"
https = true
""",
    )

    with pytest.raises(cfg.ConfigError, match="https"):
        cfg.load_config(path)


def test_dns_name_must_be_a_domain_without_a_port(tmp_path):
    path = write_config(
        tmp_path,
        """
version = 1
[[targets]]
domain = "www.example.com"
dns_name = "example.com:53"
""",
    )

    with pytest.raises(cfg.ConfigError, match="dns_name"):
        cfg.load_config(path)


def test_public_metadata_excludes_owner_and_notes(tmp_path):
    loaded = cfg.load_config(write_config(tmp_path))

    metadata = loaded.targets[0].public_metadata()

    assert metadata == {"tags": ["public", "core"], "group": "corporate"}
    assert "owner" not in metadata
    assert "notes" not in metadata


def test_registration_is_opt_in(tmp_path):
    path = write_config(
        tmp_path,
        """
version = 1
[[targets]]
domain = "example.com"
""",
    )

    target = cfg.load_config(path).targets[0]

    assert target.ssl is True
    assert target.registration is False


def test_per_entry_port_must_agree_with_domain_port(tmp_path):
    path = write_config(
        tmp_path,
        """
version = 1
[[targets]]
domain = "mail.example.com:993"
ssl_port = 993
""",
    )

    assert cfg.load_config(path).targets[0].ssl_endpoint == "mail.example.com:993"


def test_target_must_enable_ssl_or_registration(tmp_path):
    path = write_config(
        tmp_path,
        """
version = 1
[[targets]]
domain = "example.com"
ssl = false
""",
    )

    with pytest.raises(cfg.ConfigError, match="not valid under any"):
        cfg.load_config(path)


def test_registration_only_target_rejects_a_port(tmp_path):
    path = write_config(
        tmp_path,
        """
version = 1
[[targets]]
domain = "example.com:8443"
ssl = false
registration = true
""",
    )

    with pytest.raises(cfg.ConfigError, match="port"):
        cfg.load_config(path)


# ── Invalid TOML never silently falls back ───────────────────────────────────


def test_invalid_toml_does_not_fall_back_to_legacy_conf(tmp_path, monkeypatch):
    (tmp_path / "ssl.conf").write_text("legacy.example.com\n", encoding="utf-8")
    (tmp_path / "certiwatch.toml").write_text("version = [\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(cfg.ConfigError, match="invalid TOML"):
        cfg.load_config()


def test_schema_violation_does_not_fall_back_to_legacy_conf(tmp_path, monkeypatch):
    (tmp_path / "ssl.conf").write_text("legacy.example.com\n", encoding="utf-8")
    (tmp_path / "certiwatch.toml").write_text(
        "version = 1\n[[targets]]\ndomain = 'example.com'\nunknown = true\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(cfg.ConfigError, match="unknown"):
        cfg.load_config()


def test_explicit_missing_config_is_an_error(tmp_path):
    with pytest.raises(cfg.ConfigError, match="not found"):
        cfg.load_config(tmp_path / "missing.toml")


# ── Semantic validation ──────────────────────────────────────────────────────


def test_duplicate_ssl_endpoint_is_rejected(tmp_path):
    path = write_config(
        tmp_path,
        """
version = 1
[[targets]]
domain = "example.com"
[[targets]]
domain = "https://EXAMPLE.com/login"
""",
    )

    with pytest.raises(cfg.ConfigError, match="duplicate SSL endpoint"):
        cfg.load_config(path)


def test_duplicate_registration_domain_is_rejected(tmp_path):
    path = write_config(
        tmp_path,
        """
version = 1
[[targets]]
domain = "www.example.com"
registration = true
[[targets]]
domain = "example.com"
registration = true
""",
    )

    with pytest.raises(cfg.ConfigError, match="duplicate registration domain"):
        cfg.load_config(path)


def test_thresholds_must_be_strictly_descending(tmp_path):
    path = write_config(
        tmp_path,
        """
version = 1
[defaults]
thresholds = [30, 14, 14, 1]
[[targets]]
domain = "example.com"
""",
    )

    with pytest.raises(cfg.ConfigError, match="thresholds"):
        cfg.load_config(path)


@pytest.mark.parametrize("days, band", [
    (None, "unknown"),
    (-1, "expired"),
    (0, "critical"),
    (1, "critical"),
    (2, "urgent"),
    (7, "urgent"),
    (8, "warning"),
    (14, "warning"),
    (15, "notice"),
    (30, "notice"),
    (31, "ok"),
])
def test_band_for_days_uses_configured_thresholds(days, band):
    assert cfg.band_for_days(days, (30, 14, 7, 1)) == band


# ── Legacy compatibility ─────────────────────────────────────────────────────


def test_legacy_conf_files_are_loaded_when_no_toml_exists(tmp_path, monkeypatch):
    (tmp_path / "ssl.conf").write_text(
        "# legacy\nwww.example.com\nmail.example.com:993\n", encoding="utf-8"
    )
    (tmp_path / "domains.conf").write_text(
        "example.com\nother.example\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    loaded = cfg.load_config()

    assert loaded.source == "legacy"
    assert loaded.thresholds == (30, 14, 7, 1)
    assert loaded.history_limit == 365
    by_endpoint = {target.ssl_endpoint: target for target in loaded.targets if target.ssl}
    assert by_endpoint["www.example.com"].registration is True
    assert by_endpoint["www.example.com"].registration_domain == "example.com"
    assert by_endpoint["mail.example.com:993"].registration is False
    assert {t.registration_domain for t in loaded.registration_targets()} == {
        "example.com",
        "other.example",
    }


def test_toml_wins_over_legacy_conf_when_both_exist(tmp_path, monkeypatch):
    (tmp_path / "ssl.conf").write_text("legacy.example.com\n", encoding="utf-8")
    (tmp_path / "certiwatch.toml").write_text(
        "version = 1\n[[targets]]\ndomain = 'toml.example.com'\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    loaded = cfg.load_config()

    assert loaded.source == "toml"
    assert [t.host for t in loaded.targets] == ["toml.example.com"]


# ── Schema artifact and sample config ────────────────────────────────────────


def test_schema_file_is_valid_json_schema():
    import jsonschema

    schema_path = cfg.schema_path()
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)

    assert schema["$schema"].endswith("2020-12/schema")
    assert schema["type"] == "object"
    assert "targets" in schema["required"]


def test_committed_sample_config_matches_schema():
    sample = Path(__file__).resolve().parent.parent / "certiwatch.toml"

    loaded = cfg.load_config(sample)

    assert loaded.source == "toml"
    assert loaded.targets
    assert loaded.thresholds == (30, 14, 7, 1)
    assert all(target.tags for target in loaded.targets)
