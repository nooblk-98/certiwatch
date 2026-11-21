"""Regression tests for src/ssl/scripts/check_ssl.py."""

from __future__ import annotations

import datetime
import json
import re
import socket

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module
from conftest import (
    build_cert,
    dns_san,
    ip_san,
)

import check_ssl as cs

LEGACY_RESULT_FIELDS = {
    "domain",
    "status",
    "provider",
    "issued_on",
    "expires_on",
    "days_left",
    "error",
    "checked_at",
}

NEW_RESULT_FIELDS = {
    "host",
    "port",
    "resolved_via",
    "trusted_chain",
    "chain_error",
    "hostname_matches",
    "common_name",
    "wildcard",
    "san",
    "san_count",
    "key_type",
    "key_size",
    "key_curve",
    "not_before",
    "not_after",
    "fingerprint_sha256",
    "serial_number",
    "tls_version",
    "cipher",
    "chain",
    "chain_length",
    "chain_source",
    "revocation_checked",
    "revocation_status",
}


# ── Provider detection ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "issuer, expected",
    [
        ({"organizationName": "Let's Encrypt", "commonName": "R3"}, "Let's Encrypt"),
        ({"organizationName": "Google Trust Services", "commonName": "GTS CA 1C3"}, "Google Trust Services"),
        ({"commonName": "GTS Root R1"}, "Google Trust Services"),
        ({"organizationName": "Amazon", "commonName": "Amazon RSA 2048 M01"}, "Amazon / AWS"),
        ({"organizationName": "Amazon Web Services, Inc."}, "Amazon / AWS"),
        ({"organizationName": "AWS Certificate Manager"}, "Amazon / AWS"),
        ({"organizationName": "12SSL"}, "12SSL"),
        ({"organizationName": "Twelve Consulting Ltd"}, "Twelve Consulting Ltd"),
        ({"organizationName": "Awsome Certs"}, "Awsome Certs"),
        ({"organizationName": "Amazonia Certificate Authority"}, "Amazonia Certificate Authority"),
        ({"organizationName": "Cloudflare, Inc."}, "Cloudflare SSL"),
        ({"organizationName": "Sectigo Limited"}, "Sectigo / Comodo"),
        ({"organizationName": "DigiCert Inc"}, "DigiCert"),
        ({"organizationName": "Some Local CA"}, "Some Local CA"),
        ({"commonName": "Fallback CN"}, "Fallback CN"),
        ({}, "Unknown"),
    ],
)
def test_detect_provider_uses_exact_ca_rules(issuer, expected):
    assert cs.detect_provider(issuer) == expected


# ── Endpoint parsing ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", ("example.com", 443)),
        ("Example.COM.", ("example.com", 443)),
        ("https://example.com/path?q=1", ("example.com", 443)),
        ("HTTPS://example.com:8443/login", ("example.com", 8443)),
        ("example.com:25", ("example.com", 25)),
        ("mail.example.com:993", ("mail.example.com", 993)),
        ("[::1]:8443", ("::1", 8443)),
        ("example.com:0", None),
        ("example.com:65536", None),
        ("example.com:abc", None),
        ("user@example.com", None),
        ("bad host", None),
        ("", None),
    ],
)
def test_parse_endpoint(raw, expected):
    assert cs.parse_endpoint(raw) == expected


def test_load_domains_normalises_comments_ports_and_duplicates(tmp_path):
    config = tmp_path / "ssl.conf"
    config.write_text(
        "\n".join(
            [
                "# monitored endpoints",
                "website",
                "Example.com",
                "example.com",
                "example.com:443",
                "mail.example.com:993",
                "mail.example.com:993",
                "https://portal.example.org/login",
                "bad_host",
                "example.com:99999",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert cs.load_domains(str(config)) == [
        "example.com",
        "mail.example.com:993",
        "portal.example.org",
    ]


# ── Certificate metadata ──────────────────────────────────────────────────────


def test_certificate_metadata_reports_san_wildcard_key_and_fingerprint(rsa_key):
    fixed_now = datetime.datetime(2026, 1, 15, tzinfo=datetime.timezone.utc)
    cert = build_cert(
        common_name="example.com",
        key=rsa_key,
        sans=dns_san("example.com", "*.example.com"),
        not_before=datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(2026, 4, 1, tzinfo=datetime.timezone.utc),
    )

    metadata = cs.certificate_metadata(cert, "api.example.com", now=fixed_now)

    assert metadata["provider"] == "CertiWatch Test"
    assert metadata["issued_on"] == "2026-01-01"
    assert metadata["expires_on"] == "2026-04-01"
    assert metadata["days_left"] == (datetime.datetime(2026, 4, 1, tzinfo=datetime.timezone.utc) - fixed_now).days
    assert metadata["san"] == ["example.com", "*.example.com"]
    assert metadata["san_count"] == 2
    assert metadata["wildcard"] is True
    assert metadata["hostname_matches"] is True
    assert metadata["key_type"] == "RSA"
    assert metadata["key_size"] == 2048
    assert metadata["key_curve"] is None
    assert re.fullmatch(r"([0-9A-F]{2}:){31}[0-9A-F]{2}", metadata["fingerprint_sha256"])
    assert metadata["not_after"] == "2026-04-01T00:00:00Z"
    assert metadata["common_name"] == "example.com"


def test_certificate_metadata_reports_ec_curve(ec_key):
    cert = build_cert(common_name="ec.example", key=ec_key, sans=dns_san("ec.example"))

    metadata = cs.certificate_metadata(cert, "ec.example")

    assert metadata["key_type"] == "ECDSA"
    assert metadata["key_size"] == 256
    assert metadata["key_curve"] in {"secp256r1", "prime256v1"}
    assert metadata["hostname_matches"] is True


@pytest.mark.parametrize(
    "host, dns_names, ip_addresses, expected",
    [
        ("example.com", ["example.com"], [], True),
        ("api.example.com", ["*.example.com"], [], True),
        ("a.b.example.com", ["*.example.com"], [], False),
        ("example.com", ["*.example.com"], [], False),
        ("example.com", ["other.com"], [], False),
        ("127.0.0.1", [], ["127.0.0.1"], True),
        ("127.0.0.2", [], ["127.0.0.1"], False),
    ],
)
def test_hostname_matches(host, dns_names, ip_addresses, expected):
    assert cs.hostname_matches(host, dns_names, ip_addresses, None) is expected


def test_hostname_falls_back_to_common_name_only_without_san():
    assert cs.hostname_matches("example.com", [], [], "example.com") is True
    assert cs.hostname_matches("other.com", [], [], "example.com") is False


# ── Status derivation ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "kwargs, status, error",
    [
        (
            dict(days_left=30, trusted_chain=True, host_matches=True, verification_error=None, self_signed=False),
            "valid",
            None,
        ),
        (
            dict(days_left=0, trusted_chain=False, host_matches=True, verification_error="expired", self_signed=False),
            "expired",
            "Certificate has expired",
        ),
        (
            dict(days_left=30, trusted_chain=False, host_matches=False, verification_error="mismatch", self_signed=False),
            "invalid",
            "Hostname mismatch",
        ),
        (
            dict(days_left=30, trusted_chain=False, host_matches=True, verification_error=None, self_signed=True),
            "invalid",
            "Self-signed certificate",
        ),
        (
            dict(
                days_left=30,
                trusted_chain=False,
                host_matches=True,
                verification_error="unable to get local issuer certificate",
                self_signed=False,
            ),
            "invalid",
            "Certificate verification failed: unable to get local issuer certificate",
        ),
        (
            dict(days_left=30, trusted_chain=False, host_matches=True, verification_error=None, self_signed=False),
            "invalid",
            "Certificate chain is not trusted",
        ),
    ],
)
def test_derive_status(kwargs, status, error):
    assert cs.derive_status(**kwargs) == (status, error)


# ── End-to-end against a throwaway local TLS server ───────────────────────────


def test_check_ssl_self_signed_reports_invalid_with_details(tls_server, rsa_key):
    cert = build_cert(
        common_name="127.0.0.1",
        key=rsa_key,
        sans=ip_san("127.0.0.1"),
    )
    server = tls_server(cert, rsa_key)

    result = cs.check_ssl(server.endpoint)

    assert result["domain"] == server.endpoint
    assert result["host"] == "127.0.0.1"
    assert result["port"] == server.port
    assert result["status"] == "invalid"
    assert result["trusted_chain"] is False
    assert result["chain_error"]
    assert result["error"] == "Self-signed certificate"
    assert result["hostname_matches"] is True
    assert result["key_type"] == "RSA"
    assert result["key_size"] == 2048
    assert result["tls_version"] in {"TLSv1.2", "TLSv1.3"}
    assert result["cipher"]
    assert result["fingerprint_sha256"]
    assert result["chain_length"] >= 1
    assert result["resolved_via"] is None
    assert result["revocation_checked"] is False
    assert result["revocation_status"] == "not_checked"


def test_check_ssl_trusted_chain_with_custom_ca(tls_server, ca_bundle, monkeypatch, rsa_key):
    root_key = rsa_key
    root = build_cert(
        common_name="CertiWatch Test Root",
        key=root_key,
        is_ca=True,
        organization="CertiWatch Test CA",
    )
    leaf_key = rsa_module.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = build_cert(
        common_name="127.0.0.1",
        key=leaf_key,
        sans=ip_san("127.0.0.1"),
        issuer_cert=root,
        issuer_key=root_key,
    )
    monkeypatch.setattr(cs, "CA_FILE", ca_bundle(root))
    server = tls_server(leaf, leaf_key)

    result = cs.check_ssl(f"https://127.0.0.1:{server.port}/health")

    assert result["domain"] == server.endpoint
    assert result["status"] == "valid"
    assert result["trusted_chain"] is True
    assert result["chain_error"] is None
    assert result["error"] is None
    assert result["hostname_matches"] is True
    assert result["days_left"] > 0
    assert result["chain_source"] in {"verified", "leaf"}
    assert result["chain_length"] >= 1
    assert result["san"] == ["127.0.0.1"]


def test_check_ssl_hostname_mismatch_is_reported_not_hidden(tls_server, ca_bundle, monkeypatch, rsa_key):
    root_key = rsa_key
    root = build_cert(
        common_name="CertiWatch Test Root",
        key=root_key,
        is_ca=True,
        organization="CertiWatch Test CA",
    )
    leaf_key = rsa_module.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = build_cert(
        common_name="other.example",
        key=leaf_key,
        sans=dns_san("other.example"),
        issuer_cert=root,
        issuer_key=root_key,
    )
    monkeypatch.setattr(cs, "CA_FILE", ca_bundle(root))
    server = tls_server(leaf, leaf_key)

    result = cs.check_ssl(server.endpoint)

    assert result["status"] == "invalid"
    assert result["trusted_chain"] is True  # chain is valid; the name is not
    assert result["chain_error"] is None
    assert result["hostname_matches"] is False
    assert result["error"] == "Hostname mismatch"


def test_www_fallback_uses_resolved_via_and_keeps_error_empty(monkeypatch, rsa_key):
    cert = build_cert(common_name="www.example.com", key=rsa_key, sans=dns_san("www.example.com"))
    der = cert.public_bytes(serialization.Encoding.DER)

    def fake_probe(host: str, port: int):
        if host == "example.com":
            raise socket.timeout("timed out")
        return cs.TLSProbe(
            der=der,
            tls_version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            trusted=True,
            chain_der=[der],
            chain_source="verified",
        )

    monkeypatch.setattr(cs, "probe_endpoint", fake_probe)

    result = cs.check_ssl("example.com")

    assert result["status"] == "valid"
    assert result["resolved_via"] == "www.example.com"
    assert result["error"] is None
    assert result["domain"] == "example.com"
    assert result["host"] == "example.com"


def test_invalid_entry_returns_error_result():
    result = cs.check_ssl("example.com:99999")

    assert result["status"] == "error"
    assert result["error"] == "Invalid host or port"
    assert LEGACY_RESULT_FIELDS <= set(result)


# ── Output contract and atomic writing ────────────────────────────────────────


def test_result_contract_keeps_legacy_fields_and_adds_documented_ones():
    result = cs.check_ssl("example.com:0")

    assert LEGACY_RESULT_FIELDS <= set(result)
    assert NEW_RESULT_FIELDS <= set(result)


def test_build_output_keeps_top_level_contract():
    output = cs.build_output(["a.example"], [{"status": "valid", "days_left": 10}])

    assert set(output) == {
        "generated_at",
        "total_domains",
        "valid",
        "expired",
        "errors",
        "results",
    }
    assert output["total_domains"] == 1
    assert output["valid"] == 1


def test_write_json_atomic_replaces_file_and_leaves_no_temp_files(tmp_path):
    target = tmp_path / "ssl_results.json"
    target.write_text('{"old": true}\n', encoding="utf-8")

    cs.write_json_atomic(str(target), {"generated_at": "now", "results": []})

    assert json.loads(target.read_text(encoding="utf-8")) == {
        "generated_at": "now",
        "results": [],
    }
    assert [p.name for p in tmp_path.iterdir()] == ["ssl_results.json"]


def test_write_json_atomic_keeps_previous_file_when_write_fails(tmp_path, monkeypatch):
    target = tmp_path / "ssl_results.json"
    target.write_text('{"old": true}\n', encoding="utf-8")

    def broken_dump(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(cs.json, "dump", broken_dump)

    with pytest.raises(RuntimeError, match="disk full"):
        cs.write_json_atomic(str(target), {"generated_at": "new", "results": []})

    assert json.loads(target.read_text(encoding="utf-8")) == {"old": True}
    assert [p.name for p in tmp_path.iterdir()] == ["ssl_results.json"]
