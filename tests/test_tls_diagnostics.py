"""Offline tests for weak keys, HSTS, STARTTLS and legacy TLS capability."""

from __future__ import annotations

import ssl

import pytest
from cryptography.hazmat.primitives import serialization

import check_ssl as cs
import config as cfg
from conftest import build_cert, dns_san


# ── Weak key classification ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "key_type, key_size, expected",
    [
        ("RSA", 1024, "weak"),
        ("RSA", 2048, "acceptable"),
        ("RSA", 3072, "strong"),
        ("ECDSA", 224, "weak"),
        ("ECDSA", 256, "acceptable"),
        ("ECDSA", 384, "strong"),
        ("Ed25519", None, "strong"),
        ("Ed448", None, "strong"),
        ("DSA", 1024, "weak"),
        ("Unknown", None, "unknown"),
        (None, None, "unknown"),
    ],
)
def test_classify_key_strength(key_type, key_size, expected):
    assert cs.classify_key_strength(key_type, key_size) == expected


def test_certificate_metadata_reports_weak_rsa_key():
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    cert = build_cert(common_name="example.com", key=key, sans=dns_san("example.com"))

    metadata = cs.certificate_metadata(cert, "example.com")

    assert metadata["key_strength"] == "weak"


def test_certificate_metadata_reports_acceptable_rsa_key(rsa_key):
    cert = build_cert(common_name="example.com", key=rsa_key, sans=dns_san("example.com"))

    metadata = cs.certificate_metadata(cert, "example.com")

    assert metadata["key_strength"] == "acceptable"


# ── HSTS ────────────────────────────────────────────────────────────────────


def test_classify_hsts_parses_directives():
    result = cs.classify_hsts(
        {
            "strict-transport-security": (
                "max-age=31536000; includeSubDomains; preload"
            )
        }
    )

    assert result == {
        "present": True,
        "valid": True,
        "max_age": 31536000,
        "include_subdomains": True,
        "preload": True,
        "error": None,
    }


@pytest.mark.parametrize(
    "header, present, valid",
    [
        (None, False, False),
        ("max-age=0", True, True),
        ("max-age=abc", True, False),
        ("includeSubDomains", True, False),
        ("max-age=-1", True, False),
    ],
)
def test_classify_hsts_absent_and_invalid(header, present, valid):
    headers = {} if header is None else {"Strict-Transport-Security": header}
    result = cs.classify_hsts(headers)
    assert result["present"] is present
    assert result["valid"] is valid


def test_hsts_is_not_checked_for_non_https():
    calls: list[tuple[str, int]] = []

    result = cs.check_hsts(
        "mail.example.com",
        993,
        applicable=False,
        fetcher=lambda host, port: calls.append((host, port)) or {},
    )

    assert result["applicable"] is False
    assert result["checked"] is False
    assert calls == []


def test_hsts_fetch_failure_is_reported_without_raising():
    def broken(host, port):
        raise OSError("connection refused")

    result = cs.check_hsts("example.com", 443, applicable=True, fetcher=broken)

    assert result["applicable"] is True
    assert result["checked"] is True
    assert result["present"] is False
    assert "connection refused" in result["error"]


def test_check_ssl_hsts_and_dns_only_use_configured_options(monkeypatch):
    target = cfg.Target(
        host="example.com",
        port=443,
        check_dns=True,
        check_hsts=True,
        check_legacy_tls=False,
    )
    probe = _probe_for(cert_for="example.com")
    monkeypatch.setattr(cs, "probe_endpoint", lambda host, port: probe)
    monkeypatch.setattr(
        cs,
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
                "limits": "test",
            },
            "limits": "test",
            "error": None,
        },
    )
    monkeypatch.setattr(
        cs,
        "check_hsts",
        lambda host, port, *, applicable: {
            "applicable": applicable,
            "checked": True,
            "present": True,
            "valid": True,
            "max_age": 60,
            "include_subdomains": False,
            "preload": False,
            "error": None,
        },
    )

    result = cs.check_ssl("example.com", target=target)

    assert result["dns"]["name"] == "example.com"
    assert result["dns"]["ns"]["status"] == "present"
    assert result["hsts"]["present"] is True
    assert result["legacy_tls"]["checked"] is False


# ── STARTTLS ────────────────────────────────────────────────────────────────


class FakeSocket:
    def __init__(self, data: bytes) -> None:
        self._data = bytearray(data)
        self.sent: list[bytes] = []

    def recv(self, size: int) -> bytes:
        if not self._data:
            return b""
        chunk = bytes(self._data[:size])
        del self._data[:size]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def settimeout(self, timeout: float) -> None:
        return None


def test_starttls_smtp_negotiates():
    sock = FakeSocket(
        b"220 mail.example ESMTP\r\n"
        b"250-mail.example\r\n"
        b"250-STARTTLS\r\n"
        b"250 OK\r\n"
        b"220 Go ahead\r\n"
    )

    cs._starttls_exchange(sock, "smtp")

    assert any(b"EHLO" in item for item in sock.sent)
    assert any(b"STARTTLS" in item for item in sock.sent)


@pytest.mark.parametrize(
    "protocol, payload",
    [
        ("imap", b"* OK ready\r\na001 OK begin TLS\r\n"),
        ("pop3", b"+OK ready\r\n+OK begin TLS\r\n"),
    ],
)
def test_starttls_imap_and_pop3_negotiate(protocol, payload):
    sock = FakeSocket(payload)

    cs._starttls_exchange(sock, protocol)

    assert sock.sent


def test_starttls_missing_capability_is_a_remote_tls_error():
    sock = FakeSocket(b"220 mail.example ESMTP\r\n250 hello\r\n")

    with pytest.raises(cs.StartTLSError, match="STARTTLS"):
        cs._starttls_exchange(sock, "smtp")


def test_unknown_starttls_protocol_is_local_unsupported():
    with pytest.raises(cs.StartTLSUnsupported, match="unsupported"):
        cs._starttls_exchange(FakeSocket(b""), "ftp")


def test_check_ssl_target_options_keep_direct_tls_verdict(tls_server, rsa_key):
    cert = build_cert(
        common_name="127.0.0.1",
        key=rsa_key,
        sans=dns_san("127.0.0.1"),
    )
    server = tls_server(cert, rsa_key)
    target = cfg.Target(
        host="127.0.0.1",
        port=server.port,
        check_dns=False,
        check_hsts=False,
        check_legacy_tls=False,
    )

    result = cs.check_ssl(server.endpoint, target=target)

    assert result["status"] == "invalid"  # self-signed local test certificate
    assert result["tls_mode"] == "direct"
    assert result["dns"]["checked"] is False
    assert result["hsts"]["applicable"] is False  # not port 443
    assert result["legacy_tls"]["checked"] is False


def test_check_ssl_starttls_marks_mode_and_disables_hsts(monkeypatch):
    target = cfg.Target(
        host="mail.example.com",
        port=587,
        tls_mode="starttls",
        starttls_protocol="smtp",
        https=False,
        check_dns=False,
        check_hsts=True,
    )
    probe = _probe_for(cert_for="mail.example.com")
    monkeypatch.setattr(cs, "probe_starttls", lambda host, port, protocol: probe)

    result = cs.check_ssl("mail.example.com:587", target=target)

    assert result["tls_mode"] == "starttls"
    assert result["starttls_protocol"] == "smtp"
    assert result["https"] is False
    assert result["hsts"]["applicable"] is False
    assert result["dns"]["checked"] is False


# ── Legacy TLS capability ───────────────────────────────────────────────────


def test_legacy_tls_distinguishes_local_unsupported_from_remote(monkeypatch):
    def handshake(host, port, version_name, *, tls_mode, protocol):
        if version_name == "tls10":
            raise cs.LocalTLSUnsupported("no protocols available")
        raise ssl.SSLError("tlsv1 alert protocol version")

    monkeypatch.setattr(cs, "_legacy_handshake", handshake)

    result = cs.check_legacy_tls("example.com", 443)

    assert result["checked"] is True
    assert result["tls10"] == "local_unsupported"
    assert result["tls11"] == "not_supported"
    assert "OpenSSL/Python" in result["note"]


def test_legacy_tls_timeout_is_unknown_and_success_is_supported(monkeypatch):
    def handshake(host, port, version_name, *, tls_mode, protocol):
        if version_name == "tls10":
            raise TimeoutError("timed out")
        return None

    monkeypatch.setattr(cs, "_legacy_handshake", handshake)

    result = cs.check_legacy_tls("example.com", 443)

    assert result["tls10"] == "unknown"
    assert result["tls11"] == "supported"


def test_legacy_tls_is_optional(monkeypatch):
    target = cfg.Target(
        host="example.com",
        port=443,
        check_dns=False,
        check_hsts=False,
        check_legacy_tls=False,
    )
    monkeypatch.setattr(cs, "probe_endpoint", lambda host, port: _probe_for("example.com"))

    result = cs.check_ssl("example.com", target=target)

    assert result["legacy_tls"] == {
        "checked": False,
        "tls10": "not_checked",
        "tls11": "not_checked",
    }


# ── Revocation disclosure ───────────────────────────────────────────────────


def test_revocation_is_not_claimed_without_a_real_check():
    result = cs.check_ssl("example.com:0")

    assert result["revocation_checked"] is False
    assert result["revocation_status"] == "not_checked"
    assert result["revocation"]["checked"] is False
    assert result["revocation"]["supported"] is False
    assert "not" in result["revocation"]["note"].lower()


def _probe_for(cert_for: str) -> cs.TLSProbe:
    cert = build_cert(common_name=cert_for, key=_test_key(), sans=dns_san(cert_for))
    der = cert.public_bytes(serialization.Encoding.DER)
    return cs.TLSProbe(
        der=der,
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        trusted=True,
        chain_der=[der],
        chain_source="verified",
    )


def _test_key():
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
