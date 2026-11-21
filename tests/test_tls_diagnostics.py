"""Offline tests for weak keys, HSTS, STARTTLS and legacy TLS capability."""

from __future__ import annotations

import http.server
import ssl
import threading

import pytest
from cryptography.hazmat.primitives import serialization

import check_ssl as cs
import config as cfg
from conftest import build_cert, cert_pem, dns_san, ip_san, key_pem


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
        "enabled": True,
        "status": "present",
        "max_age": 31536000,
        "include_subdomains": True,
        "preload": True,
        "error": None,
    }


@pytest.mark.parametrize(
    "header, present, valid, enabled, status",
    [
        (None, False, False, False, "absent"),
        ("max-age=0", True, True, False, "disabled"),
        ("max-age=abc", True, False, False, "invalid"),
        ("includeSubDomains", True, False, False, "invalid"),
        ("max-age=-1", True, False, False, "invalid"),
    ],
)
def test_classify_hsts_absent_disabled_and_invalid(
    header, present, valid, enabled, status
):
    headers = {} if header is None else {"Strict-Transport-Security": header}
    result = cs.classify_hsts(headers)
    assert result["present"] is present
    assert result["valid"] is valid
    assert result["enabled"] is enabled
    assert result["status"] == status


def test_hsts_max_age_zero_is_disabled_not_an_error():
    result = cs.classify_hsts({"Strict-Transport-Security": "max-age=0"})

    assert result["present"] is True
    assert result["valid"] is True
    assert result["enabled"] is False
    assert result["status"] == "disabled"
    assert result["error"] is None


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


def test_hsts_fetch_failure_is_indeterminate_not_absent():
    def broken(host, port):
        raise ssl.SSLCertVerificationError("hostname mismatch")

    result = cs.check_hsts("example.com", 443, applicable=True, fetcher=broken)

    assert result["applicable"] is True
    assert result["checked"] is True
    assert result["status"] == "indeterminate"
    assert result["present"] is None
    assert result["valid"] is None
    assert result["enabled"] is None
    assert "hostname mismatch" in result["error"]


def test_hsts_connection_uses_verified_context_and_configured_trust_store(monkeypatch):
    captured: dict[str, object] = {}

    class FakeContext:
        check_hostname = False
        verify_mode = ssl.CERT_NONE
        hostname_checks_common_name = True

    class FakeResponse:
        def getheaders(self):
            return [("Strict-Transport-Security", "max-age=60")]

        def read(self):
            return b""

    class FakeConnection:
        def __init__(self, host, port, *, timeout, context):
            captured.update(
                {
                    "host": host,
                    "port": port,
                    "timeout": timeout,
                    "context": context,
                }
            )

        def request(self, *args, **kwargs):
            return None

        def getresponse(self):
            return FakeResponse()

        def close(self):
            return None

    context = FakeContext()
    monkeypatch.setattr(cs, "CA_FILE", "/tmp/certiwatch-ca.pem")
    monkeypatch.setattr(
        cs.ssl,
        "create_default_context",
        lambda cafile=None: captured.update({"cafile": cafile}) or context,
    )
    monkeypatch.setattr(cs.http.client, "HTTPSConnection", FakeConnection)

    headers = cs.fetch_https_headers("example.com", 443)

    assert headers == {"strict-transport-security": "max-age=60"}
    assert captured["cafile"] == "/tmp/certiwatch-ca.pem"
    assert captured["host"] == "example.com"
    assert captured["port"] == 443
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.hostname_checks_common_name is False


class _HstsHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Strict-Transport-Security", "max-age=60")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):
        return None


def _start_https_hsts_server(cert, key, tmp_path):
    cert_file = tmp_path / "hsts-server-cert.pem"
    key_file = tmp_path / "hsts-server-key.pem"
    cert_file.write_bytes(cert_pem(cert))
    key_file.write_bytes(key_pem(key))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_file), str(key_file))
    server = http.server.HTTPServer(("127.0.0.1", 0), _HstsHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_hsts_authenticates_trust_and_san_offline(tmp_path, ca_bundle, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = build_cert(
        common_name="CertiWatch Test Root",
        key=root_key,
        is_ca=True,
        organization="CertiWatch Test CA",
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = build_cert(
        common_name="127.0.0.1",
        key=leaf_key,
        sans=ip_san("127.0.0.1"),
        issuer_cert=root,
        issuer_key=root_key,
    )
    monkeypatch.setattr(cs, "CA_FILE", ca_bundle(root))
    server, thread = _start_https_hsts_server(leaf, leaf_key, tmp_path)
    try:
        headers = cs.fetch_https_headers("127.0.0.1", server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert headers["strict-transport-security"] == "max-age=60"


def test_hsts_authenticates_trust_and_dns_san_offline(tmp_path, ca_bundle, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = build_cert(
        common_name="CertiWatch Test Root",
        key=root_key,
        is_ca=True,
        organization="CertiWatch Test CA",
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = build_cert(
        common_name="not-localhost.example",
        key=leaf_key,
        sans=dns_san("localhost"),
        issuer_cert=root,
        issuer_key=root_key,
    )
    monkeypatch.setattr(cs, "CA_FILE", ca_bundle(root))
    server, thread = _start_https_hsts_server(leaf, leaf_key, tmp_path)
    try:
        headers = cs.fetch_https_headers("localhost", server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert headers["strict-transport-security"] == "max-age=60"


def test_hsts_trusted_loopback_cn_only_certificate_is_indeterminate(
    tmp_path, ca_bundle, monkeypatch
):
    from cryptography.hazmat.primitives.asymmetric import rsa

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = build_cert(
        common_name="CertiWatch Test Root",
        key=root_key,
        is_ca=True,
        organization="CertiWatch Test CA",
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Deliberately CN-only: no subjectAltName at all.
    leaf = build_cert(
        common_name="localhost",
        key=leaf_key,
        issuer_cert=root,
        issuer_key=root_key,
    )
    monkeypatch.setattr(cs, "CA_FILE", ca_bundle(root))
    server, thread = _start_https_hsts_server(leaf, leaf_key, tmp_path)
    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            cs.fetch_https_headers("localhost", server.server_port)
        result = cs.check_hsts(
            "localhost",
            server.server_port,
            applicable=True,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result["status"] == "indeterminate"
    assert result["present"] is None
    assert result["valid"] is None
    assert result["enabled"] is None


def test_hsts_hostname_mismatch_is_indeterminate(tmp_path, ca_bundle, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = build_cert(
        common_name="CertiWatch Test Root",
        key=root_key,
        is_ca=True,
        organization="CertiWatch Test CA",
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = build_cert(
        common_name="127.0.0.2",
        key=leaf_key,
        sans=ip_san("127.0.0.2"),
        issuer_cert=root,
        issuer_key=root_key,
    )
    monkeypatch.setattr(cs, "CA_FILE", ca_bundle(root))
    server, thread = _start_https_hsts_server(leaf, leaf_key, tmp_path)
    try:
        result = cs.check_hsts(
            "127.0.0.1",
            server.server_port,
            applicable=True,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result["status"] == "indeterminate"
    assert result["present"] is None


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
            "enabled": True,
            "status": "present",
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


def test_starttls_aggregate_read_byte_cap():
    sock = FakeSocket(b"220 " + b"x" * 100 + b"\r\n")

    with pytest.raises(cs.StartTLSError, match="byte cap"):
        cs._starttls_exchange(sock, "smtp", max_bytes=20)


def test_starttls_aggregate_line_cap():
    sock = FakeSocket(b"220 hi\r\n250-one\r\n250-two\r\n")

    with pytest.raises(cs.StartTLSError, match="line cap"):
        cs._starttls_exchange(sock, "smtp", max_lines=1)


def test_starttls_write_bytes_count_toward_the_cap():
    sock = FakeSocket(b"220 hi\r\n")

    with pytest.raises(cs.StartTLSError, match="byte cap"):
        cs._starttls_exchange(sock, "smtp", max_bytes=10)

    assert sock.sent == [], "the over-budget command must not be written"


def test_starttls_line_length_cap():
    sock = FakeSocket(b"220 " + b"x" * 50 + b"\r\n")

    with pytest.raises(cs.StartTLSError, match="line length cap"):
        cs._starttls_exchange(sock, "smtp", max_line_bytes=20)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class ClockedSocket(FakeSocket):
    def __init__(self, data: bytes, clock: FakeClock, step: float) -> None:
        super().__init__(data)
        self._clock = clock
        self._step = step

    def recv(self, size: int) -> bytes:
        self._clock.now += self._step
        return super().recv(size)

    def sendall(self, data: bytes) -> None:
        self._clock.now += self._step
        super().sendall(data)


def test_starttls_deadline_covers_the_whole_plaintext_exchange():
    clock = FakeClock()
    sock = ClockedSocket(b"220 hi\r\n", clock, step=1.0)

    with pytest.raises(TimeoutError, match="deadline"):
        cs._starttls_exchange(sock, "smtp", timeout=2.0, clock=clock)


def test_starttls_write_time_counts_toward_the_deadline():
    class WriteClockedSocket(FakeSocket):
        def sendall(self, data: bytes) -> None:
            clock.now += 2.0
            super().sendall(data)

    clock = FakeClock()
    sock = WriteClockedSocket(b"220 hi\r\n")

    with pytest.raises(TimeoutError, match="deadline"):
        cs._starttls_exchange(sock, "smtp", timeout=1.0, clock=clock)


def test_starttls_budget_error_keeps_protocol_classification(monkeypatch):
    target = cfg.Target(
        host="mail.example.com",
        port=587,
        tls_mode="starttls",
        starttls_protocol="smtp",
        check_dns=False,
        check_hsts=False,
    )
    monkeypatch.setattr(
        cs,
        "probe_starttls",
        lambda host, port, protocol: (_ for _ in ()).throw(
            cs.StartTLSError("STARTTLS aggregate byte cap exceeded")
        ),
    )

    result = cs.check_ssl("mail.example.com:587", target=target)

    assert result["status"] == "ssl_error"
    assert result["tls_mode"] == "starttls"
    assert "byte cap" in result["error"]


def test_starttls_deadline_keeps_timeout_classification(monkeypatch):
    target = cfg.Target(
        host="mail.example.com",
        port=587,
        tls_mode="starttls",
        starttls_protocol="smtp",
        check_dns=False,
        check_hsts=False,
    )
    monkeypatch.setattr(
        cs,
        "probe_starttls",
        lambda host, port, protocol: (_ for _ in ()).throw(
            TimeoutError("STARTTLS negotiation deadline exceeded")
        ),
    )

    result = cs.check_ssl("mail.example.com:587", target=target)

    assert result["status"] == "timeout"
    assert result["tls_mode"] == "starttls"
    assert "timed out" in result["error"].lower()


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
