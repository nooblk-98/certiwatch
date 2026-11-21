#!/usr/bin/env python3
"""
SSL certificate checker.

Reads targets from ssl.conf, connects over TLS and reports:

- Provider/issuer (Let's Encrypt, Cloudflare, Google Trust Services, etc.)
- Issue date and expiry: ``days_left`` is floored for display, while status
  uses the exact ``not_after`` timestamp (``is_expired``)
- Whether the presented chain validates against the configured trust store
- DNS/IP SAN coverage (subject CN is not used for hostname matching), wildcard
  metadata, including rejection of wildcards under a single-label suffix
- Leaf key type/size/curve and SHA-256 fingerprint
- Negotiated TLS version and cipher
- The certificate chain as presented by the server

Entries may be ``host`` or ``host:port`` (default port 443), so mail and
other TLS services can be monitored as well as HTTPS.

If the configured host is unreachable on port 443 because of DNS or a timeout,
the original row keeps that status and error. A separate ``fallback`` object
may carry a full TLS result for ``www.<host>``; it never changes the original
validity. Other ports do not use a fallback.

Revocation (OCSP/CRL) is **not** checked. The result records
``revocation_checked: false`` rather than claiming a revocation status.

Outputs results to ssl_results.json (written atomically).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import time
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

try:
    from config import CONFIG_FILE, ConfigError, Target, load_config
    from dns_diagnostics import diagnose_dns
except ModuleNotFoundError:  # direct ``python3 src/ssl/scripts/check_ssl.py``
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from config import CONFIG_FILE, ConfigError, Target, load_config
    from dns_diagnostics import diagnose_dns

DOMAIN_FILE = "ssl.conf"
OUTPUT_FILE = "ssl_results.json"
DEFAULT_PORT = 443
TIMEOUT = float(os.getenv("SSL_CHECK_TIMEOUT", "15"))
MAX_WORKERS = int(os.getenv("SSL_CHECK_WORKERS", "20"))
# Optional custom trust bundle. Unset means the system trust store.
CA_FILE = os.getenv("SSL_CA_FILE") or None

# Issuer fingerprints should not be rewritten by hand in an if/elif chain.
# Each rule is (compiled pattern over "<organization> <common name>", label),
# checked in order. Patterns for short tokens use word boundaries so that
# "aws" cannot match "awsome" and "twelve" cannot match unrelated names.
CA_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"let'?s\s*encrypt|letsencrypt", re.I), "Let's Encrypt"),
    (re.compile(r"cloudflare", re.I), "Cloudflare SSL"),
    (re.compile(r"sectigo|comodo", re.I), "Sectigo / Comodo"),
    (re.compile(r"digicert", re.I), "DigiCert"),
    (re.compile(r"geotrust", re.I), "GeoTrust"),
    (re.compile(r"globalsign", re.I), "GlobalSign"),
    (re.compile(r"go\s*daddy|godaddy", re.I), "GoDaddy"),
    (re.compile(r"rapidssl", re.I), "RapidSSL"),
    (re.compile(r"thawte", re.I), "Thawte"),
    (re.compile(r"\bamazon\b|\baws\b", re.I), "Amazon / AWS"),
    (re.compile(r"google trust services|\bgts\b", re.I), "Google Trust Services"),
    (re.compile(r"zerossl", re.I), "ZeroSSL"),
    (re.compile(r"ssl\.com", re.I), "SSL.com"),
    (re.compile(r"12ssl|twelve\s*ssl", re.I), "12SSL"),
    (re.compile(r"entrust", re.I), "Entrust"),
    (re.compile(r"buypass", re.I), "Buypass"),
    (re.compile(r"identrust", re.I), "IdenTrust"),
    (re.compile(r"microsoft", re.I), "Microsoft"),
)

# Result ordering mirrors index.html: broken lookups first, healthy last.
STATUS_RANK = {
    "dns_error": 0,
    "timeout": 1,
    "expired": 2,
    "ssl_error": 3,
    "no_https": 3,
    "error": 3,
    "invalid": 4,
    "valid": 5,
}


# ── Endpoint handling ─────────────────────────────────────────────────────────


def parse_endpoint(raw: str) -> tuple[str, int] | None:
    """Parse ``host``, ``host:port`` or a URL into ``(host, port)``.

    Returns ``None`` for an entry that cannot be a TLS endpoint. The rules
    match src/validate_conf.py so a validated config is checked as written.
    """
    text = (raw or "").strip()
    if not text or any(ch.isspace() for ch in text):
        return None
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text):
        text = "//" + text

    try:
        parts = urllib.parse.urlsplit(text)
        host = (parts.hostname or "").strip().lower().rstrip(".")
        port = parts.port if parts.port is not None else DEFAULT_PORT
    except ValueError:
        return None

    if not host or "@" in parts.netloc:
        return None
    if not 1 <= port <= 65535:
        return None
    return host, port


def format_endpoint(host: str, port: int) -> str:
    """Canonical target for output: bare host on 443, otherwise host:port."""
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    return host if port == DEFAULT_PORT else f"{host}:{port}"


def load_domains(filepath: str) -> list[str]:
    """Load, normalise and deduplicate targets from a config file.

    Blank lines and ``#`` comments are skipped. A trailing ``website`` header
    from older config files is ignored. Entries are stored as canonical
    ``host`` / ``host:port`` strings, preserving order.
    """
    seen: set[tuple[str, int]] = set()
    domains: list[str] = []
    with open(filepath, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            first_token = stripped.split()[0]
            if first_token.lower() == "website":
                continue
            endpoint = parse_endpoint(first_token)
            if endpoint is None:
                continue
            host, port = endpoint
            if "_" in host:  # not a valid TLS hostname/label
                continue
            if endpoint in seen:
                continue
            seen.add(endpoint)
            domains.append(format_endpoint(host, port))
    return domains


# ── Certificate parsing ───────────────────────────────────────────────────────


def _name_fields(name: x509.Name) -> dict[str, str]:
    fields: dict[str, str] = {}
    attrs = {
        "organizationName": NameOID.ORGANIZATION_NAME,
        "commonName": NameOID.COMMON_NAME,
    }
    for key, oid in attrs.items():
        try:
            fields[key] = name.get_attributes_for_oid(oid)[0].value
        except (IndexError, ValueError):
            pass
    return fields


def detect_provider(issuer: dict) -> str:
    """Detect SSL provider from certificate issuer fields."""
    combined = f"{issuer.get('organizationName', '')} {issuer.get('commonName', '')}"
    for pattern, label in CA_RULES:
        if pattern.search(combined):
            return label

    raw_org = issuer.get("organizationName", "")
    if raw_org:
        return raw_org
    raw_cn = issuer.get("commonName", "")
    if raw_cn:
        return raw_cn
    return "Unknown"


def _not_before(cert: x509.Certificate) -> datetime.datetime:
    try:
        return cert.not_valid_before_utc
    except AttributeError:  # cryptography < 42
        return cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)


def _not_after(cert: x509.Certificate) -> datetime.datetime:
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def _iso_z(value: datetime.datetime) -> str:
    return value.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fingerprint(cert: x509.Certificate) -> str:
    from cryptography.hazmat.primitives import hashes

    digest = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def _subject_alt_names(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    """Return (dns_names, ip_addresses) from the SAN extension."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return [], []
    dns_names = [str(name) for name in san.get_values_for_type(x509.DNSName)]
    ip_addresses = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    return dns_names, ip_addresses


def _dnsname_match(pattern: str, host: str) -> bool:
    """RFC 6125-style match: a wildcard covers exactly one leftmost label.

    A wildcard suffix must contain at least two labels: ``*.example.com`` is
    accepted, ``*.com`` and ``*.uk`` are rejected rather than treated as a
    match for every name under a public suffix.
    """
    pattern = pattern.lower().rstrip(".")
    host = host.lower().rstrip(".")
    if pattern == host:
        return True
    if not pattern.startswith("*."):
        return False
    suffix = pattern[2:]
    suffix_labels = suffix.split(".")
    if len(suffix_labels) < 2 or any(not label for label in suffix_labels):
        return False
    if not host.endswith("." + suffix):
        return False
    prefix = host[: -(len(suffix) + 1)]
    return bool(prefix) and "." not in prefix


def hostname_matches(host: str, dns_names: list[str], ip_addresses: list[str]) -> bool:
    """Check a host or IP literal against the certificate's SAN entries only.

    The subject common name is deliberately not consulted. RFC 6125 and the
    CA/Browser Forum baseline requirements treat SAN as authoritative, and a
    CN-only certificate must report ``hostname_matches: false`` so a mismatch
    cannot be hidden by a legacy name.
    """
    host = host.strip().lower().rstrip(".")
    try:
        wanted_ip = ipaddress.ip_address(host)
    except ValueError:
        wanted_ip = None

    if wanted_ip is not None:
        for candidate in ip_addresses:
            try:
                if ipaddress.ip_address(candidate) == wanted_ip:
                    return True
            except ValueError:
                continue
        return False

    return any(_dnsname_match(pattern, host) for pattern in dns_names)


def classify_key_strength(key_type: str | None, key_size: int | None) -> str:
    """Classify a leaf key without pretending a borderline key is safe.

    ``weak`` means below current common practice; ``acceptable`` meets the
    common 2048-bit RSA / 256-bit ECDSA floor; ``strong`` is above it. Unknown
    key types are not guessed.
    """
    if key_type == "RSA":
        if not isinstance(key_size, int):
            return "unknown"
        if key_size < 2048:
            return "weak"
        if key_size < 3072:
            return "acceptable"
        return "strong"
    if key_type == "ECDSA":
        if not isinstance(key_size, int):
            return "unknown"
        if key_size < 256:
            return "weak"
        if key_size < 384:
            return "acceptable"
        return "strong"
    if key_type in ("Ed25519", "Ed448"):
        return "strong"
    if key_type == "DSA":
        return "weak"
    return "unknown"


def _key_metadata(cert: x509.Certificate) -> tuple[str | None, int | None, str | None]:
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size, None
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA", public_key.key_size, public_key.curve.name
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", getattr(public_key, "key_size", None), None
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", getattr(public_key, "key_size", None), None
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size, None
    return type(public_key).__name__, getattr(public_key, "key_size", None), None


def certificate_metadata(
    cert: x509.Certificate,
    host: str,
    now: datetime.datetime | None = None,
) -> dict:
    """Return the JSON fields that describe one leaf certificate."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    issuer_fields = _name_fields(cert.issuer)
    dns_names, ip_addresses = _subject_alt_names(cert)
    subject_cn = _name_fields(cert.subject).get("commonName")
    not_before = _not_before(cert)
    not_after = _not_after(cert)
    # days_left stays a floor for display. Expiry itself is decided by the
    # exact timestamp in is_expired, so a certificate with 12 hours left can
    # show 0 days and still be valid.
    days_left = (not_after - now).days
    is_expired = now >= not_after
    key_type, key_size, key_curve = _key_metadata(cert)

    all_names = dns_names + ip_addresses
    wildcard = any(name.startswith("*.") for name in dns_names)
    if not wildcard and subject_cn:
        wildcard = subject_cn.startswith("*.")

    return {
        "issued_on": not_before.strftime("%Y-%m-%d"),
        "expires_on": not_after.strftime("%Y-%m-%d"),
        "days_left": days_left,
        "is_expired": is_expired,
        "provider": detect_provider(issuer_fields),
        "not_before": _iso_z(not_before),
        "not_after": _iso_z(not_after),
        "common_name": subject_cn,
        "san": all_names,
        "san_count": len(all_names),
        "wildcard": wildcard,
        "hostname_matches": hostname_matches(host, dns_names, ip_addresses),
        "key_type": key_type,
        "key_size": key_size,
        "key_curve": key_curve,
        "key_strength": classify_key_strength(key_type, key_size),
        "fingerprint_sha256": _fingerprint(cert),
        "serial_number": format(cert.serial_number, "X"),
    }


def _chain_summary(chain_der: list[bytes]) -> tuple[list[dict], bool]:
    """Parse a DER chain into compact JSON rows. Skips unparseable entries."""
    rows: list[dict] = []
    complete = True
    for der in chain_der:
        try:
            cert = x509.load_der_x509_certificate(der, default_backend())
        except ValueError:
            complete = False
            continue
        subject_fields = _name_fields(cert.subject)
        issuer_fields = _name_fields(cert.issuer)
        try:
            is_ca = bool(
                cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            )
        except x509.ExtensionNotFound:
            is_ca = False
        rows.append(
            {
                "subject": subject_fields.get("commonName") or subject_fields.get("organizationName") or "Unknown",
                "issuer": issuer_fields.get("commonName") or issuer_fields.get("organizationName") or "Unknown",
                "not_before": _iso_z(_not_before(cert)),
                "not_after": _iso_z(_not_after(cert)),
                "is_ca": is_ca,
            }
        )
    return rows, complete


# ── HSTS (HTTPS only) ────────────────────────────────────────────────────────


def classify_hsts(headers: Mapping[str, str]) -> dict:
    """Classify a Strict-Transport-Security header without over-claiming.

    ``max-age=0`` is a real header that disables HSTS: it is present and
    syntactically valid, but ``enabled`` is false and ``status`` is
    ``disabled``. Missing headers are ``absent``; malformed ones are
    ``invalid``. ``indeterminate`` is reserved for a failed authenticated
    HTTPS connection (see ``check_hsts``).
    """
    value = None
    for key, header in headers.items():
        if str(key).lower() == "strict-transport-security":
            value = header
            break
    if value is None:
        return {
            "present": False,
            "valid": False,
            "enabled": False,
            "status": "absent",
            "max_age": None,
            "include_subdomains": False,
            "preload": False,
            "error": None,
        }

    directives = [part.strip() for part in str(value).split(";") if part.strip()]
    max_age: int | None = None
    include_subdomains = False
    preload = False
    error = None
    for directive in directives:
        name, _, raw_value = directive.partition("=")
        name = name.strip().lower()
        raw_value = raw_value.strip().strip('"')
        if name == "max-age":
            try:
                max_age = int(raw_value)
            except ValueError:
                error = "max-age is not an integer"
            else:
                if max_age < 0:
                    error = "max-age cannot be negative"
        elif name == "includesubdomains":
            include_subdomains = True
        elif name == "preload":
            preload = True

    if max_age is None and error is None:
        error = "max-age directive is missing"
    valid = max_age is not None and max_age >= 0
    enabled = valid and max_age > 0
    if not valid:
        status = "invalid"
    elif not enabled:
        status = "disabled"
    else:
        status = "present"
    return {
        "present": True,
        "valid": valid,
        "enabled": enabled,
        "status": status,
        "max_age": max_age,
        "include_subdomains": include_subdomains,
        "preload": preload,
        "error": error,
    }


def fetch_https_headers(host: str, port: int, *, timeout: float = TIMEOUT) -> dict[str, str]:
    """Read headers over a separately authenticated HTTPS connection.

    This connection uses the configured trust store (``CA_FILE`` or the system
    store) with certificate and hostname verification enabled. A HSTS header is
    only meaningful when the same origin proved its certificate and SAN; a
    failed TLS connection is reported by ``check_hsts`` as indeterminate rather
    than as missing HSTS.
    """
    context = ssl.create_default_context(cafile=CA_FILE)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    # A Common Name is not a subjectAltName. OpenSSL's legacy CN fallback must
    # not make a CN-only certificate authenticate the HSTS connection.
    context.hostname_checks_common_name = False
    connection = http.client.HTTPSConnection(
        host,
        port,
        timeout=timeout,
        context=context,
    )
    host_header = format_endpoint(host, port)
    try:
        connection.request(
            "HEAD",
            "/",
            headers={
                "Host": host_header,
                "User-Agent": "CertiWatch/1.0",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        headers = {str(key).lower(): value for key, value in response.getheaders()}
        response.read()
        return headers
    finally:
        connection.close()


def _hsts_not_applicable() -> dict:
    return {
        "applicable": False,
        "checked": False,
        "present": None,
        "valid": None,
        "enabled": None,
        "status": "not_checked",
        "max_age": None,
        "include_subdomains": None,
        "preload": None,
        "error": None,
    }


def _hsts_indeterminate(error: str | None) -> dict:
    return {
        "applicable": True,
        "checked": True,
        "present": None,
        "valid": None,
        "enabled": None,
        "status": "indeterminate",
        "max_age": None,
        "include_subdomains": None,
        "preload": None,
        "error": error or "HTTPS connection could not be authenticated",
    }


def check_hsts(
    host: str,
    port: int,
    *,
    applicable: bool,
    fetcher: Callable[[str, int], Mapping[str, str]] | None = None,
    timeout: float = TIMEOUT,
) -> dict:
    """Read HSTS only for an HTTPS origin; a non-HTTPS endpoint is inapplicable."""
    if not applicable:
        return _hsts_not_applicable()

    if fetcher is None:
        fetcher = lambda target_host, target_port: fetch_https_headers(
            target_host, target_port, timeout=timeout
        )
    try:
        headers = fetcher(host, port)
    except Exception as exc:
        return _hsts_indeterminate(
            _trim(str(exc), 180) or "HTTPS connection could not be authenticated"
        )

    classification = classify_hsts(headers)
    classification.update({"applicable": True, "checked": True})
    return classification


# ── STARTTLS and optional TLS 1.0/1.1 capability ────────────────────────────


class StartTLSError(ssl.SSLError):
    """A STARTTLS-capable service refused or did not advertise STARTTLS."""


class StartTLSUnsupported(StartTLSError):
    """The requested STARTTLS protocol is not implemented locally."""


class LocalTLSUnsupported(ssl.SSLError):
    """Local OpenSSL/Python cannot negotiate this protocol version."""


STARTTLS_MAX_TOTAL_BYTES = 64 * 1024
STARTTLS_MAX_TOTAL_LINES = 128
STARTTLS_MAX_LINE_BYTES = 4096


class _StartTLSBudget:
    """Deadline and aggregate read/write budget for plaintext negotiation.

    The deadline covers the whole exchange, not each socket call. Byte and line
    caps count both directions, so a server cannot evade the limit by sending a
    huge banner or by making us write an unbounded response. A deadline
    overrun raises ``TimeoutError`` so the checker keeps its existing
    ``timeout`` classification; a cap overrun raises ``StartTLSError`` so it
    remains a protocol error (``ssl_error``).
    """

    def __init__(
        self,
        sock: socket.socket,
        *,
        timeout: float,
        clock: Callable[[], float],
        max_bytes: int,
        max_lines: int,
        max_line_bytes: int,
    ) -> None:
        if timeout <= 0:
            raise TimeoutError("STARTTLS negotiation deadline exceeded")
        if max_bytes < 1 or max_lines < 1 or max_line_bytes < 1:
            raise ValueError("STARTTLS budget limits must be positive")
        self._sock = sock
        self._clock = clock
        self._deadline = clock() + timeout
        self._max_bytes = max_bytes
        self._max_lines = max_lines
        self._max_line_bytes = max_line_bytes
        self.bytes_read = 0
        self.bytes_written = 0
        self.lines_read = 0
        self.lines_written = 0

    def _check_deadline(self) -> float:
        remaining = self._deadline - self._clock()
        if remaining <= 0:
            raise TimeoutError("STARTTLS negotiation deadline exceeded")
        return remaining

    def _set_timeout(self) -> None:
        remaining = self._check_deadline()
        setter = getattr(self._sock, "settimeout", None)
        if callable(setter):
            setter(remaining)

    def _consume(
        self,
        *,
        read: int = 0,
        written: int = 0,
        read_lines: int = 0,
        written_lines: int = 0,
    ) -> None:
        self.bytes_read += read
        self.bytes_written += written
        self.lines_read += read_lines
        self.lines_written += written_lines
        if self.bytes_read + self.bytes_written > self._max_bytes:
            raise StartTLSError("STARTTLS aggregate byte cap exceeded")
        if self.lines_read + self.lines_written > self._max_lines:
            raise StartTLSError("STARTTLS aggregate line cap exceeded")

    def read_line(self) -> str:
        self._check_deadline()
        data = bytearray()
        while len(data) < self._max_line_bytes:
            self._set_timeout()
            chunk = self._sock.recv(1)
            self._check_deadline()
            if not chunk:
                break
            self._consume(read=len(chunk))
            data.extend(chunk)
            if data.endswith(b"\n"):
                self._consume(read_lines=1)
                return data.decode("utf-8", errors="replace").rstrip("\r\n")
        if data.endswith(b"\n"):
            self._consume(read_lines=1)
            return data.decode("utf-8", errors="replace").rstrip("\r\n")
        if len(data) >= self._max_line_bytes:
            raise StartTLSError("STARTTLS line length cap exceeded")
        if data:
            self._consume(read_lines=1)
        return data.decode("utf-8", errors="replace").rstrip("\r\n")

    def write(self, data: bytes) -> None:
        self._check_deadline()
        if len(data) > self._max_line_bytes:
            raise StartTLSError("STARTTLS line length cap exceeded")
        lines = data.count(b"\n")
        self._consume(written=len(data), written_lines=lines)
        self._set_timeout()
        sendall = getattr(self._sock, "sendall", None)
        if callable(sendall):
            sendall(data)
        else:
            view = memoryview(data)
            while view:
                sent = self._sock.send(view)
                if sent <= 0:
                    raise StartTLSError("STARTTLS write failed")
                view = view[sent:]
        self._check_deadline()


def _read_line(
    sock: socket.socket,
    limit: int = STARTTLS_MAX_LINE_BYTES,
    *,
    budget: _StartTLSBudget | None = None,
) -> str:
    """Read one line; with a budget, enforce aggregate and deadline limits.

    Kept as a small compatibility helper for callers/tests that pass a socket
    directly. Production STARTTLS negotiation always passes the budget.
    """
    if budget is not None:
        return budget.read_line()
    data = bytearray()
    while len(data) < limit:
        chunk = sock.recv(1)
        if not chunk:
            break
        data.extend(chunk)
        if data.endswith(b"\n"):
            break
    return data.decode("utf-8", errors="replace").rstrip("\r\n")


def _require_line(prefixes: tuple[str, ...], line: str, protocol: str) -> None:
    if not any(line.upper().startswith(prefix.upper()) for prefix in prefixes):
        raise StartTLSError(
            f"{protocol.upper()} did not accept STARTTLS: {line[:120] or 'no response'}"
        )


def _starttls_smtp(sock: socket.socket, budget: _StartTLSBudget) -> None:
    greeting = budget.read_line()
    _require_line(("220",), greeting, "smtp")
    budget.write(b"EHLO certiwatch.local\r\n")
    capabilities: list[str] = []
    while True:
        line = budget.read_line()
        if not line:
            raise StartTLSError("SMTP closed the connection during EHLO")
        capabilities.append(line)
        if len(line) >= 4 and line[3] == " ":
            break
    if not any("STARTTLS" in line.upper() for line in capabilities):
        raise StartTLSError("SMTP server does not advertise STARTTLS")
    budget.write(b"STARTTLS\r\n")
    _require_line(("220",), budget.read_line(), "smtp")


def _starttls_imap(sock: socket.socket, budget: _StartTLSBudget) -> None:
    greeting = budget.read_line()
    upper = greeting.upper()
    if not (upper.startswith("* OK") or upper.startswith("* PREAUTH")):
        raise StartTLSError(f"IMAP greeting rejected STARTTLS: {greeting[:120]}")
    budget.write(b"a001 STARTTLS\r\n")
    while True:
        line = budget.read_line()
        if not line:
            raise StartTLSError("IMAP closed the connection during STARTTLS")
        if line.upper().startswith("A001 "):
            _require_line(("a001 OK",), line, "imap")
            return


def _starttls_pop3(sock: socket.socket, budget: _StartTLSBudget) -> None:
    _require_line(("+OK",), budget.read_line(), "pop3")
    budget.write(b"STLS\r\n")
    _require_line(("+OK",), budget.read_line(), "pop3")


def _starttls_exchange(
    sock: socket.socket,
    protocol: str | None,
    *,
    timeout: float = TIMEOUT,
    clock: Callable[[], float] = time.monotonic,
    max_bytes: int = STARTTLS_MAX_TOTAL_BYTES,
    max_lines: int = STARTTLS_MAX_TOTAL_LINES,
    max_line_bytes: int = STARTTLS_MAX_LINE_BYTES,
) -> None:
    normalised = (protocol or "smtp").strip().lower()
    handlers = {
        "smtp": _starttls_smtp,
        "imap": _starttls_imap,
        "pop3": _starttls_pop3,
    }
    handler = handlers.get(normalised)
    if handler is None:
        raise StartTLSUnsupported(f"unsupported STARTTLS protocol: {normalised}")
    budget = _StartTLSBudget(
        sock,
        timeout=timeout,
        clock=clock,
        max_bytes=max_bytes,
        max_lines=max_lines,
        max_line_bytes=max_line_bytes,
    )
    handler(sock, budget)


LEGACY_TLS_VERSIONS = ("tls10", "tls11")


def classify_legacy_tls_error(exc: BaseException) -> str:
    """Separate a local OpenSSL limitation from a remote protocol refusal."""
    if isinstance(exc, LocalTLSUnsupported):
        return "local_unsupported"
    text = f"{getattr(exc, 'reason', '')} {exc}".lower()
    local_markers = (
        "no protocols available",
        "unsupported protocol",
        "unknown protocol",
        "no ciphers available",
        "no cipher match",
    )
    if any(marker in text for marker in local_markers):
        return "local_unsupported"
    return "not_supported"


def _legacy_context(version_name: str) -> ssl.SSLContext:
    version_name = version_name.lower()
    if version_name not in LEGACY_TLS_VERSIONS:
        raise LocalTLSUnsupported(f"unknown legacy TLS version: {version_name}")
    try:
        version = getattr(
            ssl.TLSVersion,
            "TLSv1" if version_name == "tls10" else "TLSv1_1",
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        return context
    except (AttributeError, ValueError, ssl.SSLError) as exc:
        raise LocalTLSUnsupported(str(exc) or "legacy TLS is disabled locally") from exc


def _legacy_handshake(
    host: str,
    port: int,
    version_name: str,
    *,
    tls_mode: str = "direct",
    protocol: str | None = None,
) -> None:
    context = _legacy_context(version_name)
    sock = _open_socket(host, port, tls_mode, protocol)
    try:
        with context.wrap_socket(sock, server_hostname=host):
            return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_legacy_version(
    host: str,
    port: int,
    version_name: str,
    *,
    tls_mode: str = "direct",
    protocol: str | None = None,
    handshake: Callable[..., None] | None = None,
) -> str:
    handshake = handshake or _legacy_handshake
    if version_name not in LEGACY_TLS_VERSIONS:
        return "local_unsupported"
    try:
        handshake(
            host,
            port,
            version_name,
            tls_mode=tls_mode,
            protocol=protocol,
        )
    except LocalTLSUnsupported:
        return "local_unsupported"
    except ssl.SSLError as exc:
        return classify_legacy_tls_error(exc)
    except (socket.timeout, TimeoutError):
        return "unknown"
    except OSError:
        return "unknown"
    except ValueError:
        return "local_unsupported"
    return "supported"


def check_legacy_tls(
    host: str,
    port: int,
    *,
    tls_mode: str = "direct",
    protocol: str | None = None,
    handshake: Callable[..., None] | None = None,
) -> dict:
    return {
        "checked": True,
        "tls10": probe_legacy_version(
            host, port, "tls10", tls_mode=tls_mode, protocol=protocol, handshake=handshake
        ),
        "tls11": probe_legacy_version(
            host, port, "tls11", tls_mode=tls_mode, protocol=protocol, handshake=handshake
        ),
        "note": (
            "local_unsupported means this machine's OpenSSL/Python cannot try the "
            "protocol; it is not evidence about the server. not_supported and "
            "supported are remote outcomes."
        ),
    }


def _not_checked_legacy_tls() -> dict:
    return {"checked": False, "tls10": "not_checked", "tls11": "not_checked"}


# ── TLS probing ───────────────────────────────────────────────────────────────


@dataclass
class TLSProbe:
    """One TLS handshake result."""

    der: bytes
    tls_version: str | None
    cipher: str | None
    trusted: bool
    verification_error: str | None = None
    chain_der: list[bytes] = field(default_factory=list)
    chain_source: str = "leaf"
    tls_mode: str = "direct"
    starttls_protocol: str | None = None


def _client_context(verify: bool) -> ssl.SSLContext:
    """Build the context used for a probe handshake.

    Trust for ``trusted_chain`` comes from ``ssl.create_default_context()``:
    the interpreter/OpenSSL default trust store (honouring ``SSL_CERT_FILE``
    and ``SSL_CERT_DIR``) or the bundle named by ``SSL_CA_FILE``. Hostname
    checking is disabled on that context because the chain probe reports
    trust only; ``hostname_matches()`` evaluates DNS/IP SAN coverage from the
    leaf separately. A private CA therefore has to be added to the configured
    trust store before ``trusted_chain`` can become true.
    """
    if verify:
        context = ssl.create_default_context(cafile=CA_FILE)
        context.check_hostname = False
        return context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _socket_chain(ssock: ssl.SSLSocket, verified: bool) -> tuple[list[bytes], str]:
    """Read the chain the interpreter exposes for this handshake.

    Python 3.13+ returns DER bytes; older builds have no public chain API, so
    the leaf alone is reported and ``chain_source`` says so.
    """
    getter = getattr(ssock, "get_verified_chain" if verified else "get_unverified_chain", None)
    if getter is None:
        return [], "leaf"
    try:
        raw_chain = getter()
    except (ssl.SSLError, ValueError):
        return [], "leaf"

    der_chain: list[bytes] = []
    for entry in raw_chain or []:
        if isinstance(entry, (bytes, bytearray)):
            der_chain.append(bytes(entry))
            continue
        public_bytes = getattr(entry, "public_bytes", None)
        if public_bytes is None:
            continue
        try:
            der_chain.append(public_bytes())
        except (TypeError, ValueError):
            continue
    if not der_chain:
        return [], "leaf"
    return der_chain, "verified" if verified else "unverified"


def _open_socket(
    host: str,
    port: int,
    tls_mode: str = "direct",
    protocol: str | None = None,
) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=TIMEOUT)
    if tls_mode == "starttls":
        try:
            _starttls_exchange(sock, protocol)
            # The plaintext budget must not shorten the subsequent TLS
            # handshake; restore the normal checker timeout.
            sock.settimeout(TIMEOUT)
        except BaseException:
            try:
                sock.close()
            except OSError:
                pass
            raise
    return sock


def _handshake(
    host: str,
    port: int,
    verify: bool,
    *,
    tls_mode: str = "direct",
    starttls_protocol: str | None = None,
) -> TLSProbe:
    context = _client_context(verify)
    sock = _open_socket(host, port, tls_mode, starttls_protocol)
    try:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            tls_version = ssock.version()
            cipher_info = ssock.cipher()
            chain_der, chain_source = _socket_chain(ssock, verify)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if not der:
        raise ssl.SSLError("server did not present a certificate")
    return TLSProbe(
        der=der,
        tls_version=tls_version,
        cipher=cipher_info[0] if cipher_info else None,
        trusted=verify,
        chain_der=chain_der,
        chain_source=chain_source,
        tls_mode=tls_mode,
        starttls_protocol=starttls_protocol if tls_mode == "starttls" else None,
    )


def _probe_with_fallback(
    host: str,
    port: int,
    *,
    tls_mode: str = "direct",
    starttls_protocol: str | None = None,
) -> TLSProbe:
    try:
        return _handshake(
            host,
            port,
            verify=True,
            tls_mode=tls_mode,
            starttls_protocol=starttls_protocol,
        )
    except ssl.SSLCertVerificationError as exc:
        probe = _handshake(
            host,
            port,
            verify=False,
            tls_mode=tls_mode,
            starttls_protocol=starttls_protocol,
        )
        probe.trusted = False
        probe.verification_error = str(exc)
        return probe


def probe_endpoint(host: str, port: int) -> TLSProbe:
    """Handshake with chain verification, falling back to an unverified read.

    ``trusted`` means the presented chain validates against the trust store;
    the hostname is evaluated separately by ``hostname_matches()``. A
    certificate-verification failure is not fatal: the certificate is read
    without verification so its dates, names and key can still be reported,
    and the original verification error is preserved. Other TLS/socket errors
    propagate to the caller, which maps them to a status.
    """
    return _probe_with_fallback(host, port, tls_mode="direct")


def probe_starttls(host: str, port: int, protocol: str | None = "smtp") -> TLSProbe:
    """Probe a STARTTLS service (SMTP/IMAP/POP3), not an implicit TLS socket."""
    return _probe_with_fallback(
        host,
        port,
        tls_mode="starttls",
        starttls_protocol=protocol or "smtp",
    )


# ── Result assembly ───────────────────────────────────────────────────────────


def _trim(value: str | None, limit: int = 240) -> str | None:
    if not value:
        return None
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _self_signed(chain: list[dict]) -> bool:
    return (
        len(chain) == 1
        and chain[0].get("subject") == chain[0].get("issuer")
        and bool(chain[0].get("subject"))
    )


def derive_status(
    *,
    days_left: int | None,
    is_expired: bool,
    trusted_chain: bool,
    host_matches: bool | None,
    verification_error: str | None,
    self_signed: bool,
) -> tuple[str, str | None]:
    """Map probe facts to the legacy status/error pair.

    Expiry uses the exact ``not_after`` timestamp (``is_expired``), not the
    floored ``days_left`` display value. ``error`` keeps a human summary; the
    untouched verification text lives in ``chain_error`` so a real CA/name
    problem is never reduced to "invalid".
    """
    if days_left is None:
        return "invalid", "Certificate has no readable expiry date"
    if is_expired:
        return "expired", "Certificate has expired"
    if host_matches is False:
        return "invalid", "Hostname mismatch"
    if not trusted_chain:
        if self_signed:
            return "invalid", "Self-signed certificate"
        if verification_error:
            return "invalid", f"Certificate verification failed: {_trim(verification_error, 180)}"
        return "invalid", "Certificate chain is not trusted"
    return "valid", None


def _base_result(domain: str, host: str, port: int) -> dict:
    return {
        "domain": domain,
        "host": host,
        "port": port,
        "status": "error",
        "provider": "N/A",
        "issued_on": "N/A",
        "expires_on": "N/A",
        "days_left": None,
        "is_expired": None,
        "error": None,
        "checked_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "resolved_via": None,
        "fallback": None,
        "trusted_chain": None,
        "chain_error": None,
        "hostname_matches": None,
        "common_name": None,
        "wildcard": False,
        "san": [],
        "san_count": 0,
        "key_type": None,
        "key_size": None,
        "key_curve": None,
        "key_strength": None,
        "not_before": None,
        "not_after": None,
        "fingerprint_sha256": None,
        "serial_number": None,
        "tls_version": None,
        "cipher": None,
        "tls_mode": "direct",
        "starttls_protocol": None,
        "https": port == DEFAULT_PORT,
        "chain": [],
        "chain_length": 0,
        "chain_source": None,
        "dns_name": None,
        "dns": {
            "checked": False,
            "name": None,
            "ns": {"status": "not_checked", "records": [], "error": None},
            "caa": {"status": "not_checked", "records": [], "error": None},
            "dnssec": {
                "status": "not_checked",
                "validated": False,
                "records": [],
                "signature_count": 0,
                "error": None,
            },
            "error": None,
        },
        "hsts": _hsts_not_applicable(),
        "legacy_tls": _not_checked_legacy_tls(),
        # Honest capability reporting: this checker never requests revocation.
        "revocation_checked": False,
        "revocation_status": "not_checked",
        "revocation_supported": False,
        "revocation": {
            "checked": False,
            "supported": False,
            "status": "not_checked",
            "method": None,
            "error": None,
            "note": (
                "OCSP/CRL revocation verification is not implemented; this "
                "checker does not claim a revocation result."
            ),
        },
    }


def _apply_probe(result: dict, probe: TLSProbe, match_host: str, now: datetime.datetime | None = None) -> None:
    cert = x509.load_der_x509_certificate(probe.der, default_backend())
    metadata = certificate_metadata(cert, match_host, now=now)
    result.update(metadata)

    chain_der = probe.chain_der or [probe.der]
    chain, complete = _chain_summary(chain_der)
    result["chain"] = chain
    result["chain_length"] = len(chain)
    result["chain_source"] = probe.chain_source if probe.chain_der else "leaf"
    if not complete:
        result["chain_error"] = "Some certificates in the chain could not be parsed"
    if probe.verification_error:
        # A real verification failure always wins over a parsing note.
        result["chain_error"] = _trim(probe.verification_error)

    result["trusted_chain"] = probe.trusted
    result["tls_version"] = probe.tls_version
    result["cipher"] = probe.cipher

    if probe.verification_error and not result["chain_error"]:
        result["chain_error"] = _trim(probe.verification_error)

    self_signed = _self_signed(chain)
    status, error = derive_status(
        days_left=metadata["days_left"],
        is_expired=metadata["is_expired"],
        trusted_chain=probe.trusted,
        host_matches=metadata["hostname_matches"],
        verification_error=probe.verification_error,
        self_signed=self_signed,
    )
    result["status"] = status
    result["error"] = error


def _check_target(
    host: str,
    port: int,
    result: dict,
    *,
    tls_mode: str = "direct",
    starttls_protocol: str | None = None,
) -> dict:
    if tls_mode == "starttls":
        probe = probe_starttls(host, port, starttls_protocol)
    else:
        probe = probe_endpoint(host, port)
    _apply_probe(result, probe, match_host=host)
    return result


def _attach_www_fallback(result: dict, host: str, port: int) -> None:
    """Record an optional ``www.`` probe without changing the original row.

    The configured host keeps its DNS/timeout status and error. Only on port
    443, and only when the host is not already ``www.``-prefixed, a complete
    second TLS result is stored in ``fallback`` with its own ``domain`` and
    ``resolved_via``. The fallback never contributes to the original row's
    validity or status; consumers must opt in to it.
    """
    if port != DEFAULT_PORT or host.startswith("www."):
        return

    fallback_host = f"www.{host}"
    fallback = _base_result(format_endpoint(fallback_host, port), fallback_host, port)
    try:
        _check_target(fallback_host, port, fallback)
    except Exception:
        # A failed fallback leaves no object; the original error stands alone.
        return
    fallback["resolved_via"] = format_endpoint(fallback_host, port)
    result["fallback"] = fallback


def _not_checked_dns(name: str | None) -> dict:
    return {
        "checked": False,
        "name": name,
        "ns": {"status": "not_checked", "records": [], "error": None},
        "caa": {"status": "not_checked", "records": [], "error": None},
        "dnssec": {
            "status": "not_checked",
            "validated": False,
            "records": [],
            "signature_count": 0,
            "error": None,
        },
        "error": None,
    }


def _failed_dns(name: str | None, exc: BaseException) -> dict:
    result = _not_checked_dns(name)
    error = _trim(str(exc), 180) or "DNS diagnostics failed"
    result.update({"checked": False, "error": error})
    for record in ("ns", "caa", "dnssec"):
        result[record]["status"] = "unknown"
        result[record]["error"] = error
    return result


def _hsts_disabled() -> dict:
    return {
        "applicable": True,
        "checked": False,
        "present": None,
        "valid": None,
        "enabled": None,
        "status": "not_checked",
        "max_age": None,
        "include_subdomains": None,
        "preload": None,
        "error": None,
    }


def _apply_configured_diagnostics(
    result: dict,
    host: str,
    port: int,
    target: Target | None,
) -> None:
    """Attach diagnostics only for a configured target, never in legacy mode."""
    if target is None:
        result["https"] = port == DEFAULT_PORT
        return

    result.update(target.connection_metadata())
    dns_name = target.dns_name_value
    result["dns_name"] = dns_name

    if target.check_dns:
        try:
            result["dns"] = diagnose_dns(dns_name)
        except Exception as exc:  # diagnostics must not abort the TLS verdict
            result["dns"] = _failed_dns(dns_name, exc)
    else:
        result["dns"] = _not_checked_dns(dns_name)

    if target.is_https:
        if target.check_hsts:
            try:
                result["hsts"] = check_hsts(host, port, applicable=True)
            except Exception as exc:
                result["hsts"] = _hsts_indeterminate(
                    _trim(str(exc), 180) or "HSTS check failed"
                )
        else:
            result["hsts"] = _hsts_disabled()
    else:
        result["hsts"] = _hsts_not_applicable()

    if target.check_legacy_tls:
        try:
            result["legacy_tls"] = check_legacy_tls(
                host,
                port,
                tls_mode=target.tls_mode,
                protocol=target.starttls_protocol,
            )
        except Exception:
            result["legacy_tls"] = {
                "checked": True,
                "tls10": "unknown",
                "tls11": "unknown",
                "note": "Legacy TLS capability probe failed locally.",
            }
    else:
        result["legacy_tls"] = _not_checked_legacy_tls()


def check_ssl(domain: str, *, target: Target | None = None) -> dict:
    """Check the TLS endpoint named by ``domain`` (``host`` or ``host:port``).

    ``target`` supplies unified-config options (STARTTLS mode, DNS/HSTS/legacy
    diagnostics). Without it the legacy direct-TLS behaviour is unchanged and
    no extra DNS/HTTP traffic is made.
    """
    endpoint = parse_endpoint(domain)
    if endpoint is None:
        clean = (domain or "").strip() or "empty entry"
        result = _base_result(clean, clean, DEFAULT_PORT)
        result["status"] = "error"
        result["error"] = "Invalid host or port"
        return result

    host, port = endpoint
    canonical = format_endpoint(host, port)
    result = _base_result(canonical, host, port)
    tls_mode = target.tls_mode if target is not None else "direct"
    starttls_protocol = target.starttls_protocol if target is not None else None
    if target is not None:
        result.update(target.connection_metadata())
        result["dns_name"] = target.dns_name_value

    try:
        _check_target(
            host,
            port,
            result,
            tls_mode=tls_mode,
            starttls_protocol=starttls_protocol,
        )

    except ssl.SSLCertVerificationError as exc:  # defensive: probe already handles this
        result["status"] = "invalid"
        result["error"] = f"Certificate verification failed: {_trim(str(exc), 180)}"
        result["chain_error"] = _trim(str(exc))
        result["trusted_chain"] = False

    except ssl.SSLError as exc:
        # Retry once: transient handshake failures are common.
        try:
            _check_target(
                host,
                port,
                result,
                tls_mode=tls_mode,
                starttls_protocol=starttls_protocol,
            )
        except Exception:
            result["status"] = "ssl_error"
            result["error"] = f"SSL error: {_trim(str(exc), 120)}"

    except (socket.timeout, TimeoutError):
        result["status"] = "timeout"
        result["error"] = "Connection timed out"
        if tls_mode == "direct":
            _attach_www_fallback(result, host, port)

    except socket.gaierror as exc:
        result["status"] = "dns_error"
        result["error"] = f"DNS error: {_trim(str(exc), 120)}"
        if tls_mode == "direct":
            _attach_www_fallback(result, host, port)

    except ConnectionRefusedError:
        result["status"] = "no_https"
        result["error"] = f"Port {port} refused"

    except OSError as exc:
        result["status"] = "error"
        result["error"] = _trim(str(exc), 120)

    _apply_configured_diagnostics(result, host, port, target)
    return result


# ── Output ────────────────────────────────────────────────────────────────────


def write_json_atomic(path: str, payload: dict) -> None:
    """Write JSON via a sibling temp file + rename.

    A crash or a full disk can never leave a half-written result file for the
    dashboard or the Pages build to consume.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


def sort_key(result: dict) -> tuple[int, int]:
    rank = STATUS_RANK.get(result.get("status", ""), 3)
    days = result.get("days_left")
    return rank, days if days is not None else 9999


def build_output(domains: list[str], results: list[dict]) -> dict:
    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "total_domains": len(domains),
        "valid": sum(1 for row in results if row.get("status") == "valid"),
        "expired": sum(1 for row in results if row.get("status") == "expired"),
        "errors": sum(1 for row in results if row.get("status") not in ("valid", "expired")),
        "results": results,
    }


def load_monitor_endpoints(
    config_path: str | Path | None = None,
) -> list[tuple[str, Target]]:
    """Return ``(endpoint, target)`` rows from the unified or legacy config."""
    loaded = load_config(config_path)
    endpoints = list(loaded.ssl_endpoints())
    if not endpoints:
        raise ConfigError("configuration contains no SSL targets")
    return endpoints


def apply_public_metadata(result: dict, target: Target | None) -> dict:
    """Attach only tags/group. Owner and notes never enter a result file."""
    if target is not None:
        result.update(target.public_metadata())
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check TLS certificates for CertiWatch.")
    parser.add_argument("--config", default=None, help=f"default: ./{CONFIG_FILE}")
    parser.add_argument("--ssl-conf", default=DOMAIN_FILE, help="legacy plain-text input")
    parser.add_argument("--output", default=OUTPUT_FILE)
    args = parser.parse_args(argv)

    try:
        if args.config is not None or Path(CONFIG_FILE).exists():
            source = args.config or CONFIG_FILE
            print(f"Loading targets from {source}...")
            entries = load_monitor_endpoints(args.config)
        else:
            print(f"Loading domains from {args.ssl_conf} (legacy)...")
            entries = [(domain, None) for domain in load_domains(args.ssl_conf)]
    except (ConfigError, OSError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1

    if not entries:
        print("No SSL targets configured.", file=sys.stderr)
        return 1

    print(f"Found {len(entries)} unique endpoints. Checking SSL certificates...")

    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_entry = {
            executor.submit(check_ssl, endpoint, target=target): (endpoint, target)
            for endpoint, target in entries
        }
        completed = 0
        for future in concurrent.futures.as_completed(future_to_entry):
            endpoint, target = future_to_entry[future]
            try:
                result = future.result()
            except Exception as exc:  # never lose the whole run to one target
                parsed = parse_endpoint(endpoint) or (endpoint, DEFAULT_PORT)
                result = _base_result(
                    format_endpoint(*parsed), parsed[0], parsed[1]
                )
                result["status"] = "error"
                result["error"] = f"Unexpected error: {_trim(str(exc), 120)}"
            apply_public_metadata(result, target)
            results.append(result)
            completed += 1
            status_icon = {
                "valid": "✓",
                "expired": "✗",
                "error": "!",
                "timeout": "?",
                "dns_error": "?",
                "ssl_error": "!",
                "invalid": "!",
                "no_https": "-",
            }.get(result["status"], "?")
            days = result["days_left"]
            days_str = f"{days}d" if days is not None else "N/A"
            trust = "trusted" if result.get("trusted_chain") else "untrusted"
            print(
                f"[{completed:3d}/{len(entries)}] {status_icon} {result['domain']:<45} "
                f"{result['provider']:<25} expires: {result['expires_on']}  "
                f"({days_str}, {trust})"
            )

    results.sort(key=sort_key)
    output = build_output([endpoint for endpoint, _ in entries], results)
    write_json_atomic(args.output, output)

    print(f"\nResults saved to {args.output}")
    print(f"  Valid:   {output['valid']}")
    print(f"  Expired: {output['expired']}")
    print(f"  Errors:  {output['errors']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
