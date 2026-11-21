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

import concurrent.futures
import datetime
import ipaddress
import json
import os
import re
import socket
import ssl
import tempfile
import urllib.parse
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

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


def _handshake(host: str, port: int, verify: bool) -> TLSProbe:
    context = _client_context(verify)
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            tls_version = ssock.version()
            cipher_info = ssock.cipher()
            chain_der, chain_source = _socket_chain(ssock, verify)

    if not der:
        raise ssl.SSLError("server did not present a certificate")
    return TLSProbe(
        der=der,
        tls_version=tls_version,
        cipher=cipher_info[0] if cipher_info else None,
        trusted=verify,
        chain_der=chain_der,
        chain_source=chain_source,
    )


def probe_endpoint(host: str, port: int) -> TLSProbe:
    """Handshake with chain verification, falling back to an unverified read.

    ``trusted`` means the presented chain validates against the trust store;
    the hostname is evaluated separately by ``hostname_matches()``. A
    certificate-verification failure is not fatal: the certificate is read
    without verification so its dates, names and key can still be reported,
    and the original verification error is preserved. Other TLS/socket errors
    propagate to the caller, which maps them to a status.
    """
    try:
        return _handshake(host, port, verify=True)
    except ssl.SSLCertVerificationError as exc:
        probe = _handshake(host, port, verify=False)
        probe.trusted = False
        probe.verification_error = str(exc)
        return probe


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
        "not_before": None,
        "not_after": None,
        "fingerprint_sha256": None,
        "serial_number": None,
        "tls_version": None,
        "cipher": None,
        "chain": [],
        "chain_length": 0,
        "chain_source": None,
        # Honest capability reporting: this checker never requests revocation.
        "revocation_checked": False,
        "revocation_status": "not_checked",
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


def _check_target(host: str, port: int, result: dict) -> dict:
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


def check_ssl(domain: str) -> dict:
    """Check the TLS endpoint named by ``domain`` (``host`` or ``host:port``)."""
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

    try:
        return _check_target(host, port, result)

    except ssl.SSLCertVerificationError as exc:  # defensive: probe already handles this
        result["status"] = "invalid"
        result["error"] = f"Certificate verification failed: {_trim(str(exc), 180)}"
        result["chain_error"] = _trim(str(exc))
        result["trusted_chain"] = False
        return result

    except ssl.SSLError as exc:
        # Retry once: transient handshake failures are common.
        try:
            return _check_target(host, port, result)
        except Exception:
            pass
        result["status"] = "ssl_error"
        result["error"] = f"SSL error: {_trim(str(exc), 120)}"

    except (socket.timeout, TimeoutError):
        result["status"] = "timeout"
        result["error"] = "Connection timed out"
        _attach_www_fallback(result, host, port)

    except socket.gaierror as exc:
        result["status"] = "dns_error"
        result["error"] = f"DNS error: {_trim(str(exc), 120)}"
        _attach_www_fallback(result, host, port)

    except ConnectionRefusedError:
        result["status"] = "no_https"
        result["error"] = f"Port {port} refused"

    except OSError as exc:
        result["status"] = "error"
        result["error"] = _trim(str(exc), 120)

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


def main() -> None:
    print(f"Loading domains from {DOMAIN_FILE}...")
    domains = load_domains(DOMAIN_FILE)
    print(f"Found {len(domains)} unique domains. Checking SSL certificates...")

    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_domain = {executor.submit(check_ssl, domain): domain for domain in domains}
        completed = 0
        for future in concurrent.futures.as_completed(future_to_domain):
            try:
                result = future.result()
            except Exception as exc:  # never lose the whole run to one target
                domain = future_to_domain[future]
                endpoint = parse_endpoint(domain) or (domain, DEFAULT_PORT)
                result = _base_result(
                    format_endpoint(*endpoint), endpoint[0], endpoint[1]
                )
                result["status"] = "error"
                result["error"] = f"Unexpected error: {_trim(str(exc), 120)}"
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
                f"[{completed:3d}/{len(domains)}] {status_icon} {result['domain']:<45} "
                f"{result['provider']:<25} expires: {result['expires_on']}  "
                f"({days_str}, {trust})"
            )

    results.sort(key=sort_key)
    output = build_output(domains, results)
    write_json_atomic(OUTPUT_FILE, output)

    print(f"\nResults saved to {OUTPUT_FILE}")
    print(f"  Valid:   {output['valid']}")
    print(f"  Expired: {output['expired']}")
    print(f"  Errors:  {output['errors']}")


if __name__ == "__main__":
    main()
