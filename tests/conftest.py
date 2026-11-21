"""Shared fixtures for the CertiWatch checker tests.

All tests are offline: certificates are generated in memory and, where a real
handshake is needed, a throwaway TLS server is started on 127.0.0.1.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import socket
import ssl
import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
for path in (
    Path(__file__).resolve().parent,
    REPO_ROOT / "src",
    REPO_ROOT / "src" / "ssl" / "scripts",
    REPO_ROOT / "src" / "domain" / "scripts",
):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402


def _key_usage(*, is_ca: bool, rsa_key: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=rsa_key and not is_ca,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=is_ca,
        crl_sign=is_ca,
        encipher_only=None,
        decipher_only=None,
    )


def build_cert(
    *,
    common_name: str,
    key,
    sans: list[x509.GeneralName] | None = None,
    issuer_cert: x509.Certificate | None = None,
    issuer_key=None,
    is_ca: bool = False,
    organization: str = "CertiWatch Test",
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
) -> x509.Certificate:
    """Build a test certificate, self-signed unless an issuer is supplied."""
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = not_before or (now - datetime.timedelta(days=1))
    not_after = not_after or (now + datetime.timedelta(days=89))
    rsa_key = isinstance(key, rsa.RSAPrivateKey)

    subject_attrs = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization)]
    subject_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    subject = x509.Name(subject_attrs)

    if issuer_cert is not None:
        issuer = issuer_cert.subject
    else:
        issuer = subject

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(_key_usage(is_ca=is_ca, rsa_key=rsa_key), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                (issuer_cert.public_key() if issuer_cert is not None else key.public_key())
            ),
            critical=False,
        )
    )
    if not is_ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        if sans:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(sans), critical=False
            )

    signing_key = issuer_key or key
    return builder.sign(signing_key, hashes.SHA256())


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def dns_san(*names: str) -> list[x509.GeneralName]:
    return [x509.DNSName(name) for name in names]


def ip_san(*addresses: str) -> list[x509.GeneralName]:
    return [x509.IPAddress(ipaddress.ip_address(address)) for address in addresses]


class LocalTLSServer:
    """Minimal one-cert TLS server bound to 127.0.0.1 on an ephemeral port."""

    def __init__(self, cert: x509.Certificate, key, tmp_path: Path) -> None:
        self._cert_file = tmp_path / "server-cert.pem"
        self._key_file = tmp_path / "server-key.pem"
        self._cert_file.write_bytes(cert_pem(cert))
        self._key_file.write_bytes(key_pem(key))

        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(str(self._cert_file), str(self._key_file))
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def endpoint(self) -> str:
        return f"127.0.0.1:{self.port}"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                with self._context.wrap_socket(conn, server_side=True) as tls_conn:
                    tls_conn.settimeout(1.0)
                    try:
                        tls_conn.recv(1)
                    except (OSError, ssl.SSLError):
                        pass
            except (OSError, ssl.SSLError):
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def __enter__(self) -> "LocalTLSServer":
        self._thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


@pytest.fixture
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def tls_server(tmp_path):
    servers: list[LocalTLSServer] = []

    def start(cert, key) -> LocalTLSServer:
        server = LocalTLSServer(cert, key, tmp_path)
        server.__enter__()
        servers.append(server)
        return server

    yield start

    for server in servers:
        server.__exit__(None, None, None)


@pytest.fixture
def ca_bundle(tmp_path):
    """Write a CA certificate to a file and return its path."""

    def write(cert: x509.Certificate) -> str:
        path = tmp_path / "trusted-ca.pem"
        path.write_bytes(cert_pem(cert))
        return str(path)

    return write


@pytest.fixture
def json_response():
    """Build a fake urllib response object for monkeypatched urlopen."""

    def make(payload: dict):
        class FakeResponse:
            def __init__(self) -> None:
                self._body = json.dumps(payload).encode("utf-8")

            def read(self) -> bytes:
                return self._body

            def __enter__(self):
                return self

            def __exit__(self, *exc_info) -> None:
                return None

        return FakeResponse()

    return make
