#!/usr/bin/env python3
"""Unified CertiWatch configuration.

``certiwatch.toml`` is the primary input for both checkers and for the
monitoring lifecycle. It is parsed with :mod:`tomllib`, validated against
``schema/certiwatch.schema.json``, then normalised into immutable
:class:`Target` objects.

Legacy ``ssl.conf`` / ``domains.conf`` files remain readable *only* when no
``certiwatch.toml`` exists. They are a local compatibility path: they carry no
tags, group, owner or notes. If a TOML file exists but cannot be parsed or
validated, loading fails; it never falls back silently to the old files.

Privacy rule: ``owner`` and ``notes`` are not emitted into result files,
history, feeds or alerts. The tracked ``certiwatch.toml`` is public in Git, so
those values are still public and must not contain secrets.
``Target.public_metadata()`` exposes exactly ``tags`` and ``group``, which are
the only target metadata the checkers and public history may write.
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.parse
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib

try:  # jsonschema is a declared runtime dependency; keep a clear error if absent.
    import jsonschema
except ImportError:  # pragma: no cover - exercised only in a broken install
    jsonschema = None  # type: ignore[assignment]

CONFIG_FILE = "certiwatch.toml"
LEGACY_SSL_FILE = "ssl.conf"
LEGACY_DOMAIN_FILE = "domains.conf"
DEFAULT_SSL_PORT = 443
DEFAULT_THRESHOLDS = (30, 14, 7, 1)
DEFAULT_HISTORY_LIMIT = 365
DEFAULT_CHECK_DNS = True
DEFAULT_CHECK_HSTS = True
DEFAULT_CHECK_LEGACY_TLS = False
SUPPORTED_VERSION = 1
TLS_MODES = ("direct", "starttls")
STARTTLS_PROTOCOLS = ("smtp", "imap", "pop3")

SCHEMA_FILE = Path(__file__).resolve().parent.parent / "schema" / "certiwatch.schema.json"

LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class ConfigError(ValueError):
    """A configuration file is missing, malformed or semantically invalid."""


# ── Endpoint handling ────────────────────────────────────────────────────────


def parse_endpoint(raw: str) -> tuple[str, int] | None:
    """Parse ``host``, ``host:port`` or a URL into ``(host, port)``.

    The rules match ``src/ssl/scripts/check_ssl.py`` so the unified config and
    the legacy checker agree on what a valid endpoint is.
    """
    parsed = split_endpoint(raw)
    if parsed is None:
        return None
    host, port, _explicit = parsed
    return host, port


def split_endpoint(raw: str) -> tuple[str, int, bool] | None:
    """Return ``(host, port, port_was_explicit)`` or ``None`` when invalid."""
    text = (raw or "").strip()
    if not text or any(ch.isspace() for ch in text):
        return None
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text):
        text = "//" + text

    try:
        parts = urllib.parse.urlsplit(text)
        host = (parts.hostname or "").strip().lower().rstrip(".")
        explicit = parts.port is not None
        port = parts.port if explicit else DEFAULT_SSL_PORT
    except ValueError:
        return None

    if not host or "@" in parts.netloc:
        return None
    if not 1 <= port <= 65535:
        return None
    return host, port, explicit


def format_endpoint(host: str, port: int) -> str:
    """Canonical target: bare host on 443, otherwise host:port."""
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    return host if port == DEFAULT_SSL_PORT else f"{host}:{port}"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _valid_host(host: str) -> bool:
    """Accept an IP literal or a valid multi-label DNS hostname."""
    if _is_ip(host):
        return True
    labels = host.split(".")
    if len(labels) < 2:
        return False
    if any(not label for label in labels):
        return False
    if len(labels[-1]) < 2:
        return False
    return all(LABEL_RE.match(label) for label in labels)


def _registration_domain(host: str) -> str:
    host = host.lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def _normalise_dns_name(value: str) -> str | None:
    """Return a bare DNS name suitable for NS/CAA/DNSSEC, or ``None``."""
    text = (value or "").strip()
    if not text or any(ch.isspace() for ch in text):
        return None
    parsed = split_endpoint(text)
    if parsed is None:
        return None
    host, _port, port_was_explicit = parsed
    if port_was_explicit or _is_ip(host) or not _valid_host(host):
        return None
    return host


# ── Normalised objects ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class Target:
    """One monitored endpoint or registration.

    ``host`` keeps a leading ``www.`` for TLS checks. Registration keys strip
    it because www and the bare name share one registration. ``owner`` and
    ``notes`` are not emitted; use :meth:`public_metadata` for anything
    published. Because the TOML file is tracked, its owner/notes values are
    still public in Git.
    """

    host: str
    port: int = DEFAULT_SSL_PORT
    ssl: bool = True
    registration: bool = False
    tags: tuple[str, ...] = ()
    group: str | None = None
    owner: str | None = None
    notes: str | None = None
    tls_mode: str = "direct"
    starttls_protocol: str | None = None
    https: bool | None = None
    dns_name: str | None = None
    # A directly constructed Target is inert; Config.load applies the TOML
    # defaults (DNS/HSTS on, legacy TLS off) before handing it to a checker.
    check_dns: bool = False
    check_hsts: bool = False
    check_legacy_tls: bool = False

    @property
    def ssl_endpoint(self) -> str | None:
        return format_endpoint(self.host, self.port) if self.ssl else None

    @property
    def registration_domain(self) -> str:
        return _registration_domain(self.host)

    @property
    def dns_name_value(self) -> str:
        value = self.dns_name or self.registration_domain
        return value.strip().lower().rstrip(".")

    @property
    def is_https(self) -> bool:
        if self.https is not None:
            return self.https
        return self.tls_mode == "direct" and self.port == DEFAULT_SSL_PORT

    def public_metadata(self) -> dict[str, Any]:
        """Only the metadata a public result file may carry."""
        return {"tags": list(self.tags), "group": self.group}

    def connection_metadata(self) -> dict[str, Any]:
        """Endpoint facts that are public but are not privacy metadata."""
        return {
            "tls_mode": self.tls_mode,
            "starttls_protocol": self.starttls_protocol,
            "https": self.is_https,
            "dns_name": self.dns_name_value,
        }

    def private_metadata(self) -> dict[str, Any]:
        """Local-only metadata. Never pass this to a public writer."""
        return {"owner": self.owner, "notes": self.notes}


@dataclass(frozen=True)
class Alerts:
    discord: bool = False


@dataclass(frozen=True)
class Config:
    version: int
    thresholds: tuple[int, int, int, int]
    ssl_port: int
    history_limit: int
    targets: tuple[Target, ...]
    alerts: Alerts = Alerts()
    source: str = "toml"
    path: Path | None = None
    check_dns: bool = DEFAULT_CHECK_DNS
    check_hsts: bool = DEFAULT_CHECK_HSTS
    check_legacy_tls: bool = DEFAULT_CHECK_LEGACY_TLS

    def ssl_targets(self) -> tuple[Target, ...]:
        return tuple(target for target in self.targets if target.ssl)

    def registration_targets(self) -> tuple[Target, ...]:
        return tuple(target for target in self.targets if target.registration)

    def ssl_endpoints(self) -> tuple[tuple[str, Target], ...]:
        endpoints: list[tuple[str, Target]] = []
        for target in self.ssl_targets():
            endpoint = target.ssl_endpoint
            if endpoint is not None:
                endpoints.append((endpoint, target))
        return tuple(endpoints)


# ── Threshold bands ──────────────────────────────────────────────────────────

_BAND_LABELS = ("notice", "warning", "urgent", "critical")


def band_for_days(
    days_left: int | None,
    thresholds: tuple[int, ...] = DEFAULT_THRESHOLDS,
) -> str:
    """Map remaining days to a stable alert band.

    Four descending thresholds produce the fixed bands ``notice``, ``warning``,
    ``urgent`` and ``critical``. Negative days are ``expired``; a missing value
    is ``unknown``. The default ``[30, 14, 7, 1]`` means 31+ days = ``ok``,
    30-15 = ``notice``, 14-8 = ``warning``, 7-2 = ``urgent``, 1-0 = ``critical``.
    """
    if days_left is None:
        return "unknown"
    if days_left < 0:
        return "expired"
    if len(thresholds) != len(_BAND_LABELS):
        raise ConfigError("thresholds must contain exactly four descending values")
    for threshold, label in zip(reversed(thresholds), reversed(_BAND_LABELS)):
        if days_left <= threshold:
            return label
    return "ok"


# ── Loading ──────────────────────────────────────────────────────────────────


def schema_path() -> Path:
    return SCHEMA_FILE


def load_config(
    path: str | Path | None = None,
    *,
    allow_legacy: bool = True,
) -> Config:
    """Load and validate configuration.

    With no ``path``: use ``certiwatch.toml`` when it exists, otherwise the
    legacy ``ssl.conf`` / ``domains.conf`` pair. An existing but invalid TOML
    file always raises :class:`ConfigError`; the legacy files are not tried.
    """
    if path is not None:
        target = Path(path)
        if not target.exists():
            raise ConfigError(f"configuration file not found: {target}")
        return _load_toml(target)

    default = Path(CONFIG_FILE)
    if default.exists():
        return _load_toml(default)
    if allow_legacy:
        return load_legacy_config()
    raise ConfigError(f"configuration file not found: {default}")


def _load_toml(path: Path) -> Config:
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read configuration: {exc}") from exc

    _validate_document(document, path)
    return _normalise_document(document, path)


def _validate_document(document: dict[str, Any], path: Path) -> None:
    if not isinstance(document, dict):
        raise ConfigError(f"{path}: the top level must be a TOML table")
    if jsonschema is None:
        raise ConfigError(
            "jsonschema is required to validate certiwatch.toml; "
            "install the dependencies from requirements.txt"
        )

    schema_file = schema_path()
    try:
        schema = json.loads(schema_file.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read JSON Schema {schema_file}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"JSON Schema {schema_file} is not valid JSON: {exc}") from exc

    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        where = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}"
            for part in first.path
        )
        raise ConfigError(f"{path}: {where}: {first.message}")


def _normalise_document(document: dict[str, Any], path: Path) -> Config:
    defaults = document.get("defaults") or {}
    thresholds_raw = defaults.get("thresholds", list(DEFAULT_THRESHOLDS))
    thresholds = _normalise_thresholds(thresholds_raw, path)
    ssl_port = int(defaults.get("ssl_port", DEFAULT_SSL_PORT))
    history_limit = int(defaults.get("history_limit", DEFAULT_HISTORY_LIMIT))
    check_dns = bool(defaults.get("check_dns", DEFAULT_CHECK_DNS))
    check_hsts = bool(defaults.get("check_hsts", DEFAULT_CHECK_HSTS))
    check_legacy_tls = bool(defaults.get("check_legacy_tls", DEFAULT_CHECK_LEGACY_TLS))
    alerts_doc = document.get("alerts") or {}

    targets: list[Target] = []
    ssl_seen: dict[str, int] = {}
    registration_seen: dict[str, int] = {}

    for index, item in enumerate(document["targets"]):
        target = _normalise_target(
            item,
            index,
            ssl_port,
            path,
            default_check_dns=check_dns,
            default_check_hsts=check_hsts,
            default_check_legacy_tls=check_legacy_tls,
        )
        if target.ssl:
            endpoint = target.ssl_endpoint
            assert endpoint is not None
            if endpoint in ssl_seen:
                raise ConfigError(
                    f"{path}: duplicate SSL endpoint {endpoint!r} "
                    f"(targets[{ssl_seen[endpoint]}] and targets[{index}])"
                )
            ssl_seen[endpoint] = index
        if target.registration:
            domain = target.registration_domain
            if domain in registration_seen:
                raise ConfigError(
                    f"{path}: duplicate registration domain {domain!r} "
                    f"(targets[{registration_seen[domain]}] and targets[{index}])"
                )
            registration_seen[domain] = index
        targets.append(target)

    return Config(
        version=int(document["version"]),
        thresholds=thresholds,
        ssl_port=ssl_port,
        history_limit=history_limit,
        targets=tuple(targets),
        check_dns=check_dns,
        check_hsts=check_hsts,
        check_legacy_tls=check_legacy_tls,
        alerts=Alerts(discord=bool(alerts_doc.get("discord", False))),
        source="toml",
        path=path,
    )


def _normalise_thresholds(values: Any, path: Path) -> tuple[int, int, int, int]:
    if not isinstance(values, list) or len(values) != 4:
        raise ConfigError(f"{path}: thresholds must contain exactly four values")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise ConfigError(f"{path}: thresholds must be integers")
    if any(value < 0 for value in values):
        raise ConfigError(f"{path}: thresholds cannot be negative")
    if any(values[i] <= values[i + 1] for i in range(len(values) - 1)):
        raise ConfigError(f"{path}: thresholds must be strictly descending")
    return values[0], values[1], values[2], values[3]


def _normalise_target(
    item: dict[str, Any],
    index: int,
    default_port: int,
    path: Path,
    *,
    default_check_dns: bool = DEFAULT_CHECK_DNS,
    default_check_hsts: bool = DEFAULT_CHECK_HSTS,
    default_check_legacy_tls: bool = DEFAULT_CHECK_LEGACY_TLS,
) -> Target:
    where = f"{path}: targets[{index}]"
    raw_domain = item.get("domain")
    if not isinstance(raw_domain, str) or not raw_domain.strip():
        raise ConfigError(f"{where}: domain is required")

    parsed = split_endpoint(raw_domain)
    if parsed is None:
        raise ConfigError(f"{where}: invalid domain {raw_domain!r}")
    host, explicit_port, port_was_explicit = parsed

    ssl_enabled = bool(item.get("ssl", True))
    registration = bool(item.get("registration", False))
    if not ssl_enabled and not registration:
        raise ConfigError(f"{where}: enable ssl, registration, or both")

    ssl_port_raw = item.get("ssl_port")
    if ssl_port_raw is not None:
        if not isinstance(ssl_port_raw, int) or isinstance(ssl_port_raw, bool):
            raise ConfigError(f"{where}: ssl_port must be an integer")
        if not 1 <= ssl_port_raw <= 65535:
            raise ConfigError(f"{where}: ssl_port must be between 1 and 65535")
        if not ssl_enabled:
            raise ConfigError(f"{where}: ssl_port is only valid when ssl is enabled")
        if port_was_explicit and ssl_port_raw != explicit_port:
            raise ConfigError(
                f"{where}: ssl_port {ssl_port_raw} conflicts with the port in domain"
            )
        port = ssl_port_raw
    elif port_was_explicit:
        if not ssl_enabled:
            raise ConfigError(f"{where}: a port is only valid when ssl is enabled")
        port = explicit_port
    else:
        port = default_port

    if not _valid_host(host):
        raise ConfigError(f"{where}: invalid host {host!r}")
    if registration and _is_ip(host):
        raise ConfigError(f"{where}: registration checks require a domain, not an IP")

    tags = tuple(str(tag).strip() for tag in item.get("tags", []))
    if any(not tag for tag in tags):
        raise ConfigError(f"{where}: tags cannot be empty")

    group = _optional_text(item.get("group"), where, "group")
    owner = _optional_text(item.get("owner"), where, "owner")
    notes = _optional_text(item.get("notes"), where, "notes")

    tls_mode = str(item.get("tls_mode", "direct")).strip().lower()
    if tls_mode not in TLS_MODES:
        raise ConfigError(f"{where}: tls_mode must be one of {', '.join(TLS_MODES)}")
    if not ssl_enabled and tls_mode != "direct":
        raise ConfigError(f"{where}: tls_mode is only valid when ssl is enabled")

    starttls_raw = item.get("starttls_protocol")
    starttls_protocol: str | None
    if starttls_raw is not None:
        starttls_protocol = str(starttls_raw).strip().lower()
        if starttls_protocol not in STARTTLS_PROTOCOLS:
            raise ConfigError(
                f"{where}: starttls_protocol must be one of "
                f"{', '.join(STARTTLS_PROTOCOLS)}"
            )
        if tls_mode != "starttls":
            raise ConfigError(
                f"{where}: starttls_protocol is only valid when tls_mode = 'starttls'"
            )
    elif tls_mode == "starttls":
        starttls_protocol = "smtp"
    else:
        starttls_protocol = None

    https_raw = item.get("https")
    if https_raw is not None and not isinstance(https_raw, bool):
        raise ConfigError(f"{where}: https must be a boolean")
    if https_raw is True and tls_mode != "direct":
        raise ConfigError(f"{where}: https cannot be combined with STARTTLS")

    dns_name_raw = item.get("dns_name")
    dns_name: str | None = None
    if dns_name_raw is not None:
        dns_name = _normalise_dns_name(str(dns_name_raw))
        if dns_name is None:
            raise ConfigError(
                f"{where}: dns_name must be a domain name without a port or IP"
            )

    check_dns = bool(item.get("check_dns", default_check_dns))
    check_hsts = bool(item.get("check_hsts", default_check_hsts))
    check_legacy_tls = bool(item.get("check_legacy_tls", default_check_legacy_tls))

    return Target(
        host=host,
        port=port,
        ssl=ssl_enabled,
        registration=registration,
        tags=tags,
        group=group,
        owner=owner,
        notes=notes,
        tls_mode=tls_mode,
        starttls_protocol=starttls_protocol,
        https=https_raw,
        dns_name=dns_name,
        check_dns=check_dns,
        check_hsts=check_hsts,
        check_legacy_tls=check_legacy_tls,
    )


def _optional_text(value: Any, where: str, field: str) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        raise ConfigError(f"{where}: {field} cannot be empty")
    return text


# ── Legacy compatibility ─────────────────────────────────────────────────────


def load_legacy_config(
    ssl_path: str | Path | None = None,
    domain_path: str | Path | None = None,
) -> Config:
    """Read the old plain-text files when no TOML configuration exists."""
    ssl_file = Path(ssl_path or LEGACY_SSL_FILE)
    domain_file = Path(domain_path or LEGACY_DOMAIN_FILE)
    if not ssl_file.exists() and not domain_file.exists():
        raise ConfigError(
            f"no configuration found: create {CONFIG_FILE} or a legacy "
            f"{LEGACY_SSL_FILE}/{LEGACY_DOMAIN_FILE}"
        )

    targets: list[Target] = []
    registration_index: dict[str, int] = {}

    for endpoint in _legacy_endpoints(ssl_file):
        parsed = parse_endpoint(endpoint)
        if parsed is None:
            continue
        host, port = parsed
        target = Target(host=host, port=port, ssl=True, registration=False)
        targets.append(target)
        registration_index.setdefault(target.registration_domain, len(targets) - 1)

    for domain in _legacy_registration_domains(domain_file):
        if domain in registration_index:
            index = registration_index[domain]
            current = targets[index]
            if not current.registration:
                targets[index] = replace(current, registration=True)
            continue
        targets.append(
            Target(
                host=domain,
                port=DEFAULT_SSL_PORT,
                ssl=False,
                registration=True,
            )
        )
        registration_index[domain] = len(targets) - 1

    if not targets:
        raise ConfigError("legacy configuration contains no usable targets")

    return Config(
        version=SUPPORTED_VERSION,
        thresholds=DEFAULT_THRESHOLDS,
        ssl_port=DEFAULT_SSL_PORT,
        history_limit=DEFAULT_HISTORY_LIMIT,
        targets=tuple(targets),
        alerts=Alerts(discord=False),
        source="legacy",
        path=None,
    )


def _legacy_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read configuration: {exc}") from exc
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        token = stripped.split()[0]
        if token.lower() == "website":
            continue
        lines.append(token)
    return lines


def _legacy_endpoints(path: Path) -> list[str]:
    seen: set[tuple[str, int]] = set()
    endpoints: list[str] = []
    for raw in _legacy_lines(path):
        parsed = parse_endpoint(raw)
        if parsed is None:
            continue
        host, port = parsed
        if "_" in host:
            continue
        if parsed in seen:
            continue
        seen.add(parsed)
        endpoints.append(format_endpoint(host, port))
    return endpoints


def _legacy_registration_domains(path: Path) -> list[str]:
    """Mirror the old domains.conf normaliser, without the stricter TOML rules."""
    seen: set[str] = set()
    domains: list[str] = []
    for raw in _legacy_lines(path):
        parsed = parse_endpoint(raw)
        if parsed is None:
            continue
        domain = _registration_domain(parsed[0])
        if not domain:
            continue
        if "_" in domain and not domain.startswith("_"):
            continue
        if domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)
    return domains
