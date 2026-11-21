#!/usr/bin/env python3
"""Defensive DNS diagnostics for configured CertiWatch targets.

The module answers three separate questions and never conflates them:

* Is data present? ``status: "present"``.
* Was the absence an authoritative/served answer? ``status: "absent"``.
* Did the lookup fail (timeout, SERVFAIL, no resolver)? ``status: "unknown"``.

DNSSEC has one more distinction: ``status: "present"`` means DNSKEY material
was returned but this machine's resolver did not set the AD bit, while
``status: "validated"`` means the resolver returned the data with AD set.
We never call data "validated" merely because RRSIG/DNSKEY records exist.

The production path uses dnspython and the operating system resolver. Tests
inject a resolver object, so no test performs DNS traffic. If dnspython is not
installed, every record is reported as ``unknown`` with a clear error rather
than silently reporting absence.
"""

from __future__ import annotations

import re
from typing import Any, Protocol

try:  # declared runtime dependency; tests use a fake resolver instead.
    import dns.flags  # noqa: F401
    import dns.resolver  # noqa: F401
except ImportError:  # pragma: no cover - only a broken install reaches this
    dns = None  # type: ignore[assignment]

STATUS_PRESENT = "present"
STATUS_ABSENT = "absent"
STATUS_UNKNOWN = "unknown"
STATUS_VALIDATED = "validated"

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

DNS_LIMITS = (
    "Records are what this machine's resolver returned for the configured "
    "dns_name. NS/CAA absence means NOERROR/NODATA or NXDOMAIN, not an "
    "unqueried name. DNSSEC is 'validated' only when the resolver sets the AD "
    "bit; 'present' means DNSKEY data was returned without local validation. "
    "CAA is queried at this name; a policy at an ancestor can still apply, and "
    "CAA is not a certificate-issuance guarantee by itself."
)


class ResolverLike(Protocol):
    def resolve(self, name: str, rdtype: str, **kwargs: Any) -> Any: ...


def _normalise_name(name: str) -> str | None:
    text = (name or "").strip().lower().rstrip(".")
    labels = text.split(".")
    if len(labels) < 2 or len(labels[-1]) < 2:
        return None
    if any(not _LABEL_RE.match(label) for label in labels):
        return None
    return text


def _error_text(exc: BaseException) -> str:
    text = " ".join(str(exc).split())
    return text[:240] if text else type(exc).__name__


def _classify_exception(exc: BaseException) -> tuple[str, str]:
    """Map resolver failures to absence vs unknown.

    NXDOMAIN and NODATA are answers: the name or type is absent. Timeouts,
    SERVFAIL and REFUSED are not evidence of absence, so they stay unknown.
    """
    name = type(exc).__name__.lower()
    if "nxdomain" in name:
        return STATUS_ABSENT, _error_text(exc) or "NXDOMAIN"
    if "noanswer" in name or "nodata" in name:
        return STATUS_ABSENT, _error_text(exc) or "NODATA"
    return STATUS_UNKNOWN, _error_text(exc)


def _record_text(record: Any) -> str:
    if isinstance(record, str):
        return record.strip()
    to_text = getattr(record, "to_text", None)
    if callable(to_text):
        try:
            return str(to_text()).strip()
        except Exception:
            pass
    return str(record).strip()


def _answer_records(answer: Any) -> list[Any]:
    rrset = getattr(answer, "rrset", None)
    if rrset is None:
        return []
    try:
        return [record for record in rrset]
    except TypeError:
        return [rrset]


def _caa_record(record: Any) -> dict[str, Any] | None:
    flags = getattr(record, "flags", None)
    tag = getattr(record, "tag", None)
    value = getattr(record, "value", None)
    if flags is not None and tag is not None and value is not None:
        return {"flags": int(flags), "tag": str(tag), "value": str(value)}
    text = _record_text(record)
    parts = text.split(None, 2)
    if len(parts) != 3:
        return None
    try:
        flags_int = int(parts[0])
    except ValueError:
        return None
    return {"flags": flags_int, "tag": parts[1], "value": parts[2]}


def _validated(answer: Any) -> bool:
    response = getattr(answer, "response", None)
    flags = getattr(response, "flags", 0)
    if isinstance(flags, int):
        return bool(flags & 0x20)  # DNS header AD bit
    return bool(getattr(answer, "validated", False) or getattr(response, "ad", False))


def _signature_count(answer: Any) -> int:
    response = getattr(answer, "response", None)
    rrsets = getattr(response, "answer", None)
    if not rrsets:
        return 0
    count = 0
    for rrset in rrsets:
        rdtype = getattr(rrset, "rdtype", None)
        if rdtype == 46 or getattr(rdtype, "name", "") == "RRSIG":
            count += 1
    return count


def _resolve(
    resolver: ResolverLike,
    name: str,
    rdtype: str,
    *,
    timeout: float = 5.0,
) -> tuple[Any | None, str | None, str | None]:
    kwargs: dict[str, Any] = {
        "raise_on_no_answer": False,
        "lifetime": timeout,
    }
    try:
        return resolver.resolve(name, rdtype, **kwargs), None, None
    except Exception as exc:  # resolver exceptions are data, not crashes
        status, error = _classify_exception(exc)
        return None, status, error


def _unknown_result(error: str) -> dict[str, Any]:
    return {"status": STATUS_UNKNOWN, "records": [], "error": error}


def _unavailable(name: str, error: str) -> dict[str, Any]:
    dnssec = _unknown_result(error)
    dnssec["validated"] = False
    dnssec["signature_count"] = 0
    dnssec["limits"] = DNS_LIMITS
    return {
        "checked": False,
        "name": name,
        "ns": _unknown_result(error),
        "caa": _unknown_result(error),
        "dnssec": dnssec,
        "error": error,
    }


def _system_resolver(timeout: float) -> ResolverLike:
    if dns is None:
        raise RuntimeError("dnspython is not installed")
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    resolver.timeout = timeout
    # Ask for DNSSEC material with the DO bit. The AD bit still comes from the
    # resolver itself; requesting RRSIG/DNSKEY data is not validation.
    try:
        resolver.use_edns(edns=True, ednsflags=dns.flags.DO)
    except (AttributeError, TypeError):
        pass
    return resolver


def query_ns(resolver: ResolverLike, name: str, *, timeout: float = 5.0) -> dict[str, Any]:
    answer, failure, error = _resolve(resolver, name, "NS", timeout=timeout)
    if failure is not None:
        return {"status": failure, "records": [], "error": error}
    records = sorted({_record_text(record) for record in _answer_records(answer) if _record_text(record)})
    if not records:
        return {"status": STATUS_ABSENT, "records": [], "error": None}
    return {"status": STATUS_PRESENT, "records": records, "error": None}


def query_caa(resolver: ResolverLike, name: str, *, timeout: float = 5.0) -> dict[str, Any]:
    answer, failure, error = _resolve(resolver, name, "CAA", timeout=timeout)
    if failure is not None:
        return {"status": failure, "records": [], "error": error}
    records: list[dict[str, Any]] = []
    for record in _answer_records(answer):
        parsed = _caa_record(record)
        if parsed is not None:
            records.append(parsed)
    records.sort(key=lambda row: (row["tag"], row["value"], row["flags"]))
    if not records:
        return {"status": STATUS_ABSENT, "records": [], "error": None}
    return {"status": STATUS_PRESENT, "records": records, "error": None}


def query_dnssec(resolver: ResolverLike, name: str, *, timeout: float = 5.0) -> dict[str, Any]:
    answer, failure, error = _resolve(resolver, name, "DNSKEY", timeout=timeout)
    if failure is not None:
        return {
            "status": failure,
            "validated": False,
            "records": [],
            "signature_count": 0,
            "error": error,
            "limits": DNS_LIMITS,
        }
    records = [
        text
        for record in _answer_records(answer)
        if (text := _record_text(record))
    ]
    if not records:
        return {
            "status": STATUS_ABSENT,
            "validated": False,
            "records": [],
            "signature_count": _signature_count(answer),
            "error": None,
            "limits": DNS_LIMITS,
        }
    validated = _validated(answer)
    return {
        "status": STATUS_VALIDATED if validated else STATUS_PRESENT,
        "validated": validated,
        "records": records,
        "signature_count": _signature_count(answer),
        "error": None,
        "limits": DNS_LIMITS,
    }


def diagnose_dns(
    name: str,
    *,
    resolver: ResolverLike | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Return NS, CAA and DNSSEC diagnostics for ``name``.

    Never raises for DNS failures. ``checked`` is false only when no lookup was
    possible (invalid name or no resolver), in which case all statuses are
    ``unknown``.
    """
    normalised = _normalise_name(name)
    if normalised is None:
        return _unavailable((name or "").strip(), "invalid DNS name")

    if resolver is None:
        try:
            resolver = _system_resolver(timeout)
        except Exception as exc:
            return _unavailable(normalised, _error_text(exc))

    result = {
        "checked": True,
        "name": normalised,
        "ns": query_ns(resolver, normalised, timeout=timeout),
        "caa": query_caa(resolver, normalised, timeout=timeout),
        "dnssec": query_dnssec(resolver, normalised, timeout=timeout),
        "limits": DNS_LIMITS,
        "error": None,
    }
    return result
