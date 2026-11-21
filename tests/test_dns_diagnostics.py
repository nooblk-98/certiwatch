"""Offline tests for NS / CAA / DNSSEC diagnostics.

No DNS traffic: every test injects a fake resolver. The production resolver is
created only when ``diagnose_dns`` is called without one.
"""

from __future__ import annotations

import dns_diagnostics as dd


class FakeRecord:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


class FakeCaa:
    def __init__(self, flags: int, tag: str, value: str) -> None:
        self.flags = flags
        self.tag = tag
        self.value = value


class FakeSignature(FakeRecord):
    rdtype = 46


class FakeResponse:
    def __init__(self, *, ad: bool = False, signatures: int = 0) -> None:
        self.flags = 0x20 if ad else 0
        self.answer = [FakeSignature(f"RRSIG-{index}") for index in range(signatures)]


class FakeAnswer:
    def __init__(self, records=(), *, ad: bool = False, signatures: int = 0) -> None:
        self._records = list(records)
        self.rrset = self._records or None
        self.response = FakeResponse(ad=ad, signatures=signatures)

    def __iter__(self):
        return iter(self._records)


class NXDOMAIN(Exception):
    pass


class NODATA(Exception):
    pass


class NoNameservers(Exception):
    pass


class LifetimeTimeout(Exception):
    pass


class FakeResolver:
    def __init__(self, mapping: dict[str, object]) -> None:
        self.mapping = mapping
        self.calls: list[tuple[str, str, dict]] = []

    def resolve(self, name: str, rdtype: str, **kwargs):
        self.calls.append((name, rdtype, kwargs))
        value = self.mapping.get(rdtype, FakeAnswer())
        if isinstance(value, Exception):
            raise value
        return value


def test_dns_records_present_and_dnssec_validated():
    resolver = FakeResolver(
        {
            "NS": FakeAnswer([FakeRecord("ns2.example."), FakeRecord("ns1.example.")]),
            "CAA": FakeAnswer([FakeCaa(0, "issue", "letsencrypt.org")]),
            "DNSKEY": FakeAnswer([FakeRecord("257 3 13 AAAA")], ad=True, signatures=1),
        }
    )

    result = dd.diagnose_dns("Example.COM.", resolver=resolver)

    assert result["name"] == "example.com"
    assert result["ns"] == {
        "status": "present",
        "records": ["ns1.example.", "ns2.example."],
        "error": None,
    }
    assert result["caa"]["status"] == "present"
    assert result["caa"]["records"] == [
        {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}
    ]
    assert result["dnssec"]["status"] == "validated"
    assert result["dnssec"]["validated"] is True
    assert result["dnssec"]["signature_count"] == 1
    assert result["dnssec"]["records"] == ["257 3 13 AAAA"]
    assert any(call[1] == "DNSKEY" for call in resolver.calls)


def test_absent_records_are_distinct_from_unknown():
    resolver = FakeResolver(
        {
            "NS": FakeAnswer(),
            "CAA": FakeAnswer(),
            "DNSKEY": FakeAnswer(),
        }
    )

    result = dd.diagnose_dns("example.com", resolver=resolver)

    assert result["ns"]["status"] == "absent"
    assert result["caa"]["status"] == "absent"
    assert result["dnssec"]["status"] == "absent"
    assert result["dnssec"]["validated"] is False


def test_lookup_failures_are_unknown_not_absent():
    resolver = FakeResolver(
        {
            "NS": LifetimeTimeout("timeout"),
            "CAA": NoNameservers("SERVFAIL"),
            "DNSKEY": NXDOMAIN("nxdomain"),
        }
    )

    result = dd.diagnose_dns("example.com", resolver=resolver)

    assert result["ns"]["status"] == "unknown"
    assert result["caa"]["status"] == "unknown"
    assert result["dnssec"]["status"] == "absent"
    assert "nxdomain" in result["dnssec"]["error"].lower()


def test_nodata_is_absent():
    resolver = FakeResolver(
        {
            "NS": NODATA("no answer"),
            "CAA": NODATA("no answer"),
            "DNSKEY": NODATA("no answer"),
        }
    )

    result = dd.diagnose_dns("example.com", resolver=resolver)

    assert result["ns"]["status"] == "absent"
    assert result["caa"]["status"] == "absent"
    assert result["dnssec"]["status"] == "absent"


def test_dnssec_data_present_but_not_validated_is_not_called_validated():
    resolver = FakeResolver(
        {
            "NS": FakeAnswer([FakeRecord("ns1.example.")]),
            "CAA": FakeAnswer(),
            "DNSKEY": FakeAnswer([FakeRecord("257 3 13 AAAA")], ad=False),
        }
    )

    result = dd.diagnose_dns("example.com", resolver=resolver)

    assert result["dnssec"]["status"] == "present"
    assert result["dnssec"]["validated"] is False
    assert "without local validation" in result["dnssec"]["limits"].lower()


def test_invalid_dns_name_returns_unknown_without_a_lookup():
    class ExplodingResolver:
        def resolve(self, *args, **kwargs):
            raise AssertionError("must not query an invalid name")

    result = dd.diagnose_dns("bad name", resolver=ExplodingResolver())

    assert result["checked"] is False
    assert result["ns"]["status"] == "unknown"
    assert result["caa"]["status"] == "unknown"
    assert result["dnssec"]["status"] == "unknown"
    assert "invalid" in result["error"].lower()
