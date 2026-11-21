"""Tests for src/validate_conf.py and its agreement with the SSL checker."""

from __future__ import annotations

import pytest

import check_ssl as cs
import validate_conf as vc

ENDPOINT_CASES = [
    "example.com",
    "Example.COM.",
    "https://example.com/path",
    "https://example.com:8443/path",
    "example.com:25",
    "mail.example.com:993",
    "[::1]:8443",
    "example.com:0",
    "example.com:65536",
    "example.com:abc",
    "user@example.com",
    "bad host",
    "",
]


@pytest.mark.parametrize("raw", ENDPOINT_CASES)
def test_parse_endpoint_matches_ssl_checker(raw):
    assert vc.parse_endpoint(raw) == cs.parse_endpoint(raw)


@pytest.mark.parametrize("raw", ENDPOINT_CASES)
def test_canonical_form_matches_ssl_checker(raw):
    endpoint = vc.parse_endpoint(raw)
    if endpoint is None:
        return
    assert vc.normalise(raw, strip_www_prefix=False) == cs.format_endpoint(*endpoint)


def test_normalise_keeps_www_for_ssl_and_strips_it_for_domains():
    assert vc.normalise("https://WWW.Example.com:8443/path", strip_www_prefix=False) == (
        "www.example.com:8443"
    )
    assert vc.normalise("https://WWW.Example.com:8443/path", strip_www_prefix=True) == (
        "example.com:8443"
    )


@pytest.mark.parametrize(
    "value, valid",
    [
        ("example.com", True),
        ("mail.example.com:993", True),
        ("example.com:0", False),
        ("example.com:70000", False),
        ("bad_host.example", False),
        ("localhost", False),
        ("example..com", False),
        ("-bad.example.com", False),
    ],
)
def test_is_valid_accepts_host_and_port(value, valid):
    is_valid, _reason = vc.is_valid(value)
    assert is_valid is valid


def test_process_file_cleans_ssl_conf_and_preserves_www_and_ports(tmp_path):
    config = tmp_path / "ssl.conf"
    config.write_text(
        "\n".join(
            [
                "# monitored TLS endpoints",
                "Website",
                "www.Example.com",
                "https://WWW.Example.com:8443/path",
                "example.com",
                "example.com",
                "mail.Example.com:993",
                "bad_host",
                "example.com:99999",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert vc.process_file(config, check_dns=False, strip_www_prefix=False) is True
    assert config.read_text(encoding="utf-8").splitlines() == [
        "www.example.com",
        "www.example.com:8443",
        "example.com",
        "mail.example.com:993",
    ]

    # A second run must not rewrite an already clean file.
    before = config.read_text(encoding="utf-8")
    assert vc.process_file(config, check_dns=False, strip_www_prefix=False) is True
    assert config.read_text(encoding="utf-8") == before


def test_process_file_strips_www_from_domains_conf(tmp_path):
    config = tmp_path / "domains.conf"
    config.write_text("www.Example.com\nexample.com\n", encoding="utf-8")

    assert vc.process_file(config, check_dns=False, strip_www_prefix=True) is True
    assert config.read_text(encoding="utf-8") == "example.com\n"


def test_checker_reads_exactly_what_validator_wrote(tmp_path):
    config = tmp_path / "ssl.conf"
    config.write_text(
        "\n".join(
            [
                "Example.com",
                "example.com:443",
                "https://portal.example.org/login",
                "mail.example.com:993",
                "mail.example.com:993",
            ]
        ),
        encoding="utf-8",
    )

    assert vc.process_file(config, check_dns=False, strip_www_prefix=False) is True

    # The checker must see the validated file as already canonical.
    assert cs.load_domains(str(config)) == config.read_text(encoding="utf-8").splitlines()
