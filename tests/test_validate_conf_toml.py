"""The existing validator checks TOML first when it is present."""

from __future__ import annotations

import sys

import validate_conf as vc


def run(monkeypatch, *args: str) -> int:
    monkeypatch.setattr(sys, "argv", ["validate_conf.py", *args])
    return vc.main()


def test_valid_toml_is_validated_without_touching_legacy_files(tmp_path, monkeypatch):
    toml = tmp_path / "certiwatch.toml"
    toml.write_text(
        "version = 1\n[[targets]]\ndomain = 'example.com'\n", encoding="utf-8"
    )
    legacy = tmp_path / "ssl.conf"
    legacy.write_text("EXAMPLE.com\n", encoding="utf-8")

    assert run(monkeypatch, "--config", str(toml), "--no-dns") == 0
    assert legacy.read_text(encoding="utf-8") == "EXAMPLE.com\n"


def test_invalid_toml_fails_before_legacy_cleanup(tmp_path, monkeypatch):
    toml = tmp_path / "certiwatch.toml"
    toml.write_text("version = 1\n[[targets]]\ndomain = 'bad host'\n", encoding="utf-8")
    legacy = tmp_path / "ssl.conf"
    legacy.write_text("EXAMPLE.com\n", encoding="utf-8")

    assert run(monkeypatch, "--config", str(toml), "--legacy", "--no-dns") == 1
    assert legacy.read_text(encoding="utf-8") == "EXAMPLE.com\n"
