"""Offline tests for the private Cloudflare KV alert-state adapter.

No network request is made: ``urlopen`` is replaced with a recorder.
"""

from __future__ import annotations

import json
import sys
import urllib.error
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

import alert_state_store as store  # noqa: E402

TOKEN = "very-secret-kv-token"
ACCOUNT = "0123456789abcdef0123456789abcdef"
NAMESPACE = "fedcba9876543210fedcba9876543210"
STATE = {
    "version": 1,
    "updated_at": "2026-11-21T00:35:00Z",
    "observations": {
        "ssl:example.com": {
            "kind": "ssl",
            "domain": "example.com",
            "status": "valid",
            "days_left": 24,
            "band": "notice",
            "fingerprint_sha256": "AA:BB",
        }
    },
    "pending_events": [{"id": "event-1", "type": "status"}],
}


class FakeResponse:
    def __init__(self, body: bytes = b"", status: int = 200) -> None:
        self._body = body
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return None


class Recorder:
    def __init__(self, response=None) -> None:
        self.response = response
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append(request)
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response or FakeResponse()


def configure(monkeypatch) -> None:
    monkeypatch.setenv(store.TOKEN_ENV, TOKEN)
    monkeypatch.setenv(store.NAMESPACE_ENV, NAMESPACE)
    monkeypatch.setenv(store.ACCOUNT_ENV, ACCOUNT)


def test_pull_writes_private_state(monkeypatch, tmp_path):
    configure(monkeypatch)
    recorder = Recorder(FakeResponse(json.dumps(STATE).encode("utf-8")))
    monkeypatch.setattr(store.urllib.request, "urlopen", recorder)
    out = tmp_path / "private" / "alert_state.json"

    code = store.main(["pull", "--out", str(out)])

    assert code == 0
    assert json.loads(out.read_text(encoding="utf-8"))["pending_events"] == STATE["pending_events"]
    request = recorder.requests[0]
    assert request.get_method() == "GET"
    assert request.full_url == (
        f"{store.API_BASE}/accounts/{ACCOUNT}/storage/kv/namespaces/"
        f"{NAMESPACE}/values/{store.DEFAULT_KEY}"
    )
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"


def test_pull_missing_key_removes_stale_local_copy(monkeypatch, tmp_path):
    configure(monkeypatch)
    out = tmp_path / "alert_state.json"
    out.write_text(json.dumps(STATE), encoding="utf-8")
    recorder = Recorder(
        urllib.error.HTTPError(
            f"{store.API_BASE}/x", 404, "not found", {}, None
        )
    )
    monkeypatch.setattr(store.urllib.request, "urlopen", recorder)

    code = store.main(["pull", "--out", str(out)])

    assert code == 0
    assert not out.exists()


def test_push_uploads_the_exact_state(monkeypatch, tmp_path):
    configure(monkeypatch)
    source = tmp_path / "alert_state.json"
    source.write_text(json.dumps(STATE), encoding="utf-8")
    recorder = Recorder(FakeResponse(b"", 200))
    monkeypatch.setattr(store.urllib.request, "urlopen", recorder)

    code = store.main(["push", "--in", str(source)])

    assert code == 0
    request = recorder.requests[0]
    assert request.get_method() == "PUT"
    assert json.loads(request.data)["observations"] == STATE["observations"]
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"


def test_missing_token_never_reaches_the_network(monkeypatch, tmp_path):
    monkeypatch.delenv(store.TOKEN_ENV, raising=False)
    monkeypatch.setenv(store.NAMESPACE_ENV, NAMESPACE)
    monkeypatch.setenv(store.ACCOUNT_ENV, ACCOUNT)
    recorder = Recorder()
    monkeypatch.setattr(store.urllib.request, "urlopen", recorder)

    assert store.main(["pull", "--out", str(tmp_path / "state.json")]) == 1
    assert recorder.requests == []


def test_invalid_namespace_and_key_are_rejected(monkeypatch, tmp_path):
    configure(monkeypatch)
    recorder = Recorder()
    monkeypatch.setattr(store.urllib.request, "urlopen", recorder)

    assert store.main(["pull", "--namespace", "../bad", "--out", str(tmp_path / "s")]) == 1
    assert store.main(["pull", "--key", "bad/key", "--out", str(tmp_path / "s")]) == 1
    assert recorder.requests == []


def test_http_failure_does_not_leak_token_or_state(monkeypatch, tmp_path, capsys):
    configure(monkeypatch)
    source = tmp_path / "alert_state.json"
    source.write_text(json.dumps(STATE), encoding="utf-8")
    recorder = Recorder(
        urllib.error.HTTPError(
            f"{store.API_BASE}/x", 403, "forbidden", {}, None
        )
    )
    monkeypatch.setattr(store.urllib.request, "urlopen", recorder)

    code = store.main(["push", "--in", str(source)])

    captured = capsys.readouterr()
    assert code == 1
    assert "HTTP 403" in captured.err
    assert TOKEN not in captured.err
    assert "example.com" not in captured.err


def test_invalid_state_is_not_uploaded(monkeypatch, tmp_path):
    configure(monkeypatch)
    source = tmp_path / "alert_state.json"
    source.write_text(json.dumps({"version": 1}), encoding="utf-8")
    recorder = Recorder()
    monkeypatch.setattr(store.urllib.request, "urlopen", recorder)

    assert store.main(["push", "--in", str(source)]) == 1
    assert recorder.requests == []


def test_kv_checkpoint_saves_the_pending_state(monkeypatch):
    configure(monkeypatch)
    recorder = Recorder(FakeResponse(b"", 200))
    monkeypatch.setattr(store.urllib.request, "urlopen", recorder)

    checkpoint = store.KvCheckpoint.from_env()
    checkpoint.save(STATE)

    request = recorder.requests[0]
    assert request.get_method() == "PUT"
    assert json.loads(request.data)["pending_events"] == STATE["pending_events"]
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"


def test_kv_checkpoint_requires_a_token(monkeypatch):
    monkeypatch.delenv(store.TOKEN_ENV, raising=False)
    monkeypatch.setenv(store.NAMESPACE_ENV, NAMESPACE)
    monkeypatch.setenv(store.ACCOUNT_ENV, ACCOUNT)
    with pytest.raises(store.StoreError, match=store.TOKEN_ENV):
        store.KvCheckpoint.from_env()


def test_symlinked_destination_is_refused(monkeypatch, tmp_path):
    configure(monkeypatch)
    real = tmp_path / "real.json"
    link = tmp_path / "state.json"
    link.symlink_to(real)
    recorder = Recorder(FakeResponse(json.dumps(STATE).encode("utf-8")))
    monkeypatch.setattr(store.urllib.request, "urlopen", recorder)

    assert store.main(["pull", "--out", str(link)]) == 1
    assert not real.exists()
