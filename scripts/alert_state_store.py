#!/usr/bin/env python3
"""Move the private CertiWatch alert state to a dedicated Cloudflare KV key.

The alert state contains last-seen status, threshold bands and certificate
fingerprints plus pending events. It is not public data: never put it in the
repository, a Pages bundle, an Actions cache or an artifact. This command is
the only supported transport for it.

``KvCheckpoint`` is the in-process interface used by ``src/monitor_state.py``:
it writes the pending batch before a Discord call and clears it only after an
acknowledged delivery. The CLI ``pull``/``push`` commands use the same key and
format for inspection and recovery.

Configuration comes from the environment so the token never appears in a
process listing, a log or a file:

    CERTIWATCH_STATE_KV_TOKEN       API token scoped to Workers KV edit
    CERTIWATCH_STATE_KV_NAMESPACE   namespace id
    CLOUDFLARE_ACCOUNT_ID           account id

Usage:
    python3 scripts/alert_state_store.py pull --out .certiwatch/alert_state.json
    python3 scripts/alert_state_store.py push --in .certiwatch/alert_state.json

``pull`` treats a missing key as a first run and removes any stale local copy.
``push`` uploads the exact validated JSON object. Neither command prints the
token, the state body or a Cloudflare response body.

Exit codes:
    0  state pulled/pushed, or no stored state yet
    1  missing configuration, invalid local state, or a failed request
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API_BASE = "https://api.cloudflare.com/client/v4"
TOKEN_ENV = "CERTIWATCH_STATE_KV_TOKEN"
NAMESPACE_ENV = "CERTIWATCH_STATE_KV_NAMESPACE"
ACCOUNT_ENV = "CLOUDFLARE_ACCOUNT_ID"
DEFAULT_KEY = "certiwatch-alert-state"
DEFAULT_OUT = ".certiwatch/alert_state.json"
MAX_STATE_BYTES = 2 * 1024 * 1024

IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
KEY = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class StoreError(ValueError):
    """A configuration, local-file or Cloudflare KV failure.

    Subclasses ``ValueError`` so callers that guard state failures as
    configuration errors catch this without importing the adapter.
    """


def _identifier(value: str | None, label: str) -> str:
    text = (value or "").strip()
    if not text:
        raise StoreError(f"{label} is not configured")
    if not IDENTIFIER.match(text):
        raise StoreError(f"{label} contains characters Cloudflare IDs cannot have")
    return text


def _key(value: str | None) -> str:
    text = (value or DEFAULT_KEY).strip()
    if not KEY.match(text):
        raise StoreError("KV key must match [A-Za-z0-9._-]{1,128}")
    return text


def _token() -> str:
    token = os.getenv(TOKEN_ENV, "").strip()
    if not token:
        raise StoreError(f"{TOKEN_ENV} is not set")
    if any(character.isspace() for character in token):
        raise StoreError(f"{TOKEN_ENV} is malformed")
    return token


def _url(account: str, namespace: str, key: str) -> str:
    return (
        f"{API_BASE}/accounts/{urllib.parse.quote(account, safe='')}/storage/kv/"
        f"namespaces/{urllib.parse.quote(namespace, safe='')}/values/"
        f"{urllib.parse.quote(key, safe='')}"
    )


def _request(
    method: str,
    url: str,
    token: str,
    *,
    body: bytes | None = None,
    timeout: float = 15.0,
) -> bytes | None:
    """Return the response body. Only a GET 404 means "absent".

    A PUT 404 is a failure: writing a checkpoint or pushing state and getting
    "not found" back must never be reported as success. Never leak the token or
    the state body.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "CertiWatch/1.0",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200))
            if not 200 <= status < 300:
                raise StoreError(f"Cloudflare KV returned HTTP {status}")
            return response.read()
    except urllib.error.HTTPError as exc:
        try:
            code = int(exc.code)
        finally:
            try:
                exc.close()
            except OSError:
                pass
        if code == 404 and method == "GET":
            return None
        raise StoreError(f"Cloudflare KV returned HTTP {code}") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise StoreError("Cloudflare KV request failed") from None


def _validate_state(raw: bytes) -> dict:
    if not raw or len(raw) > MAX_STATE_BYTES:
        raise StoreError("alert state is empty or too large")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StoreError(f"alert state is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise StoreError("alert state must be a JSON object")
    observations = payload.get("observations")
    pending = payload.get("pending_events")
    if not isinstance(observations, dict) or not isinstance(pending, list):
        raise StoreError("alert state is missing observations or pending_events")
    return payload


def _encode_state(payload: dict) -> bytes:
    """Validate and serialise one state object for a checkpoint write."""
    if not isinstance(payload, dict):
        raise StoreError("alert state must be a JSON object")
    body = json.dumps(payload, indent=2).encode("utf-8") + b"\n"
    _validate_state(body)
    return body


class KvCheckpoint:
    """Remote checkpoint for monitor_state, using the same scoped KV key."""

    def __init__(
        self,
        *,
        account: str,
        namespace: str,
        key: str,
        token: str,
        timeout: float = 15.0,
    ) -> None:
        self._account = _identifier(account, ACCOUNT_ENV)
        self._namespace = _identifier(namespace, NAMESPACE_ENV)
        self._key = _key(key)
        self._token = (token or "").strip()
        self._timeout = timeout
        if not self._token:
            raise StoreError(f"{TOKEN_ENV} is not set")
        if any(character.isspace() for character in self._token):
            raise StoreError(f"{TOKEN_ENV} is malformed")
        if self._timeout <= 0:
            raise StoreError("--timeout must be positive")

    @classmethod
    def from_env(cls, *, timeout: float = 15.0) -> "KvCheckpoint":
        return cls(
            account=_identifier(os.getenv(ACCOUNT_ENV), ACCOUNT_ENV),
            namespace=_identifier(os.getenv(NAMESPACE_ENV), NAMESPACE_ENV),
            key=DEFAULT_KEY,
            token=os.getenv(TOKEN_ENV, "").strip(),
            timeout=timeout,
        )

    def save(self, payload: dict) -> None:
        """Write one validated state object; raise StoreError on any failure."""
        _request(
            "PUT",
            _url(self._account, self._namespace, self._key),
            self._token,
            body=_encode_state(payload),
            timeout=self._timeout,
        )


def _write_atomic(path: Path, raw: bytes) -> None:
    if path.is_symlink():
        raise StoreError(f"refusing to write through a symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def pull(*, out: Path, account: str, namespace: str, key: str, token: str, timeout: float) -> int:
    raw = _request("GET", _url(account, namespace, key), token, timeout=timeout)
    if raw is None:
        out.unlink(missing_ok=True)
        print("state: no stored alert state; starting fresh")
        return 0
    payload = _validate_state(raw)
    _write_atomic(out, json.dumps(payload, indent=2).encode("utf-8") + b"\n")
    print(
        f"state: restored {len(payload['observations'])} observation(s), "
        f"{len(payload['pending_events'])} pending event(s)"
    )
    return 0


def push(
    *,
    source: Path,
    account: str,
    namespace: str,
    key: str,
    token: str,
    timeout: float,
) -> int:
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise StoreError(f"cannot read alert state: {exc}") from exc
    payload = _validate_state(raw)
    _request(
        "PUT",
        _url(account, namespace, key),
        token,
        body=_encode_state(payload),
        timeout=timeout,
    )
    print(
        f"state: stored {len(payload['observations'])} observation(s), "
        f"{len(payload['pending_events'])} pending event(s)"
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Move private CertiWatch alert state to a dedicated Cloudflare KV key."
    )
    parser.add_argument("command", choices=("pull", "push"))
    parser.add_argument("--account", default=os.getenv(ACCOUNT_ENV))
    parser.add_argument("--namespace", default=os.getenv(NAMESPACE_ENV))
    parser.add_argument("--key", default=DEFAULT_KEY)
    parser.add_argument("--out", default=DEFAULT_OUT, help="local path for pull")
    parser.add_argument("--in", dest="source", default=DEFAULT_OUT, help="local path for push")
    parser.add_argument("--timeout", type=float, default=15.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.timeout <= 0:
        print("error: --timeout must be positive", file=sys.stderr)
        return 1
    try:
        account = _identifier(args.account, ACCOUNT_ENV)
        namespace = _identifier(args.namespace, NAMESPACE_ENV)
        key = _key(args.key)
        token = _token()
        if args.command == "pull":
            return pull(
                out=Path(args.out),
                account=account,
                namespace=namespace,
                key=key,
                token=token,
                timeout=args.timeout,
            )
        return push(
            source=Path(args.source),
            account=account,
            namespace=namespace,
            key=key,
            token=token,
            timeout=args.timeout,
        )
    except StoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: local state file failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
