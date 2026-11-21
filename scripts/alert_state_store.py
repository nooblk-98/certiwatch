#!/usr/bin/env python3
"""Move the private CertiWatch alert state to a dedicated Cloudflare KV key.

The alert state contains last-seen status, threshold bands and certificate
fingerprints plus pending events. It is not public data: never put it in the
repository, a Pages bundle, an Actions cache or an artifact. This command is
the only supported transport for it.

``KvCheckpoint`` is the in-process interface used by ``src/monitor_state.py``:
it writes the pending batch before a Discord call and clears it only after an
acknowledged delivery. Cloudflare KV limits writes to the same key to one per
second, so writes are paced at that interval. HTTP 429 responses honour
``Retry-After`` (bounded by a maximum delay) and retry a limited number of
times; exhaustion is a checkpoint failure and stops the next Discord batch.
The CLI ``pull``/``push`` commands use the same key and format for inspection
and recovery.

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
import datetime
import email.utils
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

API_BASE = "https://api.cloudflare.com/client/v4"
TOKEN_ENV = "CERTIWATCH_STATE_KV_TOKEN"
NAMESPACE_ENV = "CERTIWATCH_STATE_KV_NAMESPACE"
ACCOUNT_ENV = "CLOUDFLARE_ACCOUNT_ID"
DEFAULT_KEY = "certiwatch-alert-state"
DEFAULT_OUT = ".certiwatch/alert_state.json"
MAX_STATE_BYTES = 2 * 1024 * 1024

# Official Cloudflare KV limit: writes to the same key are limited to one per
# second. Keep a full second between checkpoint PUTs to avoid self-inflicted 429s.
KV_SAME_KEY_WRITE_INTERVAL_SECONDS = 1.0
KV_MAX_WRITE_ATTEMPTS = 3
KV_MAX_RETRY_DELAY_SECONDS = 30.0

IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
KEY = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class StoreError(ValueError):
    """A configuration, local-file or Cloudflare KV failure.

    Subclasses ``ValueError`` so callers that guard state failures as
    configuration errors catch this without importing the adapter.
    """


class RateLimitedStoreError(StoreError):
    """A 429 response carrying an optional Retry-After delay."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.timezone.utc)
        return max(
            0.0,
            (when - datetime.datetime.now(datetime.timezone.utc)).total_seconds(),
        )


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
        headers = getattr(exc, "headers", None)
        retry_header = headers.get("Retry-After") if headers is not None else None
        try:
            code = int(exc.code)
        finally:
            try:
                exc.close()
            except OSError:
                pass
        if code == 404 and method == "GET":
            return None
        if code == 429:
            raise RateLimitedStoreError(
                "Cloudflare KV rate limited the request",
                _retry_after_seconds(retry_header),
            ) from None
        raise StoreError(f"Cloudflare KV returned HTTP {code}") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise StoreError("Cloudflare KV request failed") from None


def _request_with_retry(
    method: str,
    url: str,
    token: str,
    *,
    body: bytes | None = None,
    timeout: float = 15.0,
    max_attempts: int = KV_MAX_WRITE_ATTEMPTS,
    base_delay: float = 1.0,
    max_delay: float = KV_MAX_RETRY_DELAY_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> bytes | None:
    """Retry only 429 responses; other failures remain immediate."""
    for attempt in range(1, max_attempts + 1):
        try:
            return _request(method, url, token, body=body, timeout=timeout)
        except RateLimitedStoreError as exc:
            if attempt >= max_attempts:
                raise StoreError(
                    f"Cloudflare KV remained rate-limited after {attempt} attempts"
                ) from None
            delay = exc.retry_after
            if delay is None:
                delay = base_delay * (2 ** (attempt - 1))
            sleep(min(max_delay, max(0.0, delay)))
    raise StoreError("Cloudflare KV request failed")  # pragma: no cover


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
        min_write_interval: float = KV_SAME_KEY_WRITE_INTERVAL_SECONDS,
        max_attempts: int = KV_MAX_WRITE_ATTEMPTS,
        base_delay: float = 1.0,
        max_delay: float = KV_MAX_RETRY_DELAY_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._account = _identifier(account, ACCOUNT_ENV)
        self._namespace = _identifier(namespace, NAMESPACE_ENV)
        self._key = _key(key)
        self._token = (token or "").strip()
        self._timeout = timeout
        self._min_write_interval = float(min_write_interval)
        self._max_attempts = int(max_attempts)
        self._base_delay = float(base_delay)
        self._max_delay = float(max_delay)
        self._sleep = sleep
        self._clock = clock
        self._last_write: float | None = None
        if not self._token:
            raise StoreError(f"{TOKEN_ENV} is not set")
        if any(character.isspace() for character in self._token):
            raise StoreError(f"{TOKEN_ENV} is malformed")
        if self._timeout <= 0:
            raise StoreError("--timeout must be positive")
        if self._min_write_interval < 0:
            raise StoreError("KV write interval cannot be negative")
        if self._max_attempts < 1:
            raise StoreError("KV write attempts must be at least 1")
        if self._base_delay < 0 or self._max_delay < 0:
            raise StoreError("KV retry delays cannot be negative")

    @classmethod
    def from_env(cls, *, timeout: float = 15.0) -> "KvCheckpoint":
        return cls(
            account=_identifier(os.getenv(ACCOUNT_ENV), ACCOUNT_ENV),
            namespace=_identifier(os.getenv(NAMESPACE_ENV), NAMESPACE_ENV),
            key=DEFAULT_KEY,
            token=os.getenv(TOKEN_ENV, "").strip(),
            timeout=timeout,
        )

    def _pace(self) -> None:
        if self._last_write is None:
            return
        remaining = self._min_write_interval - (self._clock() - self._last_write)
        if remaining > 0:
            self._sleep(remaining)

    def save(self, payload: dict) -> None:
        """Write one checkpoint, paced and retried within fixed bounds.

        The KV same-key limit is one write per second. Pacing happens before
        every attempt, including retries. A 429 honours Retry-After but never
        waits longer than ``max_delay``; after ``max_attempts`` the checkpoint
        fails and the caller must stop before the next Discord batch.
        """
        body = _encode_state(payload)
        for attempt in range(1, self._max_attempts + 1):
            self._pace()
            self._last_write = self._clock()
            try:
                _request(
                    "PUT",
                    _url(self._account, self._namespace, self._key),
                    self._token,
                    body=body,
                    timeout=self._timeout,
                )
                return
            except RateLimitedStoreError as exc:
                if attempt >= self._max_attempts:
                    raise StoreError(
                        "Cloudflare KV remained rate-limited after "
                        f"{attempt} checkpoint attempt(s)"
                    ) from None
                delay = exc.retry_after
                if delay is None:
                    delay = self._base_delay * (2 ** (attempt - 1))
                self._sleep(min(self._max_delay, max(0.0, delay)))


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
    raw = _request_with_retry(
        "GET", _url(account, namespace, key), token, timeout=timeout
    )
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
    _request_with_retry(
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
