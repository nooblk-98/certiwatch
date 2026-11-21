#!/usr/bin/env python3
"""Helpers for reading .lk domain expiration dates from register.domains.lk.

The public endpoint rate-limits aggressively, so requests are spaced by an
adaptive limiter instead of one hard-coded sleep:

- normal spacing starts at LK_CHECK_DELAY_SEC (default 0.8 s),
- a 429/503 response doubles the spacing (honouring Retry-After) up to
  LK_CHECK_MAX_DELAY_SEC (default 5 s),
- each successful response walks the spacing back towards the normal value.

The limiter is shared by every worker thread, so the configured spacing is a
global request rate rather than a per-thread one.
"""

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

BASE_URL = "https://register.domains.lk"
SEARCH_URL = f"{BASE_URL}/domains-search"
API_URL = f"{BASE_URL}/proxy/domains/single-search"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Referer": SEARCH_URL,
    "Accept": "application/json, text/plain, */*",
}

REQUEST_DELAY_SECONDS = float(os.getenv("LK_CHECK_DELAY_SEC", "0.8"))
MAX_DELAY_SECONDS = float(os.getenv("LK_CHECK_MAX_DELAY_SEC", "5.0"))
MAX_RETRIES = int(os.getenv("LK_CHECK_MAX_RETRIES", "3"))
SUCCESS_DECAY = 0.9


class AdaptiveRateLimiter:
    """Thread-safe spacing with additive back-off and gradual recovery."""

    def __init__(
        self,
        initial: float,
        maximum: float,
        *,
        success_decay: float = SUCCESS_DECAY,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._minimum = max(0.0, initial)
        self._delay = self._minimum
        self._maximum = max(self._minimum, maximum)
        self._success_decay = min(1.0, max(0.0, success_decay))
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._last = clock() - self._minimum

    @property
    def current_delay(self) -> float:
        with self._lock:
            return self._delay

    def wait(self) -> None:
        """Block until the next request is allowed."""
        if self._minimum <= 0 and self._delay <= 0:
            return
        with self._lock:
            elapsed = self._clock() - self._last
            remaining = self._delay - elapsed
            if remaining > 0:
                self._sleep(remaining)
            self._last = self._clock()

    def note_success(self) -> None:
        with self._lock:
            self._delay = max(self._minimum, self._delay * self._success_decay)

    def note_throttled(self, retry_after: float | None = None) -> None:
        with self._lock:
            wanted = max(self._delay * 2, retry_after or 0.0)
            self._delay = min(self._maximum, max(self._minimum, wanted))


_LIMITER = AdaptiveRateLimiter(REQUEST_DELAY_SECONDS, MAX_DELAY_SECONDS)


def _throttle_request() -> None:
    """Throttle outbound LK API calls across worker threads/process imports."""
    _LIMITER.wait()


def _normalize_lk_domain(domain: str) -> str:
    value = domain.strip().lower()
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    value = value.split("/")[0].strip(" .")
    if value.startswith("www."):
        value = value[4:]
    return value


def _retry_delay(attempt: int) -> float:
    return min(2 ** attempt, 8)


def get_expiry_date(domain: str, verbose: bool = False) -> str:
    """
    Query register.domains.lk and return expiry date as YYYY-MM-DD when available.
    Returns human-readable status text when expiry cannot be determined.
    """
    lookup_domain = _normalize_lk_domain(domain)
    if not lookup_domain:
        return "[ERROR] Invalid domain"

    if verbose:
        print(f"[*] Connecting to {BASE_URL} ...")
        print(f"[*] Searching for: {lookup_domain}")

    query = urllib.parse.urlencode({"keyword": lookup_domain})
    url = f"{API_URL}?{query}"
    req = urllib.request.Request(url, headers=HEADERS, method="GET")

    payload = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            _throttle_request()
            with urllib.request.urlopen(req, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8"))
            _LIMITER.note_success()
            break
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 503) and attempt < MAX_RETRIES:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                try:
                    wait_seconds = float(retry_after) if retry_after else _retry_delay(attempt)
                except ValueError:
                    wait_seconds = _retry_delay(attempt)
                # The limiter enforces the new spacing before the next attempt.
                _LIMITER.note_throttled(max(wait_seconds, REQUEST_DELAY_SECONDS))
                continue
            return f"[ERROR] LK API HTTP error: {exc.code}"
        except urllib.error.URLError as exc:
            if attempt < MAX_RETRIES:
                time.sleep(_retry_delay(attempt))
                continue
            return f"[ERROR] LK API connection error: {exc.reason}"
        except (ValueError, json.JSONDecodeError):
            return "[ERROR] LK API returned invalid JSON"

    if payload is None:
        return "[ERROR] LK API request failed after retries"

    availability = {}
    if isinstance(payload, dict):
        availability = payload.get("result", {}).get("domainAvailability", {}) or {}

    if not availability:
        return "[INFO] Domain information not available from LK API."

    if availability.get("isAvailable") is True:
        return "[INFO] Domain is NOT registered (available for registration)."

    domain_info = availability.get("domainInfo") or {}
    expiry = domain_info.get("expireDate")
    if isinstance(expiry, str) and expiry.strip():
        return expiry.strip()

    message = availability.get("message", "")
    if isinstance(message, str) and message.strip():
        return f"[INFO] {message.strip()}"

    return "[INFO] Domain is registered, but expiry date is not exposed by API."
