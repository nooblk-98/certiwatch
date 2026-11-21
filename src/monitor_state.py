#!/usr/bin/env python3
"""CertiWatch monitoring lifecycle: public history and private alert state.

Inputs
------
* ``ssl_results.json`` and ``domain_results.json`` from the two checkers.
* The previous public ``history.json`` (optional on the first run).
* The previous private alert state (optional on the first run).
* ``certiwatch.toml`` for thresholds, history cap and the Discord opt-in.

Outputs
-------
* ``history.json`` is public and follows this fixed contract::

      {"snapshots": [
        {"date": "YYYY-MM-DD",
         "ssl": [{"domain": ..., "days_left": ..., "status": ...,
                  "fingerprint_sha256": ...}],
         "domains": [{"domain": ..., "days_left": ..., "status": ...}]}
      ]}

  There is at most one snapshot per UTC date, and at most ``history_limit``
  snapshots. No tags, group, owner, notes or webhook data is written here.

* The alert state is private and never published. It holds the last observed
  status/band/fingerprint per stable key and any undelivered events. Keeping it
  separate is why public history can be handed to a browser without leaking
  private metadata or alert delivery state.

* Discord delivery is opt-in twice: ``[alerts] discord = true`` in the TOML
  file and ``--transport discord`` on this CLI. The webhook URL is read from
  ``CERTIWATCH_DISCORD_WEBHOOK`` and is never accepted as a command-line
  argument, written to state, or printed. Tests inject a fake transport.

Usage
-----
::

    python3 src/monitor_state.py \\
        --config certiwatch.toml \\
        --ssl-results ssl_results.json \\
        --domain-results domain_results.json \\
        --history history.json \\
        --alert-state .certiwatch/alert_state.json \\
        --transport none

Use ``--transport discord`` only after the Discord opt-in and secret are
configured, and always with ``--checkpoint kv`` (or ``local`` on a genuinely
persistent host): the pending event batch is written to the remote checkpoint
before the send. A checkpoint failure aborts with zero sends; the cleared state
is written only after an acknowledged delivery. A crash can therefore duplicate
an alert but never lose one. Pull-request and offline test runs use
``--transport none``; they make no network calls.

Exit codes: 0 written successfully (including disabled delivery with pending
events preserved); 1 configuration/input error or checkpoint failure; 2 history
and pending state were written, but Discord delivery failed (the same events
remain in the checkpoint for the next run).
"""

from __future__ import annotations

import argparse
import datetime
import email.utils
import hashlib
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from config import (
    Config,
    ConfigError,
    band_for_days,
    load_config,
)

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"

HISTORY_FILE = "history.json"
ALERT_STATE_FILE = ".certiwatch/alert_state.json"
DISCORD_ENV = "CERTIWATCH_DISCORD_WEBHOOK"
STATE_VERSION = 1
MAX_DISCORD_CONTENT = 2000
_EVENT_ORDER = {"status": 0, "threshold": 1, "fingerprint": 2, "nameservers": 3}


class MonitoringError(ValueError):
    """An input, state file or monitoring operation is invalid."""


class DeliveryError(RuntimeError):
    """Discord delivery failed after its retry budget."""


class TransportError(RuntimeError):
    """The transport itself failed; the message never contains the webhook URL."""

    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


@dataclass(frozen=True)
class TransportResponse:
    status: int
    retry_after: float | None = None


@dataclass(frozen=True)
class DeliveryResult:
    attempts: int
    status: int


@dataclass(frozen=True)
class MonitoringPlan:
    snapshot: dict[str, Any]
    history: dict[str, Any]
    alert_state: dict[str, Any]
    events: tuple[dict[str, Any], ...]


class Transport(Protocol):
    def send(self, payload: dict[str, Any]) -> TransportResponse: ...


class Checkpoint(Protocol):
    def save(self, state: dict[str, Any]) -> None: ...


class LocalCheckpoint:
    """A no-op checkpoint for local/self-hosted runs with durable disk state."""

    def save(self, state: dict[str, Any]) -> None:
        return None


def checkpoint_from_args(args: argparse.Namespace) -> Checkpoint | None:
    """Build the durable checkpoint selected by ``--checkpoint``.

    ``none`` is valid only with ``--transport none``. ``kv`` imports the small
    Cloudflare adapter from ``scripts/`` so CI and local runs share exactly one
    state format and one scoped key.
    """
    if args.checkpoint == "none":
        return None
    if args.checkpoint == "local":
        return LocalCheckpoint()
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))
    try:
        import alert_state_store
    except ImportError as exc:  # pragma: no cover - deployment mistake
        raise MonitoringError(f"KV checkpoint adapter is unavailable: {exc}") from exc
    try:
        return alert_state_store.KvCheckpoint.from_env(timeout=args.timeout)
    except alert_state_store.StoreError as exc:
        raise MonitoringError(str(exc)) from exc


# ── Discord transport ────────────────────────────────────────────────────────


class DiscordWebhookTransport:
    """Minimal Discord webhook transport with a redacted representation."""

    def __init__(self, webhook_url: str, *, timeout: float = 15.0) -> None:
        self._url = _validate_webhook_url(webhook_url)
        self._timeout = float(timeout)

    @classmethod
    def from_env(cls, *, timeout: float = 15.0) -> "DiscordWebhookTransport":
        url = os.getenv(DISCORD_ENV, "").strip()
        if not url:
            raise MonitoringError(
                f"{DISCORD_ENV} is not set; Discord delivery needs the webhook secret"
            )
        return cls(url, timeout=timeout)

    def __repr__(self) -> str:
        return "DiscordWebhookTransport(<redacted>)"

    __str__ = __repr__

    def send(self, payload: dict[str, Any]) -> TransportResponse:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            self._url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "CertiWatch/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                return TransportResponse(int(getattr(response, "status", 204)))
        except urllib.error.HTTPError as exc:
            retry_after = _retry_after_seconds(exc.headers.get("Retry-After"))
            # The URL stays in the HTTPError; do not let it escape in a message.
            try:
                exc.close()
            except OSError:
                pass
            return TransportResponse(int(exc.code), retry_after)
        except (urllib.error.URLError, TimeoutError, OSError):
            raise TransportError("Discord request failed", retryable=True) from None


def _validate_webhook_url(value: str) -> str:
    text = (value or "").strip()
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError as exc:
        raise MonitoringError("the Discord webhook URL is malformed") from exc
    host = (parts.hostname or "").lower()
    allowed_host = host == "discord.com" or host.endswith(".discord.com") or (
        host == "discordapp.com" or host.endswith(".discordapp.com")
    )
    if (
        parts.scheme != "https"
        or not allowed_host
        or not parts.path.startswith("/api/webhooks/")
    ):
        raise MonitoringError(f"{DISCORD_ENV} must be an https Discord webhook URL")
    return text


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.timezone.utc)
        seconds = (when - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    return max(0.0, seconds)


def _retry_delay(
    response: TransportResponse,
    attempt: int,
    *,
    base_delay: float,
    max_delay: float,
) -> float:
    if response.retry_after is not None:
        return min(max_delay, max(0.0, response.retry_after))
    return min(max_delay, base_delay * (2 ** (attempt - 1)))


def post_with_retry(
    transport: Transport,
    payload: dict[str, Any],
    *,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    sleep: Callable[[float], None] = time.sleep,
) -> DeliveryResult:
    """POST a payload, retrying 429/5xx and transient transport errors.

    ``sleep`` is injectable so tests can prove the exact delay sequence without
    waiting. A non-retryable response (for example 400 or 403) fails at once.
    Error messages never contain the webhook URL or payload.
    """
    if max_attempts < 1:
        raise MonitoringError("max_attempts must be at least 1")
    if base_delay < 0 or max_delay < 0:
        raise MonitoringError("retry delays cannot be negative")

    attempt = 0
    while attempt < max_attempts:
        attempt += 1
        try:
            response = transport.send(payload)
        except TransportError as exc:
            if not exc.retryable or attempt >= max_attempts:
                raise DeliveryError(
                    f"Discord delivery failed after {attempt} attempt(s): transport error"
                ) from None
            sleep(
                min(
                    max_delay,
                    base_delay * (2 ** (attempt - 1)),
                )
            )
            continue

        status = int(response.status)
        if 200 <= status < 300:
            return DeliveryResult(attempts=attempt, status=status)

        retryable = status == 429 or 500 <= status < 600
        if not retryable or attempt >= max_attempts:
            raise DeliveryError(
                f"Discord delivery failed with HTTP {status} after {attempt} attempt(s)"
            )
        sleep(
            _retry_delay(
                response,
                attempt,
                base_delay=base_delay,
                max_delay=max_delay,
            )
        )

    raise DeliveryError("Discord delivery failed")  # pragma: no cover


# ── Public history ───────────────────────────────────────────────────────────


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def parse_generated_date(value: Any) -> str | None:
    """Read the UTC date from a checker's ``generated_at`` value."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    for fmt in ("%Y-%m-%d %H:%M UTC", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(text, fmt).date().isoformat()
        except ValueError:
            continue
    try:
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return None


def snapshot_date_for(
    ssl_output: dict[str, Any],
    domain_output: dict[str, Any],
    override: str | None = None,
) -> str:
    """Choose the one UTC snapshot date, preferring an explicit override."""
    if override is not None:
        try:
            return datetime.date.fromisoformat(override).isoformat()
        except ValueError as exc:
            raise MonitoringError(f"--date must be YYYY-MM-DD: {override!r}") from exc
    for output in (ssl_output, domain_output):
        date = parse_generated_date(output.get("generated_at"))
        if date:
            return date
    return _utc_now().date().isoformat()


def _normalise_fingerprint(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().replace(" ", "").upper()
    return text or None


def _last_known_fingerprints(
    previous_history: dict[str, Any] | None,
    previous_alert_state: dict[str, Any] | None,
) -> dict[str, str]:
    known: dict[str, str] = {}
    if previous_history:
        snapshots = previous_history.get("snapshots") or []
        for snapshot in reversed(snapshots):
            for row in snapshot.get("ssl") or []:
                if not isinstance(row, dict):
                    continue
                domain = row.get("domain")
                fingerprint = _normalise_fingerprint(row.get("fingerprint_sha256"))
                if isinstance(domain, str) and fingerprint and f"ssl:{domain}" not in known:
                    known[f"ssl:{domain}"] = fingerprint
    if previous_alert_state:
        observations = previous_alert_state.get("observations") or {}
        for key, observation in observations.items():
            if not isinstance(observation, dict):
                continue
            fingerprint = _normalise_fingerprint(observation.get("fingerprint_sha256"))
            if fingerprint:
                known[key] = fingerprint
    return known


def build_snapshot(
    ssl_output: dict[str, Any],
    domain_output: dict[str, Any],
    *,
    previous_history: dict[str, Any] | None = None,
    previous_alert_state: dict[str, Any] | None = None,
    snapshot_date: str | None = None,
) -> dict[str, Any]:
    """Build one public snapshot with the exact history contract."""
    date = snapshot_date_for(ssl_output, domain_output, snapshot_date)
    known_fingerprints = _last_known_fingerprints(previous_history, previous_alert_state)

    ssl_rows: list[dict[str, Any]] = []
    for row in _result_rows(ssl_output, "ssl_results.json"):
        domain = row.get("domain")
        if not isinstance(domain, str) or not domain:
            raise MonitoringError("ssl_results.json contains a row without a domain")
        fingerprint = _normalise_fingerprint(row.get("fingerprint_sha256"))
        if fingerprint is None:
            fingerprint = known_fingerprints.get(f"ssl:{domain}")
        ssl_rows.append(
            {
                "domain": domain,
                "days_left": _optional_int(row.get("days_left"), "ssl_results.json"),
                "status": _status(row.get("status"), "ssl_results.json"),
                "fingerprint_sha256": fingerprint,
            }
        )

    domain_rows: list[dict[str, Any]] = []
    for row in _result_rows(domain_output, "domain_results.json"):
        domain = row.get("domain")
        if not isinstance(domain, str) or not domain:
            raise MonitoringError("domain_results.json contains a row without a domain")
        domain_rows.append(
            {
                "domain": domain,
                "days_left": _optional_int(row.get("days_left"), "domain_results.json"),
                "status": _status(row.get("status"), "domain_results.json"),
            }
        )

    ssl_rows.sort(key=lambda row: row["domain"])
    domain_rows.sort(key=lambda row: row["domain"])
    return {"date": date, "ssl": ssl_rows, "domains": domain_rows}


def _result_rows(output: dict[str, Any], label: str) -> list[dict[str, Any]]:
    if not isinstance(output, dict):
        raise MonitoringError(f"{label}: expected a JSON object")
    rows = output.get("results")
    if not isinstance(rows, list):
        raise MonitoringError(f"{label}: missing 'results' list")
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise MonitoringError(f"{label}: results[{index}] is not an object")
    return rows


def _optional_int(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise MonitoringError(f"{label}: days_left must be an integer or null")
    return value


def _status(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise MonitoringError(f"{label}: status must be a non-empty string")
    return value


def merge_history(
    previous_history: dict[str, Any] | None,
    snapshot: dict[str, Any],
    limit: int,
) -> dict[str, Any]:
    """Upsert by UTC date, sort ascending, and keep the newest ``limit``."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise MonitoringError("history_limit must be a positive integer")
    previous = _normalise_history(previous_history)

    by_date = {entry["date"]: entry for entry in previous["snapshots"]}
    by_date[snapshot["date"]] = snapshot
    dates = sorted(by_date)
    kept = dates[-limit:]
    return {"snapshots": [by_date[date] for date in kept]}


def _normalise_history(previous: dict[str, Any] | None) -> dict[str, Any]:
    if previous is None:
        return {"snapshots": []}
    if not isinstance(previous, dict) or not isinstance(previous.get("snapshots"), list):
        raise MonitoringError("previous history must be an object with a snapshots list")

    snapshots: list[dict[str, Any]] = []
    for index, snapshot in enumerate(previous["snapshots"]):
        if not isinstance(snapshot, dict):
            raise MonitoringError(f"previous history snapshots[{index}] is not an object")
        date = snapshot.get("date")
        if not isinstance(date, str):
            raise MonitoringError(f"previous history snapshots[{index}].date is missing")
        try:
            date = datetime.date.fromisoformat(date).isoformat()
        except ValueError as exc:
            raise MonitoringError(
                f"previous history snapshots[{index}].date is not YYYY-MM-DD"
            ) from exc
        if not isinstance(snapshot.get("ssl"), list) or not isinstance(
            snapshot.get("domains"), list
        ):
            raise MonitoringError(
                f"previous history snapshots[{index}] must contain ssl and domains lists"
            )
        snapshots.append(
            {
                "date": date,
                "ssl": _normalise_history_ssl(snapshot["ssl"], index),
                "domains": _normalise_history_domains(snapshot["domains"], index),
            }
        )
    snapshots.sort(key=lambda entry: entry["date"])
    return {"snapshots": snapshots}


def _normalise_history_ssl(rows: list[Any], snapshot_index: int) -> list[dict[str, Any]]:
    normalised: list[dict[str, Any]] = []
    for row_index, row in enumerate(rows):
        where = f"previous history snapshots[{snapshot_index}].ssl[{row_index}]"
        if not isinstance(row, dict):
            raise MonitoringError(f"{where} is not an object")
        domain = row.get("domain")
        status = row.get("status")
        if not isinstance(domain, str) or not domain:
            raise MonitoringError(f"{where}.domain is missing")
        if not isinstance(status, str) or not status:
            raise MonitoringError(f"{where}.status is missing")
        fingerprint = _normalise_fingerprint(row.get("fingerprint_sha256"))
        normalised.append(
            {
                "domain": domain,
                "days_left": _optional_int(row.get("days_left"), where),
                "status": status,
                "fingerprint_sha256": fingerprint,
            }
        )
    return normalised


def _normalise_history_domains(rows: list[Any], snapshot_index: int) -> list[dict[str, Any]]:
    normalised: list[dict[str, Any]] = []
    for row_index, row in enumerate(rows):
        where = f"previous history snapshots[{snapshot_index}].domains[{row_index}]"
        if not isinstance(row, dict):
            raise MonitoringError(f"{where} is not an object")
        domain = row.get("domain")
        status = row.get("status")
        if not isinstance(domain, str) or not domain:
            raise MonitoringError(f"{where}.domain is missing")
        if not isinstance(status, str) or not status:
            raise MonitoringError(f"{where}.status is missing")
        normalised.append(
            {
                "domain": domain,
                "days_left": _optional_int(row.get("days_left"), where),
                "status": status,
            }
        )
    return normalised


# ── Alert observations and events ────────────────────────────────────────────


def default_alert_state() -> dict[str, Any]:
    return {"version": STATE_VERSION, "observations": {}, "pending_events": []}


def _normalise_alert_state(previous: dict[str, Any] | None) -> dict[str, Any]:
    if previous is None:
        return default_alert_state()
    if not isinstance(previous, dict):
        raise MonitoringError("previous alert state must be a JSON object")
    observations = previous.get("observations", {})
    if not isinstance(observations, dict):
        raise MonitoringError("previous alert state observations must be an object")
    for key, value in observations.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            raise MonitoringError("previous alert state contains an invalid observation")
    pending = previous.get("pending_events", [])
    if not isinstance(pending, list):
        raise MonitoringError("previous alert state pending_events must be a list")
    for event in pending:
        if not isinstance(event, dict) or not isinstance(event.get("id"), str):
            raise MonitoringError("previous alert state contains an invalid pending event")
    return {
        "version": STATE_VERSION,
        "observations": dict(observations),
        "pending_events": list(pending),
    }


def _dns_observations(
    ssl_output: dict[str, Any],
    domain_output: dict[str, Any],
    previous: dict[str, Any],
) -> dict[str, Any]:
    """Collect nameserver observations from both result files.

    ``unknown`` is not an empty delegation: it keeps the last known nameservers
    so a timeout cannot masquerade as a nameserver change.
    """
    observations: dict[str, Any] = {}
    for output, label in (
        (ssl_output, "ssl_results.json"),
        (domain_output, "domain_results.json"),
    ):
        for row in _result_rows(output, label):
            dns = row.get("dns")
            if not isinstance(dns, dict):
                continue
            name = dns.get("name")
            if not isinstance(name, str) or not name:
                continue
            ns = dns.get("ns")
            ns = ns if isinstance(ns, dict) else {}
            status = ns.get("status")
            if status not in ("present", "absent"):
                status = "unknown"
            raw_records = ns.get("records")
            records = raw_records if isinstance(raw_records, list) else []
            current_records = sorted(
                {str(record).strip() for record in records if str(record).strip()}
            )
            key = f"dns:{name}"
            previous_observation = previous.get(key)
            previous_nameservers = (
                previous_observation.get("nameservers")
                if isinstance(previous_observation, dict)
                and isinstance(previous_observation.get("nameservers"), list)
                else []
            )
            lookup_status = status
            if status == "present":
                nameservers = current_records
            elif status == "absent":
                nameservers = []
            else:
                nameservers = list(previous_nameservers)
                # A failed lookup must not erase a known delegation or suppress
                # a later real change. Keep the last answered status.
                if isinstance(previous_observation, dict) and previous_observation.get(
                    "status"
                ) in ("present", "absent"):
                    status = previous_observation["status"]

            observation = {
                "kind": "dns",
                "domain": name,
                "status": status,
                "lookup_status": lookup_status,
                "nameservers": nameservers,
            }
            existing = observations.get(key)
            priority = {"unknown": 0, "absent": 1, "present": 2}
            if existing is None or priority[status] > priority.get(
                existing.get("status"), 0
            ):
                observations[key] = observation
    return observations


def _observations_from_snapshot(
    snapshot: dict[str, Any],
    thresholds: tuple[int, ...],
    *,
    ssl_output: dict[str, Any] | None = None,
    domain_output: dict[str, Any] | None = None,
    previous_observations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    observations: dict[str, Any] = {}
    for row in snapshot["ssl"]:
        key = f"ssl:{row['domain']}"
        observations[key] = {
            "kind": "ssl",
            "domain": row["domain"],
            "status": row["status"],
            "days_left": row["days_left"],
            "band": band_for_days(row["days_left"], thresholds),
            "fingerprint_sha256": row["fingerprint_sha256"],
        }
    for row in snapshot["domains"]:
        key = f"domain:{row['domain']}"
        observations[key] = {
            "kind": "domain",
            "domain": row["domain"],
            "status": row["status"],
            "days_left": row["days_left"],
            "band": band_for_days(row["days_left"], thresholds),
        }
    if ssl_output is not None and domain_output is not None:
        observations.update(
            _dns_observations(
                ssl_output,
                domain_output,
                previous_observations or {},
            )
        )
    return observations


def _make_event(
    *,
    key: str,
    kind: str,
    domain: str,
    event_type: str,
    before: Any,
    after: Any,
    days_left: int | None,
    date: str,
) -> dict[str, Any]:
    identity = f"{key}|{event_type}|{before}|{after}|{date}"
    return {
        "id": hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
        "key": key,
        "kind": kind,
        "domain": domain,
        "type": event_type,
        "from": before,
        "to": after,
        "days_left": days_left,
        "date": date,
    }


def _compare_observations(
    previous: dict[str, Any],
    current: dict[str, Any],
    *,
    date: str,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for key in sorted(current):
        observation = current[key]
        before = previous.get(key)
        if not isinstance(before, dict):
            continue  # first observation is the baseline, not an alert
        if observation.get("kind") == "dns":
            before_nameservers = before.get("nameservers")
            after_nameservers = observation.get("nameservers")
            if (
                before.get("status") in ("present", "absent")
                and observation.get("status") in ("present", "absent")
                and isinstance(before_nameservers, list)
                and isinstance(after_nameservers, list)
                and before_nameservers != after_nameservers
            ):
                events.append(
                    _make_event(
                        key=key,
                        kind="dns",
                        domain=observation["domain"],
                        event_type="nameservers",
                        before=before_nameservers,
                        after=after_nameservers,
                        days_left=None,
                        date=date,
                    )
                )
            continue
        status_changed = before.get("status") != observation["status"]
        if status_changed:
            events.append(
                _make_event(
                    key=key,
                    kind=observation["kind"],
                    domain=observation["domain"],
                    event_type="status",
                    before=before.get("status"),
                    after=observation["status"],
                    days_left=observation["days_left"],
                    date=date,
                )
            )
        before_band = before.get("band")
        after_band = observation.get("band")
        if (
            not status_changed
            and before_band not in (None, "unknown")
            and after_band not in (None, "unknown")
            and before_band != after_band
        ):
            events.append(
                _make_event(
                    key=key,
                    kind=observation["kind"],
                    domain=observation["domain"],
                    event_type="threshold",
                    before=before_band,
                    after=after_band,
                    days_left=observation["days_left"],
                    date=date,
                )
            )
        if observation["kind"] == "ssl":
            before_fingerprint = _normalise_fingerprint(before.get("fingerprint_sha256"))
            after_fingerprint = _normalise_fingerprint(observation.get("fingerprint_sha256"))
            if (
                before_fingerprint
                and after_fingerprint
                and before_fingerprint != after_fingerprint
            ):
                events.append(
                    _make_event(
                        key=key,
                        kind=observation["kind"],
                        domain=observation["domain"],
                        event_type="fingerprint",
                        before=before_fingerprint,
                        after=after_fingerprint,
                        days_left=observation["days_left"],
                        date=date,
                    )
                )
    events.sort(key=lambda event: (event["key"], _EVENT_ORDER.get(event["type"], 9)))
    return events


def _merge_events(
    pending: list[dict[str, Any]],
    new_events: list[dict[str, Any]],
) -> tuple[dict[str, Any], ...]:
    merged: dict[str, dict[str, Any]] = {}
    for event in [*pending, *new_events]:
        merged.setdefault(event["id"], event)
    ordered = sorted(
        merged.values(),
        key=lambda event: (
            event.get("date", ""),
            event.get("key", ""),
            _EVENT_ORDER.get(event.get("type"), 9),
        ),
    )
    return tuple(ordered)


# ── Planning ─────────────────────────────────────────────────────────────────


def prepare_monitoring(
    *,
    config: Config,
    ssl_output: dict[str, Any],
    domain_output: dict[str, Any],
    previous_history: dict[str, Any] | None = None,
    previous_alert_state: dict[str, Any] | None = None,
    snapshot_date: str | None = None,
) -> MonitoringPlan:
    """Combine both result files with previous state.

    Pure: performs no network, file or environment access. The caller decides
    whether and how to deliver ``plan.events``.
    """
    if not _result_rows(ssl_output, "ssl_results.json") and not _result_rows(
        domain_output, "domain_results.json"
    ):
        raise MonitoringError("both result files are empty; refusing to write a blank snapshot")

    history_before = _normalise_history(previous_history)
    state_before = _normalise_alert_state(previous_alert_state)

    snapshot = build_snapshot(
        ssl_output,
        domain_output,
        previous_history=history_before,
        previous_alert_state=state_before,
        snapshot_date=snapshot_date,
    )
    history = merge_history(history_before, snapshot, config.history_limit)

    current_observations = _observations_from_snapshot(
        snapshot,
        config.thresholds,
        ssl_output=ssl_output,
        domain_output=domain_output,
        previous_observations=state_before["observations"],
    )
    new_events = _compare_observations(
        state_before["observations"],
        current_observations,
        date=snapshot["date"],
    )
    events = _merge_events(state_before["pending_events"], new_events)

    alert_state = {
        "version": STATE_VERSION,
        "updated_at": _utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "observations": current_observations,
        "pending_events": [],
    }
    return MonitoringPlan(
        snapshot=snapshot,
        history=history,
        alert_state=alert_state,
        events=events,
    )


def finalize_alert_state(
    alert_state: dict[str, Any],
    events: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    *,
    delivered: bool,
) -> dict[str, Any]:
    """Clear delivered events, or retain them for the next run."""
    final = {
        "version": STATE_VERSION,
        "updated_at": alert_state.get("updated_at")
        or _utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "observations": dict(alert_state.get("observations") or {}),
        "pending_events": [] if delivered else [dict(event) for event in events],
    }
    return final


# ── Discord message ──────────────────────────────────────────────────────────


def _short_fingerprint(value: Any) -> str:
    text = str(value or "")
    return text[:23] + "…" if len(text) > 23 else text


def _event_line(event: dict[str, Any]) -> str:
    domain = str(event.get("domain") or event.get("key") or "unknown")
    kind = str(event.get("kind") or "target").upper()
    days = event.get("days_left")
    days_text = f"{days} days left" if isinstance(days, int) else "days unknown"
    if event.get("type") == "fingerprint":
        return (
            f"- {kind} {domain}: certificate fingerprint changed "
            f"({_short_fingerprint(event.get('from'))} -> {_short_fingerprint(event.get('to'))})"
        )
    if event.get("type") == "nameservers":
        before = ", ".join(str(item) for item in event.get("from") or []) or "none"
        after = ", ".join(str(item) for item in event.get("to") or []) or "none"
        return f"- DNS {domain}: nameservers changed ({before} -> {after})"
    if event.get("type") == "threshold":
        return (
            f"- {kind} {domain}: threshold {event.get('from')} -> "
            f"{event.get('to')} ({days_text})"
        )
    return (
        f"- {kind} {domain}: status {event.get('from')} -> "
        f"{event.get('to')} ({days_text})"
    )


def _escape_mentions(text: str) -> str:
    # Discord strips a zero-width space, but the mention token itself no longer
    # matches. allowed_mentions is the primary guard; this is defence in depth.
    return text.replace("@", "@\u200b")


def build_discord_payload(
    events: tuple[dict[str, Any], ...] | list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a mention-safe Discord message for a batch of events."""
    header = "**CertiWatch alert**"
    lines = [_event_line(event) for event in events]
    if not lines:
        lines = ["- no changes"]

    content = header + "\n" + "\n".join(lines)
    if len(content) > MAX_DISCORD_CONTENT:
        kept: list[str] = []
        used = len(header) + 1
        omitted = 0
        for line in lines:
            if used + len(line) + 1 > MAX_DISCORD_CONTENT - 40:
                omitted += 1
                continue
            kept.append(line)
            used += len(line) + 1
        content = header + "\n" + "\n".join(kept)
        if omitted:
            content += f"\n- …and {omitted} more"
    content = _escape_mentions(content)
    return {
        "content": content[:MAX_DISCORD_CONTENT],
        "allowed_mentions": {"parse": []},
    }


# ── Files and CLI ────────────────────────────────────────────────────────────


def load_result_file(path: str | Path, label: str) -> dict[str, Any]:
    file_path = Path(path)
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise MonitoringError(f"{label}: cannot read {file_path}: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MonitoringError(f"{label}: not valid JSON: {exc}") from exc
    _result_rows(payload, label)
    return payload


def load_json_if_exists(path: str | Path) -> dict[str, Any] | None:
    file_path = Path(path)
    if not file_path.exists():
        return None
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise MonitoringError(f"cannot read {file_path}: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MonitoringError(f"{file_path}: not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise MonitoringError(f"{file_path}: expected a JSON object")
    return payload


def write_json_atomic(path: str | Path, payload: dict[str, Any]) -> None:
    """Write JSON through a sibling temp file and rename."""
    file_path = Path(path)
    directory = file_path.parent
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{file_path.name}.", suffix=".tmp", dir=str(directory)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, file_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare CertiWatch public history and private alert state."
    )
    parser.add_argument(
        "--config",
        default=None,
        help="certiwatch.toml (default: ./certiwatch.toml)",
    )
    parser.add_argument("--ssl-results", default="ssl_results.json")
    parser.add_argument("--domain-results", default="domain_results.json")
    parser.add_argument("--history", default=HISTORY_FILE, help="public history.json")
    parser.add_argument(
        "--alert-state",
        default=ALERT_STATE_FILE,
        help="private alert state; never publish this file",
    )
    parser.add_argument(
        "--transport",
        choices=("none", "discord"),
        default="none",
        help="none writes state only; discord also posts opt-in events",
    )
    parser.add_argument(
        "--checkpoint",
        choices=("none", "local", "kv"),
        default="none",
        help=(
            "durable state checkpoint: 'kv' writes the pending batch to the "
            "scoped Cloudflare KV key before sending; 'local' asserts the "
            "--alert-state path is persistent; required for --transport discord"
        ),
    )
    parser.add_argument("--date", default=None, help="override the UTC snapshot date (YYYY-MM-DD)")
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--retry-delay", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=15.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.max_attempts < 1:
        print("error: --max-attempts must be at least 1", file=sys.stderr)
        return 1
    if args.retry_delay < 0:
        print("error: --retry-delay cannot be negative", file=sys.stderr)
        return 1
    if args.timeout <= 0:
        print("error: --timeout must be positive", file=sys.stderr)
        return 1
    if args.transport == "discord" and args.checkpoint == "none":
        print(
            "error: --transport discord requires --checkpoint local or kv; "
            "the pending batch must survive the run so a send can be retried",
            file=sys.stderr,
        )
        return 1
    try:
        config = load_config(args.config)
        ssl_output = load_result_file(args.ssl_results, "ssl_results.json")
        domain_output = load_result_file(args.domain_results, "domain_results.json")
        previous_history = load_json_if_exists(args.history)
        previous_state = load_json_if_exists(args.alert_state)

        plan = prepare_monitoring(
            config=config,
            ssl_output=ssl_output,
            domain_output=domain_output,
            previous_history=previous_history,
            previous_alert_state=previous_state,
            snapshot_date=args.date,
        )

        transport: DiscordWebhookTransport | None = None
        if args.transport == "discord":
            if not config.alerts.discord:
                raise MonitoringError(
                    "Discord alerts are not enabled in certiwatch.toml "
                    "([alerts] discord = true is required)"
                )
            transport = DiscordWebhookTransport.from_env(timeout=args.timeout)
        checkpoint = checkpoint_from_args(args)
    except (ConfigError, MonitoringError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Persist the pending batch locally, then to the actual remote checkpoint
    # before any Discord request. A crash after the checkpoint leaves the same
    # batch recoverable; a checkpoint failure means no send at all.
    pending_state = finalize_alert_state(
        plan.alert_state,
        plan.events,
        delivered=False,
    )
    try:
        write_json_atomic(args.history, plan.history)
        write_json_atomic(args.alert_state, pending_state)
    except OSError as exc:
        print(f"error: cannot write monitoring state: {exc}", file=sys.stderr)
        return 1

    if checkpoint is not None:
        try:
            checkpoint.save(pending_state)
        except (OSError, ValueError) as exc:
            print(
                "error: durable checkpoint failed before send; no alerts sent: "
                f"{exc}",
                file=sys.stderr,
            )
            return 1

    latest = plan.snapshot["date"]
    print(
        f"history: {len(plan.history['snapshots'])} snapshot(s), latest {latest}, "
        f"ssl={len(plan.snapshot['ssl'])}, domains={len(plan.snapshot['domains'])}"
    )

    if transport is None:
        # Delivery is disabled. Keep pending events instead of pretending they
        # were delivered; they remain available for the next enabled run.
        print(
            f"alerts: {len(plan.events)} event(s), transport=none, "
            "delivered=disabled"
        )
        return 0

    if not plan.events:
        print(f"alerts: 0 event(s), transport={args.transport}, delivered=nothing")
        return 0

    try:
        post_with_retry(
            transport,
            build_discord_payload(plan.events),
            max_attempts=args.max_attempts,
            base_delay=args.retry_delay,
            sleep=time.sleep,
        )
    except DeliveryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(
            f"alerts: {len(plan.events)} event(s), transport={args.transport}, "
            "delivered=no"
        )
        return 2

    final_state = finalize_alert_state(
        plan.alert_state,
        plan.events,
        delivered=True,
    )
    try:
        write_json_atomic(args.alert_state, final_state)
    except OSError as exc:
        # The remote checkpoint still holds the pending batch, so the next run
        # sends it again rather than losing it.
        print(
            "error: alert delivered but local state could not be cleared; "
            f"the batch may be retried: {exc}",
            file=sys.stderr,
        )
        return 1

    if checkpoint is not None:
        try:
            checkpoint.save(final_state)
        except (OSError, ValueError) as exc:
            # The alerts were acknowledged; the remote checkpoint still has the
            # pending batch, so a retry can duplicate but cannot lose it.
            print(
                "error: alert delivered but checkpoint could not be cleared; "
                f"the batch may be retried: {exc}",
                file=sys.stderr,
            )
            return 1

    print(f"alerts: {len(plan.events)} event(s), transport={args.transport}, delivered=yes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
