"""Offline tests for history, fingerprints and alert delivery."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import config as cfg
import monitor_state as ms

FP_A = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
FP_B = "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"


def load_config(tmp_path: Path, *, history_limit: int = 30, discord: bool = False) -> cfg.Config:
    path = tmp_path / "certiwatch.toml"
    path.write_text(
        f"""
version = 1
[defaults]
history_limit = {history_limit}
[alerts]
discord = {"true" if discord else "false"}
[[targets]]
domain = "example.com"
registration = true
tags = ["public"]
group = "corporate"
owner = "ops@example.com"
notes = "private only"
""",
        encoding="utf-8",
    )
    return cfg.load_config(path)


def ssl_row(
    domain: str = "example.com",
    *,
    days: int | None = 25,
    status: str = "valid",
    fingerprint: str | None = FP_A,
    dns: dict | None = None,
) -> dict:
    row = {
        "domain": domain,
        "days_left": days,
        "status": status,
        "fingerprint_sha256": fingerprint,
    }
    if dns is not None:
        row["dns"] = dns
    return row


def dns_row(*nameservers: str, status: str = "present") -> dict:
    return {
        "checked": True,
        "name": "example.com",
        "ns": {
            "status": status,
            "records": list(nameservers),
            "error": None if status != "unknown" else "timeout",
        },
        "caa": {"status": "absent", "records": [], "error": None},
        "dnssec": {
            "status": "absent",
            "validated": False,
            "records": [],
            "signature_count": 0,
            "error": None,
        },
        "error": None,
    }


def domain_row(
    domain: str = "example.com",
    *,
    days: int | None = 200,
    status: str = "active",
) -> dict:
    return {"domain": domain, "days_left": days, "status": status}


def ssl_output(*rows: dict, generated_at: str = "2026-11-21 00:30 UTC") -> dict:
    return {"generated_at": generated_at, "results": list(rows)}


def domain_output(*rows: dict, generated_at: str = "2026-11-21 00:31 UTC") -> dict:
    return {"generated_at": generated_at, "results": list(rows)}


def prepare(
    config: cfg.Config,
    *,
    ssl: dict | None = None,
    domains: dict | None = None,
    history: dict | None = None,
    state: dict | None = None,
    date: str = "2026-11-21",
) -> ms.MonitoringPlan:
    return ms.prepare_monitoring(
        config=config,
        ssl_output=ssl if ssl is not None else ssl_output(ssl_row()),
        domain_output=domains if domains is not None else domain_output(domain_row()),
        previous_history=history,
        previous_alert_state=state,
        snapshot_date=date,
    )


# ── Public history contract ──────────────────────────────────────────────────


def test_first_snapshot_matches_public_contract_and_has_no_private_metadata(tmp_path):
    plan = prepare(load_config(tmp_path))

    assert plan.snapshot == {
        "date": "2026-11-21",
        "ssl": [
            {
                "domain": "example.com",
                "days_left": 25,
                "status": "valid",
                "fingerprint_sha256": FP_A,
            }
        ],
        "domains": [
            {"domain": "example.com", "days_left": 200, "status": "active"}
        ],
    }
    assert plan.history == {"snapshots": [plan.snapshot]}
    serialised = json.dumps(plan.history)
    assert "ops@example.com" not in serialised
    assert "private only" not in serialised
    assert "owner" not in serialised
    assert "notes" not in serialised


def test_one_snapshot_per_utc_day_replaces_the_same_date(tmp_path):
    config = load_config(tmp_path)
    first = prepare(config, date="2026-11-21")
    second = prepare(
        config,
        ssl=ssl_output(ssl_row(days=20)),
        history=first.history,
        state=first.alert_state,
        date="2026-11-21",
    )

    assert len(second.history["snapshots"]) == 1
    assert second.history["snapshots"][0]["ssl"][0]["days_left"] == 20


def test_history_is_capped_to_the_configured_number(tmp_path):
    config = load_config(tmp_path, history_limit=2)
    previous = {
        "snapshots": [
            {"date": "2026-11-19", "ssl": [], "domains": []},
            {"date": "2026-11-20", "ssl": [], "domains": []},
        ]
    }

    plan = prepare(config, history=previous, date="2026-11-21")

    assert [snap["date"] for snap in plan.history["snapshots"]] == [
        "2026-11-20",
        "2026-11-21",
    ]


def test_snapshot_date_uses_ssl_generated_at(tmp_path):
    config = load_config(tmp_path)
    plan = prepare(
        config,
        ssl=ssl_output(ssl_row(), generated_at="2026-11-22 23:59 UTC"),
        domains=domain_output(domain_row(), generated_at="2026-11-23 00:01 UTC"),
        date=None,
    )

    assert plan.snapshot["date"] == "2026-11-22"


def test_corrupt_previous_history_is_rejected_not_overwritten(tmp_path):
    config = load_config(tmp_path)

    with pytest.raises(ms.MonitoringError, match="history"):
        prepare(config, history={"snapshots": "not a list"})


# ── Fingerprints and stable keys ─────────────────────────────────────────────


def test_last_known_fingerprint_survives_an_outage(tmp_path):
    config = load_config(tmp_path)
    first = prepare(config, date="2026-11-21")
    outage = prepare(
        config,
        ssl=ssl_output(
            ssl_row(days=None, status="timeout", fingerprint=None)
        ),
        history=first.history,
        state=first.alert_state,
        date="2026-11-22",
    )

    assert outage.snapshot["ssl"][0]["fingerprint_sha256"] == FP_A
    observation = outage.alert_state["observations"]["ssl:example.com"]
    assert observation["fingerprint_sha256"] == FP_A
    assert observation["status"] == "timeout"
    assert [event["type"] for event in outage.events] == ["status"]


def test_identical_snapshot_does_not_repeat_an_event(tmp_path):
    config = load_config(tmp_path)
    first = prepare(config, date="2026-11-21")
    changed = prepare(
        config,
        ssl=ssl_output(ssl_row(status="expired", days=-1)),
        history=first.history,
        state=first.alert_state,
        date="2026-11-22",
    )
    assert len(changed.events) == 1
    delivered = ms.finalize_alert_state(changed.alert_state, changed.events, delivered=True)

    repeated = prepare(
        config,
        ssl=ssl_output(ssl_row(status="expired", days=-1)),
        history=changed.history,
        state=delivered,
        date="2026-11-23",
    )

    assert repeated.events == ()


def test_metadata_and_order_do_not_change_stable_keys(tmp_path):
    config = load_config(tmp_path)
    first = prepare(
        config,
        ssl=ssl_output(ssl_row(), ssl_row(domain="other.example", fingerprint=FP_B)),
        domains=domain_output(domain_row(), domain_row("other.example")),
    )
    reordered = prepare(
        config,
        ssl=ssl_output(ssl_row(domain="other.example", fingerprint=FP_B), ssl_row()),
        domains=domain_output(domain_row("other.example"), domain_row()),
        history=first.history,
        state=first.alert_state,
        date="2026-11-22",
    )

    assert reordered.events == ()
    assert set(reordered.alert_state["observations"]) == {
        "ssl:example.com",
        "ssl:other.example",
        "domain:example.com",
        "domain:other.example",
    }


# ── Alert event semantics ───────────────────────────────────────────────────


def test_status_threshold_and_fingerprint_changes_each_create_one_event(tmp_path):
    config = load_config(tmp_path)
    first = prepare(config, date="2026-11-21")
    changed = prepare(
        config,
        ssl=ssl_output(ssl_row(days=10, status="valid", fingerprint=FP_B)),
        history=first.history,
        state=first.alert_state,
        date="2026-11-22",
    )

    assert [(event["type"], event["from"], event["to"]) for event in changed.events] == [
        ("threshold", "notice", "warning"),
        ("fingerprint", FP_A, FP_B),
    ]


def test_nameserver_change_is_one_persisted_event(tmp_path):
    config = load_config(tmp_path)
    first = prepare(
        config,
        ssl=ssl_output(ssl_row(dns=dns_row("ns1.example.", "ns2.example."))),
        date="2026-11-21",
    )
    assert first.alert_state["observations"]["dns:example.com"]["nameservers"] == [
        "ns1.example.",
        "ns2.example.",
    ]

    changed = prepare(
        config,
        ssl=ssl_output(ssl_row(dns=dns_row("ns2.example.", "ns3.example."))),
        history=first.history,
        state=first.alert_state,
        date="2026-11-22",
    )

    assert [(event["type"], event["from"], event["to"]) for event in changed.events] == [
        (
            "nameservers",
            ["ns1.example.", "ns2.example."],
            ["ns2.example.", "ns3.example."],
        )
    ]
    delivered = ms.finalize_alert_state(changed.alert_state, changed.events, delivered=True)
    repeated = prepare(
        config,
        ssl=ssl_output(ssl_row(dns=dns_row("ns2.example.", "ns3.example."))),
        history=changed.history,
        state=delivered,
        date="2026-11-23",
    )
    assert repeated.events == ()


def test_nameserver_unknown_does_not_look_like_an_empty_change(tmp_path):
    config = load_config(tmp_path)
    first = prepare(
        config,
        ssl=ssl_output(ssl_row(dns=dns_row("ns1.example."))),
        date="2026-11-21",
    )
    unknown = prepare(
        config,
        ssl=ssl_output(ssl_row(dns=dns_row(status="unknown"))),
        history=first.history,
        state=first.alert_state,
        date="2026-11-22",
    )

    assert unknown.events == ()
    observation = unknown.alert_state["observations"]["dns:example.com"]
    assert observation["status"] == "present"
    assert observation["lookup_status"] == "unknown"
    assert observation["nameservers"] == ["ns1.example."]


def test_nameserver_change_after_unknown_still_alerts(tmp_path):
    config = load_config(tmp_path)
    first = prepare(
        config,
        ssl=ssl_output(ssl_row(dns=dns_row("ns1.example."))),
        date="2026-11-21",
    )
    unknown = prepare(
        config,
        ssl=ssl_output(ssl_row(dns=dns_row(status="unknown"))),
        history=first.history,
        state=first.alert_state,
        date="2026-11-22",
    )
    changed = prepare(
        config,
        ssl=ssl_output(ssl_row(dns=dns_row("ns2.example."))),
        history=unknown.history,
        state=unknown.alert_state,
        date="2026-11-23",
    )

    assert [event["type"] for event in changed.events] == ["nameservers"]


def test_first_observation_is_a_baseline_not_an_alert(tmp_path):
    plan = prepare(load_config(tmp_path))

    assert plan.events == ()


def test_threshold_change_is_derived_from_configured_thresholds(tmp_path):
    config = load_config(tmp_path)
    first = prepare(config, date="2026-11-21")
    changed = prepare(
        config,
        ssl=ssl_output(ssl_row(days=3)),
        history=first.history,
        state=first.alert_state,
        date="2026-11-22",
    )

    assert [(event["type"], event["from"], event["to"]) for event in changed.events] == [
        ("threshold", "notice", "urgent")
    ]


# ── Delivery and retry semantics ────────────────────────────────────────────


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0
        self.payloads = []

    def send(self, payload):
        self.calls += 1
        self.payloads.append(payload)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def test_retry_uses_retry_after_and_exponential_backoff():
    transport = FakeTransport(
        [
            ms.TransportResponse(500),
            ms.TransportResponse(429, retry_after=2.0),
            ms.TransportResponse(204),
        ]
    )
    waits: list[float] = []

    result = ms.post_with_retry(
        transport,
        {"content": "hello"},
        max_attempts=3,
        base_delay=1.0,
        sleep=waits.append,
    )

    assert result.attempts == 3
    assert transport.calls == 3
    assert waits == [1.0, 2.0]


def test_non_retryable_status_stops_immediately():
    transport = FakeTransport([ms.TransportResponse(400)])

    with pytest.raises(ms.DeliveryError, match="400"):
        ms.post_with_retry(
            transport, {"content": "hello"}, max_attempts=3, sleep=lambda _: None
        )

    assert transport.calls == 1


def test_failed_delivery_is_retried_from_private_state_on_the_next_run(tmp_path):
    config = load_config(tmp_path)
    first = prepare(config, date="2026-11-21")
    changed = prepare(
        config,
        ssl=ssl_output(ssl_row(status="expired", days=-1)),
        history=first.history,
        state=first.alert_state,
        date="2026-11-22",
    )
    failed_state = ms.finalize_alert_state(changed.alert_state, changed.events, delivered=False)

    assert [event["type"] for event in failed_state["pending_events"]] == ["status"]

    retry = prepare(
        config,
        ssl=ssl_output(ssl_row(status="expired", days=-1)),
        history=changed.history,
        state=failed_state,
        date="2026-11-23",
    )

    assert len(retry.events) == 1
    assert retry.events[0]["type"] == "status"
    delivered = ms.finalize_alert_state(retry.alert_state, retry.events, delivered=True)
    assert delivered["pending_events"] == []


def test_discord_payload_blocks_mentions_and_stays_short():
    events = [
        {
            "key": "@everyone ssl:example.com",
            "kind": "ssl",
            "domain": "@here.example",
            "type": "status",
            "from": "valid",
            "to": "expired",
            "days_left": -1,
            "date": "2026-11-21",
        }
    ]

    payload = ms.build_discord_payload(events)

    assert payload["allowed_mentions"] == {"parse": []}
    assert "@everyone" not in payload["content"]
    assert "@here" not in payload["content"]
    assert len(payload["content"]) <= 2000


def test_webhook_secret_never_appears_in_repr_or_errors():
    secret = "https://discord.com/api/webhooks/123456/very-secret-token"
    transport = ms.DiscordWebhookTransport(secret)

    assert "very-secret-token" not in repr(transport)
    assert "very-secret-token" not in str(transport)

    class Broken:
        def send(self, payload):
            raise ms.TransportError("network down", retryable=False)

    with pytest.raises(ms.DeliveryError) as excinfo:
        ms.post_with_retry(Broken(), {"content": "x"}, max_attempts=1, sleep=lambda _: None)
    assert "very-secret-token" not in str(excinfo.value)


# ── CLI ─────────────────────────────────────────────────────────────────────


def test_cli_writes_history_and_private_state_without_network(tmp_path, capsys):
    config_path = tmp_path / "certiwatch.toml"
    config_path.write_text(
        """
version = 1
[defaults]
history_limit = 7
[[targets]]
domain = "example.com"
registration = true
""",
        encoding="utf-8",
    )
    ssl_path = tmp_path / "ssl_results.json"
    domain_path = tmp_path / "domain_results.json"
    ssl_path.write_text(json.dumps(ssl_output(ssl_row())), encoding="utf-8")
    domain_path.write_text(json.dumps(domain_output(domain_row())), encoding="utf-8")
    history_path = tmp_path / "history.json"
    state_path = tmp_path / "private" / "alert_state.json"

    code = ms.main(
        [
            "--config",
            str(config_path),
            "--ssl-results",
            str(ssl_path),
            "--domain-results",
            str(domain_path),
            "--history",
            str(history_path),
            "--alert-state",
            str(state_path),
            "--transport",
            "none",
            "--date",
            "2026-11-21",
        ]
    )

    assert code == 0
    assert json.loads(history_path.read_text(encoding="utf-8"))["snapshots"][0]["date"] == (
        "2026-11-21"
    )
    private = json.loads(state_path.read_text(encoding="utf-8"))
    assert "observations" in private
    assert "owner" not in json.dumps(private)
    assert "notes" not in json.dumps(private)
    output = capsys.readouterr().out
    assert "1 snapshot" in output


def test_cli_rejects_invalid_retry_options():
    assert ms.main(["--max-attempts", "0"]) == 1
    assert ms.main(["--retry-delay", "-1"]) == 1
    assert ms.main(["--timeout", "0"]) == 1


def test_cli_refuses_discord_when_not_opted_in(tmp_path):
    config_path = tmp_path / "certiwatch.toml"
    config_path.write_text(
        "version = 1\n[[targets]]\ndomain = 'example.com'\n", encoding="utf-8"
    )
    (tmp_path / "ssl_results.json").write_text(
        json.dumps(ssl_output(ssl_row())), encoding="utf-8"
    )
    (tmp_path / "domain_results.json").write_text(
        json.dumps(domain_output(domain_row())), encoding="utf-8"
    )

    code = ms.main(
        [
            "--config",
            str(config_path),
            "--ssl-results",
            str(tmp_path / "ssl_results.json"),
            "--domain-results",
            str(tmp_path / "domain_results.json"),
            "--history",
            str(tmp_path / "history.json"),
            "--alert-state",
            str(tmp_path / "state.json"),
            "--transport",
            "discord",
            "--checkpoint",
            "local",
            "--date",
            "2026-11-21",
        ]
    )

    assert code == 1
    assert not (tmp_path / "history.json").exists()


def _cli_args(
    tmp_path: Path,
    *,
    transport: str,
    checkpoint: str = "none",
) -> list[str]:
    return [
        "--config",
        str(tmp_path / "certiwatch.toml"),
        "--ssl-results",
        str(tmp_path / "ssl_results.json"),
        "--domain-results",
        str(tmp_path / "domain_results.json"),
        "--history",
        str(tmp_path / "history.json"),
        "--alert-state",
        str(tmp_path / "private" / "alert_state.json"),
        "--transport",
        transport,
        "--checkpoint",
        checkpoint,
        "--date",
        "2026-11-21",
    ]


def _write_cli_inputs(tmp_path: Path, *, expired: bool = False) -> None:
    load_config(tmp_path, discord=True)
    status = "expired" if expired else "valid"
    days = -1 if expired else 25
    (tmp_path / "ssl_results.json").write_text(
        json.dumps(ssl_output(ssl_row(status=status, days=days))), encoding="utf-8"
    )
    (tmp_path / "domain_results.json").write_text(
        json.dumps(domain_output(domain_row())), encoding="utf-8"
    )


class RecordingCheckpoint:
    def __init__(self, order: list, *, fail_on: int | None = None) -> None:
        self.order = order
        self.fail_on = fail_on
        self.saved: list[dict] = []

    def save(self, state: dict) -> None:
        index = len(self.saved)
        self.saved.append(state)
        self.order.append(("checkpoint", len(state.get("pending_events", []))))
        if self.fail_on == index:
            raise OSError("checkpoint unavailable")


class RecordingTransport:
    def __init__(self, order: list) -> None:
        self.order = order
        self.payloads: list[dict] = []

    def send(self, payload: dict) -> ms.TransportResponse:
        self.order.append(("send",))
        self.payloads.append(payload)
        return ms.TransportResponse(204)


def test_checkpoint_factory_selects_local_kv_or_none(monkeypatch):
    from argparse import Namespace

    assert ms.checkpoint_from_args(Namespace(checkpoint="none", timeout=15)) is None
    assert isinstance(
        ms.checkpoint_from_args(Namespace(checkpoint="local", timeout=15)),
        ms.LocalCheckpoint,
    )

    monkeypatch.setenv("CERTIWATCH_STATE_KV_TOKEN", "token-value")
    monkeypatch.setenv("CERTIWATCH_STATE_KV_NAMESPACE", "namespace-value")
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "account-value")
    checkpoint = ms.checkpoint_from_args(Namespace(checkpoint="kv", timeout=15))
    assert checkpoint.__class__.__name__ == "KvCheckpoint"


def test_cli_requires_checkpoint_before_discord(tmp_path):
    _write_cli_inputs(tmp_path)
    code = ms.main(_cli_args(tmp_path, transport="discord"))
    assert code == 1
    assert not (tmp_path / "history.json").exists()
    assert not (tmp_path / "private" / "alert_state.json").exists()


def test_cli_checkpoints_pending_before_send_and_clears_after(tmp_path, monkeypatch):
    _write_cli_inputs(tmp_path)
    assert ms.main(_cli_args(tmp_path, transport="none")) == 0

    # A state change on the next run creates one event.
    _write_cli_inputs(tmp_path, expired=True)
    order: list = []
    checkpoint = RecordingCheckpoint(order)
    transport = RecordingTransport(order)

    class FakeWebhook:
        @classmethod
        def from_env(cls, timeout=15.0):
            return transport

    monkeypatch.setattr(ms, "DiscordWebhookTransport", FakeWebhook)
    monkeypatch.setattr(ms, "checkpoint_from_args", lambda args: checkpoint)
    code = ms.main(_cli_args(tmp_path, transport="discord", checkpoint="kv"))

    assert code == 0
    assert order == [("checkpoint", 1), ("send",), ("checkpoint", 0)]
    assert checkpoint.saved[0]["pending_events"]
    assert checkpoint.saved[1]["pending_events"] == []
    final = json.loads((tmp_path / "private" / "alert_state.json").read_text(encoding="utf-8"))
    assert final["pending_events"] == []


def test_failed_checkpoint_means_zero_sends(tmp_path, monkeypatch):
    _write_cli_inputs(tmp_path)
    assert ms.main(_cli_args(tmp_path, transport="none")) == 0
    _write_cli_inputs(tmp_path, expired=True)

    order: list = []
    checkpoint = RecordingCheckpoint(order, fail_on=0)
    transport = RecordingTransport(order)

    class FakeWebhook:
        @classmethod
        def from_env(cls, timeout=15.0):
            return transport

    monkeypatch.setattr(ms, "DiscordWebhookTransport", FakeWebhook)
    monkeypatch.setattr(ms, "checkpoint_from_args", lambda args: checkpoint)
    code = ms.main(_cli_args(tmp_path, transport="discord", checkpoint="kv"))

    assert code == 1
    assert transport.payloads == []
    assert [item[0] for item in order] == ["checkpoint"]
    state = json.loads((tmp_path / "private" / "alert_state.json").read_text(encoding="utf-8"))
    assert state["pending_events"], "pending batch must survive a checkpoint failure"


def test_delivery_failure_keeps_pending_local_and_remote(tmp_path, monkeypatch):
    _write_cli_inputs(tmp_path)
    assert ms.main(_cli_args(tmp_path, transport="none")) == 0
    _write_cli_inputs(tmp_path, expired=True)

    order: list = []
    checkpoint = RecordingCheckpoint(order)

    class FailingWebhook:
        @classmethod
        def from_env(cls, timeout=15.0):
            class Failing:
                def send(self, payload):
                    order.append(("send-failed",))
                    return ms.TransportResponse(500)

            return Failing()

    monkeypatch.setattr(ms, "DiscordWebhookTransport", FailingWebhook)
    monkeypatch.setattr(ms, "checkpoint_from_args", lambda args: checkpoint)
    code = ms.main(
        [
            *_cli_args(tmp_path, transport="discord", checkpoint="kv"),
            "--max-attempts",
            "1",
        ]
    )

    assert code == 2
    assert [item[0] for item in order] == ["checkpoint", "send-failed"]
    assert checkpoint.saved[0]["pending_events"]
    state = json.loads((tmp_path / "private" / "alert_state.json").read_text(encoding="utf-8"))
    assert state["pending_events"], "failed delivery must remain pending"


def test_checkpoint_clear_failure_after_acknowledged_send(tmp_path, monkeypatch):
    _write_cli_inputs(tmp_path)
    assert ms.main(_cli_args(tmp_path, transport="none")) == 0
    _write_cli_inputs(tmp_path, expired=True)

    order: list = []
    checkpoint = RecordingCheckpoint(order, fail_on=1)
    transport = RecordingTransport(order)

    class FakeWebhook:
        @classmethod
        def from_env(cls, timeout=15.0):
            return transport

    monkeypatch.setattr(ms, "DiscordWebhookTransport", FakeWebhook)
    monkeypatch.setattr(ms, "checkpoint_from_args", lambda args: checkpoint)
    code = ms.main(_cli_args(tmp_path, transport="discord", checkpoint="kv"))

    assert code == 1
    assert order == [("checkpoint", 1), ("send",), ("checkpoint", 0)]
    # The checkpoint still holds the acknowledged batch; a retry may duplicate.
    assert checkpoint.saved[0]["pending_events"]
    assert checkpoint.saved[1]["pending_events"] == []
    final = json.loads((tmp_path / "private" / "alert_state.json").read_text(encoding="utf-8"))
    assert final["pending_events"] == []


def test_transport_none_preserves_pending_events(tmp_path, monkeypatch):
    _write_cli_inputs(tmp_path)
    assert ms.main(_cli_args(tmp_path, transport="none")) == 0
    _write_cli_inputs(tmp_path, expired=True)

    order: list = []
    checkpoint = RecordingCheckpoint(order)
    monkeypatch.setattr(ms, "checkpoint_from_args", lambda args: checkpoint)

    code = ms.main(
        _cli_args(tmp_path, transport="none", checkpoint="kv")
    )

    assert code == 0
    assert order == [("checkpoint", 1)]
    state = json.loads((tmp_path / "private" / "alert_state.json").read_text(encoding="utf-8"))
    assert state["pending_events"], "disabled delivery must preserve pending events"


def test_cli_does_not_send_when_local_state_write_fails(tmp_path, monkeypatch):
    _write_cli_inputs(tmp_path)
    assert ms.main(_cli_args(tmp_path, transport="none")) == 0
    _write_cli_inputs(tmp_path, expired=True)

    order: list = []
    checkpoint = RecordingCheckpoint(order)
    transport = RecordingTransport(order)
    real_write = ms.write_json_atomic
    state_path = tmp_path / "private" / "alert_state.json"

    def fail_state(path, payload):
        if Path(path) == state_path:
            raise OSError("state volume is read-only")
        return real_write(path, payload)

    class FakeWebhook:
        @classmethod
        def from_env(cls, timeout=15.0):
            return transport

    monkeypatch.setattr(ms, "DiscordWebhookTransport", FakeWebhook)
    monkeypatch.setattr(ms, "checkpoint_from_args", lambda args: checkpoint)
    monkeypatch.setattr(ms, "write_json_atomic", fail_state)
    code = ms.main(_cli_args(tmp_path, transport="discord", checkpoint="kv"))

    assert code == 1
    assert transport.payloads == []
    assert checkpoint.saved == []


# ── Bounded batches, partial failure and TLS coverage ───────────────────────


def make_event(index: int, domain: str | None = None) -> dict:
    name = domain or f"example-{index:03d}.example"
    return {
        "id": f"event-{index}",
        "key": f"ssl:{name}",
        "kind": "ssl",
        "domain": name,
        "type": "status",
        "from": "valid",
        "to": "expired",
        "days_left": index,
        "date": "2026-11-21",
    }


def test_discord_batches_are_bounded_and_never_drop_events():
    events = [make_event(index) for index in range(80)]
    batches = ms.build_discord_batches(events)

    assert len(batches) > 1
    assert sum(len(batch.events) for batch in batches) == len(events)
    assert all(len(batch.payload["content"]) <= ms.MAX_DISCORD_CONTENT for batch in batches)
    sent_ids = [event["id"] for batch in batches for event in batch.events]
    assert sent_ids == [event["id"] for event in events]
    assert all("…and" not in batch.payload["content"] for batch in batches)


def test_a_single_oversized_event_is_refused_not_truncated():
    with pytest.raises(ms.MonitoringError, match="exceeds|too large"):
        ms.build_discord_batches([make_event(0, domain="x" * 3000 + ".example")])


def test_partial_multi_batch_failure_keeps_only_unacknowledged_events(
    tmp_path, monkeypatch
):
    _write_cli_inputs(tmp_path)
    assert ms.main(_cli_args(tmp_path, transport="none")) == 0

    events = [make_event(index) for index in range(80)]
    state_path = tmp_path / "private" / "alert_state.json"
    state_path.write_text(
        json.dumps(
            {
                "version": 1,
                "updated_at": "2026-11-20T00:00:00Z",
                "observations": {},
                "pending_events": events,
            }
        ),
        encoding="utf-8",
    )
    first_batch = len(ms.build_discord_batches(events)[0].events)

    order: list = []
    checkpoint = RecordingCheckpoint(order)

    class FailSecondBatch:
        def __init__(self):
            self.calls = 0

        def send(self, payload):
            self.calls += 1
            order.append(("send", self.calls))
            if self.calls == 2:
                return ms.TransportResponse(500)
            return ms.TransportResponse(204)

        @classmethod
        def from_env(cls, timeout=15.0):
            return cls()

    transport = FailSecondBatch()

    class FakeWebhook:
        @classmethod
        def from_env(cls, timeout=15.0):
            return transport

    monkeypatch.setattr(ms, "DiscordWebhookTransport", FakeWebhook)
    monkeypatch.setattr(ms, "checkpoint_from_args", lambda args: checkpoint)
    code = ms.main(
        [
            *_cli_args(tmp_path, transport="discord", checkpoint="kv"),
            "--max-attempts",
            "1",
        ]
    )

    assert code == 2
    assert transport.calls == 2, "must not continue after an unacknowledged batch"
    assert [len(state["pending_events"]) for state in checkpoint.saved] == [
        len(events),
        len(events) - first_batch,
    ]
    final = json.loads(state_path.read_text(encoding="utf-8"))
    assert len(final["pending_events"]) == len(events) - first_batch
    assert final["pending_events"][0]["id"] == events[first_batch]["id"]


def test_all_unreachable_tls_run_never_writes_history_state_or_alerts(
    tmp_path, monkeypatch, capsys
):
    _write_cli_inputs(tmp_path)
    assert ms.main(_cli_args(tmp_path, transport="none")) == 0

    history_path = tmp_path / "history.json"
    state_path = tmp_path / "private" / "alert_state.json"
    history_before = history_path.read_bytes()
    state_before = state_path.read_bytes()

    failed = ssl_output(
        ssl_row("one.example", status="dns_error", days=None),
        ssl_row("two.example", status="timeout", days=None),
    )
    (tmp_path / "ssl_results.json").write_text(json.dumps(failed), encoding="utf-8")

    order: list = []
    checkpoint = RecordingCheckpoint(order)
    transport = RecordingTransport(order)

    class FakeWebhook:
        @classmethod
        def from_env(cls, timeout=15.0):
            return transport

    monkeypatch.setattr(ms, "DiscordWebhookTransport", FakeWebhook)
    monkeypatch.setattr(ms, "checkpoint_from_args", lambda args: checkpoint)
    code = ms.main(_cli_args(tmp_path, transport="none", checkpoint="kv"))

    assert code == 1
    assert history_path.read_bytes() == history_before
    assert state_path.read_bytes() == state_before
    assert checkpoint.saved == []
    assert transport.payloads == []
    assert "no certificate was read" in capsys.readouterr().err


def test_put_404_checkpoint_means_zero_sends(tmp_path, monkeypatch):
    import sys
    import urllib.error

    scripts = Path(__file__).resolve().parent.parent / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import alert_state_store

    _write_cli_inputs(tmp_path)
    assert ms.main(_cli_args(tmp_path, transport="none")) == 0
    _write_cli_inputs(tmp_path, expired=True)

    order: list = []
    transport = RecordingTransport(order)

    class FakeWebhook:
        @classmethod
        def from_env(cls, timeout=15.0):
            return transport

    def not_found(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 404, "not found", {}, None)

    monkeypatch.setenv("CERTIWATCH_STATE_KV_TOKEN", "token")
    monkeypatch.setenv("CERTIWATCH_STATE_KV_NAMESPACE", "namespace")
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "account")
    monkeypatch.setattr(ms, "DiscordWebhookTransport", FakeWebhook)
    monkeypatch.setattr(alert_state_store.urllib.request, "urlopen", not_found)
    code = ms.main(_cli_args(tmp_path, transport="discord", checkpoint="kv"))

    assert code == 1
    assert transport.payloads == []
    state = json.loads((tmp_path / "private" / "alert_state.json").read_text(encoding="utf-8"))
    assert state["pending_events"], "pending batch must survive a PUT 404"


def test_each_acknowledged_batch_advances_the_checkpoint(tmp_path, monkeypatch):
    _write_cli_inputs(tmp_path)
    assert ms.main(_cli_args(tmp_path, transport="none")) == 0

    events = [make_event(index) for index in range(80)]
    state_path = tmp_path / "private" / "alert_state.json"
    state_path.write_text(
        json.dumps(
            {
                "version": 1,
                "updated_at": "2026-11-20T00:00:00Z",
                "observations": {},
                "pending_events": events,
            }
        ),
        encoding="utf-8",
    )
    batch_sizes = [len(batch.events) for batch in ms.build_discord_batches(events)]
    assert len(batch_sizes) >= 3

    order: list = []
    checkpoint = RecordingCheckpoint(order)
    transport = RecordingTransport(order)

    class FakeWebhook:
        @classmethod
        def from_env(cls, timeout=15.0):
            return transport

    monkeypatch.setattr(ms, "DiscordWebhookTransport", FakeWebhook)
    monkeypatch.setattr(ms, "checkpoint_from_args", lambda args: checkpoint)
    code = ms.main(_cli_args(tmp_path, transport="discord", checkpoint="kv"))

    assert code == 0
    assert len(transport.payloads) == len(batch_sizes)
    expected = [len(events)]
    remaining = len(events)
    for size in batch_sizes:
        remaining -= size
        expected.append(remaining)
    assert [len(state["pending_events"]) for state in checkpoint.saved] == expected
    assert checkpoint.saved[-1]["pending_events"] == []
