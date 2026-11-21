# Unified config, history and alert lifecycle

This document describes the monitoring lifecycle added for CertiWatch PR #12.
It covers the files, the public JSON contract, the private state, the opt-in
Discord path, the durable-state rule, and the exact CI inputs/outputs. The
workflow, publish allowlist and headers are now integrated; the remaining
verification items are listed at the end.

## Files

| File | Owner | Public? |
|---|---|---|
| `certiwatch.toml` | source | yes |
| `schema/certiwatch.schema.json` | source | yes |
| `src/config.py` | source | yes |
| `src/monitor_state.py` | source | yes |
| `ssl_results.json` | generated | yes |
| `domain_results.json` | generated | yes |
| `history.json` | generated | yes |
| `.certiwatch/alert_state.json` | generated | **no, private** |
| `scripts/build_public_feeds.py` | source | yes |
| `scripts/alert_state_store.py` | source | yes |

`history.json` and `.certiwatch/` are git-ignored. In CI, public history uses a
main-only Actions cache; the private state uses a dedicated scoped Cloudflare KV
key. The private state must never be committed, published, put in an Actions
cache or uploaded as an artifact.

## Unified configuration

`certiwatch.toml` is parsed with `tomllib`, validated against
`schema/certiwatch.schema.json`, and normalised into immutable `Target`
objects. Unknown keys are rejected so a typo cannot silently disable a check.

```toml
version = 1

[defaults]
ssl_port = 443
thresholds = [30, 14, 7, 1]
history_limit = 365

[alerts]
discord = false

[[targets]]
domain = "example.com"          # host, host:port or URL
ssl = true                      # default: true
registration = false            # default: false (opt-in)
ssl_port = 443                  # optional per-entry TLS port
tags = ["public", "core"]
group = "corporate"
owner = "ops@example.com"       # not emitted; tracked TOML is public in Git
notes = "Primary site."         # not emitted; tracked TOML is public in Git
```

Rules enforced by `src/config.py`:

- `domain` is required. A leading `www.` is preserved for TLS and stripped for
  registration keys.
- `ssl` defaults to `true`; `registration` defaults to `false`. At least one
  must be enabled.
- `ssl_port` overrides `[defaults].ssl_port`. A port in `domain` and an
  `ssl_port` must agree. A port is rejected on a registration-only target.
- Duplicate TLS endpoints and duplicate registration domains are rejected.
- `thresholds` must contain exactly four non-negative, strictly descending
  integers.
- Only `tags` and `group` are emitted as public metadata. `owner` and `notes`
  stay local to the loaded `Target` and never reach result files, history or
  Discord messages. The tracked `certiwatch.toml` itself is public in Git, so
  every value in it—including owner/notes—must be treated as public.
- An existing TOML file that is invalid is a hard error. There is **no silent
  fallback** to `ssl.conf` / `domains.conf`.

### Legacy `.conf` compatibility

When `certiwatch.toml` is absent, both checkers (and the monitoring CLI) can read
the old `ssl.conf` / `domains.conf` pair for local use. The legacy path has no
tags, group, owner or notes, and it always uses the default thresholds and
history cap. If `certiwatch.toml` exists, it wins even when the `.conf` files
also exist.

The repository keeps the `.conf` files only for local legacy use. The publish
workflow requires `certiwatch.toml`, passes it explicitly to both checkers and
does not require either `.conf` file.

`python3 src/validate_conf.py --no-dns` validates `certiwatch.toml` when it is
present and leaves the legacy files alone. Add `--legacy` to also validate and
auto-fix `ssl.conf` / `domains.conf`.

### Threshold bands

Four descending thresholds map to fixed bands:

| Days left | Band |
|---|---|
| negative | `expired` |
| 0 through threshold 4 (default 1) | `critical` |
| threshold 3 (default 7) | `urgent` |
| threshold 2 (default 14) | `warning` |
| threshold 1 (default 30) | `notice` |
| above threshold 1 | `ok` |
| missing | `unknown` |

The checker's public `status` is unchanged (`valid`, `expired`, `invalid`,
`active`, `warning`, `urgent`, …). The band exists for alert changes.

## Public history contract

`history.json` is exactly:

```json
{
  "snapshots": [
    {
      "date": "YYYY-MM-DD",
      "ssl": [
        {
          "domain": "example.com",
          "days_left": 24,
          "status": "valid",
          "fingerprint_sha256": "AA:BB:…"
        }
      ],
      "domains": [
        {
          "domain": "example.com",
          "days_left": 180,
          "status": "active"
        }
      ]
    }
  ]
}
```

- The date comes from `ssl_results.json`'s `generated_at`, then
  `domain_results.json`'s, then the current UTC date. `--date` overrides it.
- One snapshot per UTC date. A second run on the same date replaces that date.
- The newest `history_limit` snapshots are retained.
- Rows are sorted by `domain` for reproducible diffs.
- `fingerprint_sha256` keeps the last known fingerprint when the current TLS
  probe failed and did not return one. It is `null` only before the first
  successful observation.
- No tags, group, owner, notes or webhook data is written to this file.

## Published feeds

`scripts/build_public_feeds.py` turns the same result files into:

| Output | Contract |
|---|---|
| `status.json` | versioned summary, aggregate counts and per-domain certificate/registration status |
| `expiries.ics` | RFC 5545 all-day events for each real certificate and registration expiry |
| `badges/manifest.json` | domain → badge URL/status/colour/sha256 |
| `badges/<slug>-<sha256>.svg` | deterministic escaped badge per domain |

The bundle builder invokes the feed builder inside its staging directory, adds
the dynamic file list to the allowlist check, and swaps the whole bundle
atomically. See the module docstring for the exact JSON/ICS fields and the
README for the endpoint table.

## TLS coverage before state

`monitor_state.py` calls the same TLS-coverage gate as the publish builder
before it reads previous history/state or writes anything. A run in which every
SSL row is a DNS, connect, handshake or input failure exits `1` with both
`history.json` and the private state byte-for-byte unchanged, and no checkpoint
or Discord call is made. Genuine `valid`, `expired` or `invalid` verdicts pass.

## Private alert state

`.certiwatch/alert_state.json` is separate and structurally different:

```json
{
  "version": 1,
  "updated_at": "2026-11-21T00:35:00Z",
  "observations": {
    "ssl:example.com": {
      "kind": "ssl",
      "domain": "example.com",
      "status": "valid",
      "days_left": 24,
      "band": "notice",
      "fingerprint_sha256": "AA:BB:…"
    }
  },
  "pending_events": []
}
```

Keys are stable across runs:

- TLS: `ssl:<canonical host[:port]>` (for example `ssl:mail.example.com:993`).
- Registration: `domain:<normalised registrable name>`, with `www.` stripped.

Changing tags, group, owner, notes or target order does not change a key. A
different TLS port is a different endpoint by design.

An event is created only when a previously observed key changes:

- `status` change (including recovery),
- `threshold` band change while status is unchanged,
- TLS `fingerprint` change.

A first observation is a baseline and does not alert. Repeated identical
snapshots produce no events. A status change supersedes the threshold-band
change it implies, so one incident does not produce two events. If delivery
fails, the events stay in `pending_events` and are retried on the next run.

### Durable state before sending

The local file alone is not a checkpoint: a hosted runner is lost when the job
ends, and a workflow step that pushes KV **after** `monitor_state.py` returns
cannot protect a crash inside that process. `src/monitor_state.py` therefore
takes a `--checkpoint`:

| Value | Meaning |
|---|---|
| `kv` | Before any Discord call, write the pending batch to the scoped Cloudflare KV key. After an acknowledged delivery, write the cleared state. |
| `local` | Assert that `--alert-state` is on genuinely persistent storage (self-hosted/manual runs). No remote call. |
| `none` | No checkpoint. Refused with `--transport discord`; valid only for disabled delivery. |

Ordering is strict:

1. write `history.json` and the pending local state;
2. write the pending batch to the remote checkpoint (KV);
3. **only then** call Discord;
4. only after a 2xx acknowledgement, clear the local batch and then the remote
   checkpoint.

Consequences:

- a checkpoint failure aborts with **zero sends** and exit `1`;
- a failed send leaves the batch pending locally and remotely, and exits `2`;
- a crash after a successful send but before the clearing write leaves the
  batch pending, so the next run may send it again;
- a failed checkpoint-clear write after a 2xx acknowledgement leaves the remote
  batch pending, so a retry may duplicate it;
- a crash after the checkpoint but before the send similarly leaves pending
  events for the next run.

This is **at-least-once**, not exactly-once. A duplicate alert is the accepted
cost; an alert lost because the runner vanished is not. `--transport discord`
requires `--checkpoint local` or `kv`; CI always uses `kv` and refuses to send
without a remote checkpoint.

### Disabled-send backlog and KV failures

When delivery is disabled (`--transport none`), no events are discarded. The
pending list is rewritten unchanged, so a later enabled run sends the backlog;
the list can grow while alerts are off and is bounded only by the 2 MB KV state
limit. Exceeding that limit fails the checkpoint closed and sends nothing.

KV failure behavior is deliberate:

- a missing **GET** key is a first run, not an error;
- a **PUT 404 or any other PUT failure** is a checkpoint failure, never success;
- a pull failure stops the job before `monitor_state.py`;
- a pre-send checkpoint failure aborts with zero sends;
- a post-acknowledgement checkpoint failure can duplicate the acknowledged
  batch on the next run; it cannot lose it.

Cloudflare limits writes to the same key to **one per second**. The checkpoint
paces writes at that interval and retries HTTP 429 using `Retry-After`, with a
bounded attempt count and maximum delay. The next Discord batch is not sent
until the prior checkpoint PUT has been acknowledged; a failed or exhausted
checkpoint stops the queue. A nameserver event may be large, so only its
Discord display is shortened with an explicit omitted count; the complete list
remains in the private event state.

Messages are split into bounded batches of at most 2000 characters. Every event
belongs to exactly one batch. A very large nameserver list is shortened only in
the Discord display, with an explicit omitted count, while the complete list
stays in the private event state; any other event that still cannot fit fails
rather than being silently truncated or dropped. After each acknowledged batch,
the local and remote states retain only the unacknowledged events.

## Discord delivery

Delivery is opt-in twice:

1. `[alerts] discord = true` in `certiwatch.toml`.
2. `--transport discord` on the CLI (the workflow additionally requires the
   `CERTIWATCH_ALERTS_ENABLED` repository variable).

The webhook URL comes only from the `CERTIWATCH_DISCORD_WEBHOOK` environment
secret. It is never a command-line argument, never written to state, and never
included in an error or log. Messages set `allowed_mentions: {"parse": []}` and
also escape `@`, so a domain or note cannot ping `@everyone` or `@here`.

`--transport discord` also requires `--checkpoint local` or `--checkpoint kv`.
CI always chooses `kv` when `CERTIWATCH_STATE_KV_NAMESPACE` is configured and
refuses to enable delivery otherwise, so an ephemeral runner cannot send an
alert without first writing the pending batch to durable storage.

`post_with_retry()` retries HTTP 429 and 5xx responses (honouring `Retry-After`)
and transient transport errors with exponential backoff, up to `--max-attempts`.
Other 4xx responses fail immediately. `sleep` is injectable, so the offline
tests assert the exact delay sequence without making a request.

## CLI

```bash
python3 src/monitor_state.py \
  --config certiwatch.toml \
  --ssl-results ssl_results.json \
  --domain-results domain_results.json \
  --history history.json \
  --alert-state .certiwatch/alert_state.json \
  --transport none
```

To send from a persistent host, add the checkpoint and transport:

```bash
python3 src/monitor_state.py ... --transport discord --checkpoint local
```

In CI, use `--checkpoint kv` with the KV environment; never `local` on a hosted
runner.

- `--transport none` writes history and state only; it is the default and makes
  no network request. Existing pending events are preserved, not discarded.
- `--transport discord` requires the TOML opt-in, the environment secret and a
  checkpoint other than `none`.
- `--checkpoint kv` writes the pending batch to the scoped KV key before the
  send; a failed checkpoint means zero sends.
- `--date YYYY-MM-DD` overrides the snapshot date (backfills and tests only).
- Exit `0`: written successfully (including disabled delivery with pending
  events preserved).
- Exit `1`: configuration, input, local-write or checkpoint error. A failed
  checkpoint means no send; any pending local state is kept for inspection.
- Exit `2`: history and pending state were written, but Discord delivery failed;
  the events remain pending locally and in the checkpoint for the next run.

## Exact CI state inputs and outputs

### Verify job (pull requests, pushes, offline tests)

Inputs:

- repository files only, including `certiwatch.toml` and the schema;
- no environment secret, no network, no previous state.

Commands now run:

```bash
python3 src/validate_conf.py --config certiwatch.toml --no-dns
python -m pytest -q -p no:cacheprovider
node --test tests/dashboard.test.mjs
python3 scripts/test_build_dist.py
```

The Python tests include the feed, config, monitor-state, checkpoint-ordering,
KV adapter and bundle suites. They generate in-memory certificates, local TLS
servers and fake Discord/KV transports only. The verify job never restores
history, touches KV or sends a request.

These checks are in `.github/workflows/verify.yml` as a reusable
`workflow_call`. `.github/workflows/pr-verify.yml` calls it for every pull
request with no secrets; the production workflow calls the same job as its
`needs: verify` dependency. The dedicated PR workflow is independent of the
production workflow's `disabled_inactivity` state.

Outputs:

- none. The verify job writes no history, no private state and sends no
  notification.

### Publish job (main, schedule, manual)

The publish job runs only on `refs/heads/main`; a feature-branch dispatch is
skipped.

| Input | Source | Required |
|---|---|---|
| `certiwatch.toml` | repository | yes |
| `ssl_results.json` | SSL checker | yes |
| `domain_results.json` | domain checker | yes |
| `history.json` | main-only Actions cache | no (first run) |
| `.certiwatch/alert_state.json` | dedicated scoped Cloudflare KV | no (first run) |
| `CERTIWATCH_DISCORD_WEBHOOK` | repository secret | only when alerts are enabled |

Outputs:

| Output | Destination | Publish? |
|---|---|---|
| `history.json` | main-only Actions cache, then publish bundle | yes |
| `.certiwatch/alert_state.json` | dedicated scoped Cloudflare KV | **never** |
| `status.json`, `expiries.ics`, `badges/**` | publish bundle | yes |
| Discord message | external webhook, opt-in only | yes, opt-in only |

Exact production command after the result checkers:

```bash
python3 src/monitor_state.py \
  --config certiwatch.toml \
  --ssl-results ssl_results.json \
  --domain-results domain_results.json \
  --history history.json \
  --alert-state .certiwatch/alert_state.json \
  --transport none
```

When alerts are enabled, use `--transport discord --checkpoint kv`; the workflow
chooses `kv` only when `CERTIWATCH_STATE_KV_NAMESPACE` is configured and refuses
to enable Discord otherwise. With no KV namespace it stays at
`--transport none --checkpoint none`, preserving any pulled pending events
locally (no remote checkpoint is claimed without KV).

### Public history cache

The cache key is `certiwatch-history-<run_id>-<run_attempt>` with the
`certiwatch-history-` restore prefix. It is public data and is restored/saved
only in the main-only publish job. GitHub evicts caches unused for 7 days and
caps a repository's cache at 10 GB (least-recently-used entries first). A cache
miss starts a new history with the current snapshot; the dashboard treats
history as optional, so publish is never blocked.

### Private state KV

`scripts/alert_state_store.py` uses the fixed Cloudflare API origin and only the
configured namespace/key. Configuration comes from
`CERTIWATCH_STATE_KV_TOKEN`, `CERTIWATCH_STATE_KV_NAMESPACE` and
`CLOUDFLARE_ACCOUNT_ID`; the token is never a CLI argument and never appears in
output. A missing **GET** key is a first run. A **PUT 404** or any other PUT
failure is a hard checkpoint failure and sends nothing.

The workflow pulls state before `monitor_state.py`; the CLI then owns every
checkpoint write before and after each acknowledged batch. There is no redundant
post-run push step. The path is never uploaded as an artifact or cache.

## Remaining verification

1. The production workflow is currently `disabled_inactivity` (last run
   2026-08-31), so it will not run until an admin enables it. The new
   `pr-verify.yml` is a separate, secret-free workflow and is intended to run PR
   checks despite that state; it begins running once these files are committed
   and a PR event occurs.
2. Cloudflare Pages project mapping (`certiwatch` vs the older
   `ssl-domain-monitor`) remains unverified.
3. Cloudflare's handling of `Content-Type` for `.ics` and `.svg` through
   `pages/_headers` should be confirmed with `curl -I` after a real deploy.
4. The KV namespace/token and Discord webhook are optional and were not created
   or exercised; the offline tests use fakes.
