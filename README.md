# CertiWatch

Certificate and domain-expiry monitoring as **one Rust service**. CertiWatch
ships as a single binary and a single Docker Compose container: it runs the
checks on a built-in schedule, keeps history and alert state on a persistent
volume, and serves a server-rendered dashboard plus read-only JSON, badge and
calendar feeds.

Configure targets in `certiwatch.toml` and open the read-only dashboard.

![CertiWatch Command Center dashboard (dark theme)](docs/dashboard.png)

*Command Center dashboard, dark theme (default): status banner, KPI row, certificate table grouped by urgency (healthy group collapsed) with expandable details, clickable expiry radar, a 30-day renewal calendar and issuers. A Dark/Light switch in the header remembers your choice in a cookie.*

![CertiWatch Command Center dashboard (light theme)](docs/dashboard-light.png)

*Light theme, using the bundled default targets.*

## What it does

- Checks TLS certificates directly or through SMTP/IMAP/POP3 STARTTLS: trust
  chain, hostname/SAN match, expiry, key strength, TLS version and cipher.
- Checks domain registration through RDAP, the IANA bootstrap and WHOIS,
  including the `.lk` registry API.
- Optionally reports DNS (NS/CAA/DNSSEC), HSTS, and legacy TLS 1.0/1.1
  capability.
- Merges each run into a public history, derives alert events, and can deliver
  them to one Discord webhook.
- Publishes all files atomically: a failed or partial run keeps the previous
  snapshot visible.

## Architecture

```
certiwatch serve
  ├─ scheduler ── refresh pipeline
  │                 1. read + validate certiwatch.toml (read-only)
  │                 2. TLS checks + registration checks (bounded concurrency)
  │                 3. coverage gate (a run that read no certificate cannot publish)
  │                 4. history + private alert state
  │                 5. feeds built in memory
  │                 6. atomic commit of one generation: public files plus the
  │                    initial private alert checkpoint
  │                 7. optional Discord delivery (state persisted before send)
  └─ Axum HTTP
        GET /                  server-rendered dashboard (filters are GET forms)
        GET /dashboard.css     the embedded stylesheet
        GET /healthz /readyz   liveness / snapshot-readiness probes
        GET /ssl_results.json  latest certificate results
        GET /domain_results.json
        GET /history.json
        GET /status.json       summary feed
        GET /expiries.ics      renewal calendar
        GET /badges/*          SVG badges + manifest
```

The HTTP surface is read-only. Refreshes happen on the schedule or through the
`certiwatch check` CLI; nothing in the running server can be triggered remotely.

## Quick start: Docker Compose

Requirements: Docker with Compose v2.

```bash
# 1. Review targets. This file is the only configuration and is mounted read-only.
$EDITOR certiwatch.toml

# 2. Build and start one container.
docker compose up -d --build

# 3. Watch the first run and the probes.
docker compose logs -f certiwatch
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

Open <http://127.0.0.1:8080/>. The first check can take a while for many
targets; `/readyz` answers `503` until the first snapshot is published.
`docker compose down` stops the service; data stays in the `certiwatch-data`
volume.

To change the port: `CERTIWATCH_PORT=9090 docker compose up -d`.

Published releases are available from GHCR, tagged with the version (no `v`):

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/certiwatch.toml:/config/certiwatch.toml:ro" \
  -v certiwatch-data:/data \
  ghcr.io/nooblk-98/certiwatch:2.0.1
```

### Compose contract

| Item | Value |
| --- | --- |
| Service | `certiwatch` (one container, no sidecars) |
| Image user | `10001:10001`, non-root |
| Root filesystem | read-only, `/tmp` tmpfs |
| Config | `./certiwatch.toml` mounted at `/config/certiwatch.toml:ro` |
| Persistent data | named volume `certiwatch-data` at `/data` |
| Capabilities | all dropped, `no-new-privileges` |
| Healthcheck | `curl -fsS http://127.0.0.1:8080/healthz` |
| Stop | `SIGTERM`, 30 s grace period |

## Native build

Rust 1.88 or newer, a C toolchain, OpenSSL development headers and `pkg-config`:

```bash
cargo build --release --locked
./target/release/certiwatch validate --config certiwatch.toml
./target/release/certiwatch serve --config certiwatch.toml --data-dir ./data
```

Run one check without starting the server:

```bash
./target/release/certiwatch check --config certiwatch.toml --data-dir ./data
```

`check` exits `0` when the run published, `2` when it published with a delivery
error, and `1` when it failed (the previous snapshot is kept).

## Configuration

`certiwatch.toml` is validated against `schema/certiwatch.schema.json`. Unknown
keys are rejected so a typo cannot silently disable a check. `owner` and `notes`
stay local and are never copied to results, history, feeds or Discord.

```toml
version = 1

[defaults]
ssl_port = 443
thresholds = [30, 14, 7, 1]
history_limit = 365
check_dns = true
check_hsts = true
check_legacy_tls = false

[alerts]
discord = false          # webhook comes from CERTIWATCH_DISCORD_WEBHOOK

[[targets]]
domain = "example.com"   # host, host:port or URL
registration = true
tags = ["public", "core"]
group = "corporate"
owner = "ops@example.com"
notes = "Primary site."

[[targets]]
domain = "mail.example.com:587"
tls_mode = "starttls"
starttls_protocol = "smtp"
https = false
```

Per-target overrides: `ssl`, `ssl_port`, `registration`, `tls_mode`,
`starttls_protocol`, `https`, `dns_name`, `check_dns`, `check_hsts`,
`check_legacy_tls`.

The service reads the file at startup and on every refresh, so target edits are
picked up on the next run without a restart. It never writes to the file.

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `CERTIWATCH_CONFIG` | `./certiwatch.toml` | Configuration path |
| `CERTIWATCH_DATA_DIR` | `./data` | Persistent generation store and run state |
| `CERTIWATCH_LISTEN` | `0.0.0.0:8080` | HTTP listen address |
| `CERTIWATCH_REFRESH_INTERVAL` | `3600` | Seconds between scheduled runs |
| `CERTIWATCH_RUN_ON_START` | `1` | Run once at startup (`0`/`false` disables) |
| `CERTIWATCH_RUN_TIMEOUT` | `900` | Overall run deadline, seconds |
| `CERTIWATCH_MAX_CONCURRENCY` | `4` | Parallel checks per run |
| `SSL_CHECK_TIMEOUT` | `15` | Per-connection timeout in seconds; finite positive values up to 86400, otherwise the default |
| `SSL_CA_FILE` | unset | Extra CA bundle for private CAs |
| `CERTIWATCH_DISCORD_WEBHOOK` | unset | Discord webhook; never logged or stored |

## Releases

`.github/workflows/release-publish.yml` is the only workflow. It runs when a
**published** GitHub release named `vMAJOR.MINOR.PATCH` is created (never on a
branch, pull request, draft or prerelease) and:

1. checks out the release tag and rejects a tag that is not exactly
   `vMAJOR.MINOR.PATCH`;
2. requires `Cargo.toml`'s version to equal the release version;
3. requires the checked-out commit to be an ancestor of `main`;
4. pushes one image, `ghcr.io/nooblk-98/certiwatch:<MAJOR.MINOR.PATCH>`, and
   records its `sha256` digest in the run summary.

It does not create releases, deploy the service, or push `latest`. Repository
`contents` are read-only for the job; only the publish step receives
`packages: write`. Actions are pinned to commit SHAs.

## Data, backup and restore

```
/data
├── current.json               # convenience pointer; records are authoritative
├── commits/
│   └── <id>.json              # durable commit evidence for each generation
├── generations/
│   └── <id>/
│       ├── public/            # served; safe to back up
│       │   ├── ssl_results.json
│       │   ├── domain_results.json
│       │   ├── history.json
│       │   ├── status.json
│       │   ├── expiries.ics
│       │   └── badges/
│       ├── private/           # 0700; never served
│       │   └── alert_state.json
│       └── .complete.json     # manifest of the committed generation
├── public/                    # legacy tree, copied into a generation once
└── private/last_run.json      # latest run summary
```

Back up the whole volume; the committed `generations/` directories,
`commits/` records and `current.json` are what prevent duplicate alerts after a
restart. Recovery fails closed on incomplete record I/O, while readable
invalid records suppress migration and allow fallback to an older verified
generation. Record IDs come only from strict filenames and must match the
payload. Retention counts only recovery-eligible generations, protects the
current one, and preserves unknown or unverifiable evidence; records are
removed only after a generation directory is removed. Snapshot example:

```bash
docker run --rm -v certiwatch-data:/data -v "$PWD/backup:/backup" \
  alpine tar czf /backup/certiwatch-$(date +%F).tgz -C /data .
```

Restore into a new volume, then start the service. Certificate history is a
single writer: run exactly one CertiWatch container against a volume.

## Operations

- **Health:** `/healthz` proves the process is up. `/readyz` is `200` only after
  a complete, coherent generation is committed, `503` with `Retry-After: 30`
  before that. See [publication and egress hardening](docs/security-hardening.md).
- **Refresh:** scheduled every `CERTIWATCH_REFRESH_INTERVAL` seconds, plus one
  startup run unless disabled. There is no HTTP refresh endpoint.
- **Logs:** one line per run (trigger, row counts, events, duration, whether the
  snapshot was published) and one at shutdown. Secrets are never logged.
- **Graceful stop:** `SIGTERM` stops accepting connections, lets the scheduler
  finish within 10 s, and exits. Compose allows 30 s.
- **Upgrade:** `docker compose build --pull && docker compose up -d`. The volume
  and config are untouched.
- **Rollback:** start the previous image tag against the same volume and config.
  Generations are committed atomically, but an image older than this layout
  reads only the legacy `public/` tree, so back up the volume before downgrading
  across the layout change.
- **Failure:** a run that cannot read any certificate, or cannot build a feed,
  does not publish. The dashboard keeps showing the last good snapshot and marks
  stale data after 36 hours.

## Security posture

- Non-root container, read-only root filesystem, all capabilities dropped.
- `certiwatch.toml` is mounted read-only; no secrets belong in it.
- Private state is `0700` and never routed.
- Security headers: `nosniff`, `no-referrer`, `X-Frame-Options: DENY`, and a CSP
  with `default-src 'none'`, no scripts, inline styles only (the embedded
  stylesheet) and `form-action 'self'` for the dashboard filters.
- Discord mentions are neutralised (`allowed_mentions: {"parse": []}`).

## From the original CertiWatch

The project began as scheduled certificate and domain checks that published a
static dashboard. Version 2 brings the checks, schedule, storage, dashboard and
feeds together in one self-hosted Rust service. The migration matched 1,411
recorded legacy cases using [rust-anything](https://github.com/erkamyaman/rust-anything).
See the [migration notes](docs/migration.md) for scope and verification limits.

## Contributions welcome

Bug reports, feature suggestions and pull requests are welcome. For a bug,
include your version, deployment method and a minimal example with credentials
and private target names removed.

Before opening a PR, run:

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
docker compose build
```

## Live protocol gaps

Operational limits:

- **No operator API.** Refreshes are scheduled or CLI-only. A misconfigured
  container is fixed with config + restart/next run, not a remote action.
- **One writer per data volume.** There is no distributed lock or leader
  election; two containers sharing `/data` can interleave publications.
- **No config hot reload of operational settings.** `certiwatch.toml` targets are
  re-read on each run, but listen address, data dir, interval and timeouts need a
  restart.
- **Outbound network required.** DNS, TLS, RDAP/WHOIS and Discord are not
  mirrored offline. Live service behaviour (including rate limits) is verified
  through offline test fixtures during the migration.
- **Revocation:** OCSP/CRL checking is not implemented and is not claimed.
- **DNS semantics:** records are what the host resolver returned; DNSSEC is
  "validated" only when the resolver sets the AD bit.
- **Discord is the only alert transport.** Delivery is at-least-once with a
  durable batch; ordering across runs is not guaranteed.
- **UTC.** All timestamps are UTC; the dashboard formats dates for display.
- **History is daily.** Multiple runs on the same day replace that day's
  snapshot.
- **Release images.** Publishing a GitHub release builds the versioned GHCR image.
  The running service handles monitoring and scheduling independently.

## License

MIT.
