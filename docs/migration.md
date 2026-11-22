# Rust migration and integration notes

Base: `nooblk-98/certiwatch` commit
`d2d83478311f242af621e8783935be106f50a367` (the merge of PR #13). The two
upstream patches added `backend/` and the redesigned `src/dashboard.*`. This
integration turns them into one root Rust application and removes the legacy
runtime.

## Final layout

```
Cargo.toml, Cargo.lock     one crate, one binary
src/                       Rust service, checkers, feeds, dashboard
docs/                      HTTP contract, migration notes, dashboard design
Dockerfile, compose.yaml   one non-root container
certiwatch.toml            the only target configuration (read-only in Docker)
schema/                    the TOML schema the Rust validator implements
```

Removed in this integration: `backend/` (moved to the root), `.github/workflows`
(all five), `index.html`, `app.js`, `style.css`, `pages/`, `images/`,
`requirements.txt`, `ssl.conf`, `domains.conf`, `scripts/`, the Python `src/`
tree, the Python/node tests, and the Cloudflare Pages/KV assumptions. The
service no longer depends on GitHub Actions, Cloudflare or a static web
directory.

## Architecture

One `certiwatch` binary, one Tokio runtime, one Axum server:

```
scheduler (startup + interval)
  │  1. read + validate certiwatch.toml (read-only, sole target config)
  │  2. TLS checks (bounded concurrency, per-connection timeouts)
  │     registration checks (RDAP → IANA → WHOIS, .lk)
  │  3. TLS coverage gate (no certificate read → abort)
  │  4. history merge + private observations/events
  │  5. feeds built in memory
  │  6. atomic publish under the snapshot lock
  │  7. optional Discord batches (state persisted before send)
  ▼
Axum: GET / (server-rendered dashboard + filters), /dashboard.css,
      /ssl_results.json, /domain_results.json, /history.json, /status.json,
      /expiries.ics, /badges/*, /healthz, /readyz
```

Deliberate choices:

- **No runtime fallback.** No Python, no shelling out to legacy scripts. Parity
  is verified offline, not emulated in production.
- **One config.** `certiwatch.toml` keeps its schema, unknown-key rejection and
  privacy rules. The retired `ssl.conf`/`domains.conf` fallback is gone, so a
  missing or invalid TOML always fails loudly.
- **One server-rendered UI.** The Rust dashboard owns `/`; there is no web
  directory to mount and no browser JavaScript.
- **No operator surface.** There is no admin page, token or `/api` route.
  Refreshes come from the scheduler or `certiwatch check`.
- **Persistent local state.** `private/alert_state.json` replaces the Cloudflare
  KV checkpoint; the pending Discord batch is written before a send.
- **Last-good snapshot.** A failed or partial run never replaces public data.

## Legacy → Rust mapping

| Legacy | Rust | Notes |
| --- | --- | --- |
| `src/config.py` | `src/config.rs` | TOML validation/normalisation, endpoints, bands; no `.conf` fallback |
| `src/ssl/scripts/check_ssl.py` | `src/tls.rs`, `src/certinfo.rs` | direct + STARTTLS, trust vs SAN, HSTS, legacy TLS, full row |
| `src/dns_diagnostics.py` | `src/dns.rs` | NS/CAA/DNSKEY, AD-bit validation, unknown vs absent |
| `src/domain/scripts/check_domains.py` | `src/registration.rs` | RDAP, IANA bootstrap, WHOIS, throttling |
| `src/domain/scripts/check_LK_domains.py` | `src/registration.rs` | `.lk` API with adaptive limiter and retries |
| `src/monitor_state.py` | `src/monitor.rs` | history, observations, events, Discord batching |
| `scripts/build_public_feeds.py` | `src/feeds.rs` | status.json, expiries.ics, badges |
| `scripts/build_dist.py` allowlist + coverage gate | `src/service.rs` | publish gate and public files |
| `scripts/alert_state_store.py` (KV) | `private/alert_state.json` | durable local volume |
| `.github/workflows/*` | built-in scheduler | removed; no CI deployment path |
| `index.html` + `app.js` + `style.css` | `src/dashboard.rs`, `src/dashboard.css` | server-rendered, no JavaScript |
| `src/validate_conf.py` | `certiwatch validate` | summary only; `.conf` repair not ported |

Preserved public contracts: field names and presence, status values, sort
order, history shape, feed categories, badge/UID derivation, ICS folding, cache
headers, `owner`/`notes` exclusion, mention-safe Discord messages.

## Verification run for this integration

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
docker compose build
docker compose up -d
```

The exact counts and container observations are recorded in the delivery
report. The HTTP/pipeline/TLS suites and their fixtures stay in the verification
workspace along with the unit tests and replay inputs. Verification covers configuration, result contracts,
feeds, certificate rules, the HTTP surface, the loopback TLS/STARTTLS probes,
the refresh pipeline and dashboard fixtures. No test needs internet access.

### rust-anything parity

Upstream: `github.com/erkamyaman/rust-anything`.

- release **v2.1.0**, tag commit `71c78e10c5beb39acecd52c2eb3f675a199f3cea`
- `main` inspected at `c5a44482cc98b1ba5845001e704df9c0ddf4ed1f`
- Linux x86_64 asset SHA-256
  `ed36d7a7bc8dd933937c29a6bea8cee53707052fb10cdca483d57242d5342d68`

Workflow: `analyze` → `bridge` (PyO3) → `record` (60 generated cases per
function) → implement `parity/port.rs` by delegating to this crate → `build` →
`diff`.

Result: **1411/1411 cases match**, including 164 recorded error paths, across 19
deterministic units. The recording is tied to base commit `d2d8347` and retained in the verification workspace.

## Recorded seams

1. **Custom exception class.** `ConfigError` subclasses `ValueError` in Python.
   The PyO3 bridge raises standard classes, so the harness records `ValueError`
   for the invalid-threshold path. Messages are identical.
2. **Network behaviour is not recorded.** TLS, DNS, RDAP/WHOIS/.lk and Discord
   are covered by offline integration tests with loopback servers and fakes, not
   by recorded internet traffic.
3. **Byte-for-byte file output.** Public JSON/ICS/SVG are tested for shape,
   determinism, escaping and folding; a full byte diff of every generated file
   against the Python builders is not part of the recording.

## Remaining gaps (do not claim full parity)

| Area | Status |
| --- | --- |
| Cloudflare KV checkpoint | Replaced by durable local state; no KV equivalent. |
| Deployment | The container is self-hosted. A release workflow publishes images to GHCR. |
| Single-check config | Certificate-only or registration-only deployments build feeds from the checks they have; legacy required both result sets. |
| Live DNS/RDAP/WHOIS/.lk/Discord | Not probed here; logic is offline-tested. |
| `.lk` spacing | Shares the global 0.35 s RDAP/WHOIS throttle; slightly slower, no correctness effect. |
| `validate_conf.py` legacy `.conf` repair | Not ported; `certiwatch validate` validates TOML only. |
| HSTS `max-age` bounds | Parsed as `i64`; values above `i64::MAX` are invalid. |
| Exotic EC curve names | Common curves map to Python names; others use the OpenSSL short name. |
| Dashboard visual parity | Deliberately redesigned; see `docs/rust-dashboard-design.md`. |
| Multi-instance data volume | Not supported; one writer per `/data`. |

## Operational safety

- Public HTTP is read-only; there is no remote action surface.
- Private state is `0700`, never served; public writes are atomic.
- Network work is bounded per socket and per run; the run deadline aborts
  without publishing.
- A run in which no certificate was read cannot replace production data.
- Discord sets `allowed_mentions: {"parse": []}` and escapes `@`.
- The webhook comes from the environment and is never logged or written to state.
