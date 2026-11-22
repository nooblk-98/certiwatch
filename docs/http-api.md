# CertiWatch HTTP contract

The service has one public, read-only HTTP surface: a server-rendered dashboard
and the generated feeds. There is no operator, administration or write API.

## Routes

| Method | Path | Body | `Content-Type` | `Cache-Control` |
| --- | --- | --- | --- | --- |
| GET/HEAD | `/` | dashboard, rendered per request | `text/html; charset=utf-8` | `no-cache` |
| GET/HEAD | `/dashboard.css` | the same stylesheet the page embeds | `text/css; charset=utf-8` | `public, max-age=3600` |
| GET/HEAD | `/ssl_results.json` | latest certificate checks | `application/json; charset=utf-8` | `no-cache, must-revalidate` |
| GET/HEAD | `/domain_results.json` | latest registration checks | `application/json; charset=utf-8` | `no-cache, must-revalidate` |
| GET/HEAD | `/history.json` | public snapshots; optional | `application/json; charset=utf-8` | `no-cache, must-revalidate` |
| GET/HEAD | `/status.json` | public summary feed; optional | `application/json; charset=utf-8` | `no-cache, must-revalidate` |
| GET/HEAD | `/expiries.ics` | RFC 5545 calendar | `text/calendar; charset=utf-8` | `public, max-age=300, must-revalidate` |
| GET/HEAD | `/badges/manifest.json` | badge index | `application/json; charset=utf-8` | `no-cache, must-revalidate` |
| GET/HEAD | `/badges/<slug>-<32 hex>.svg` | one badge | `image/svg+xml; charset=utf-8` | `public, max-age=300, must-revalidate` |
| GET/HEAD | `/healthz` | liveness | `application/json; charset=utf-8` | `no-store` |
| GET/HEAD | `/readyz` | snapshot readiness | `application/json; charset=utf-8` | `no-store` |
| GET/HEAD | `/robots.txt` | `Disallow: /` | `text/plain; charset=utf-8` | none |

Missing public files return `404`. A missing `/status.json` before a run with
both checks is normal. Unknown paths — including the retired `/index.html`,
`/app.js`, `/style.css`, `/api/status`, `/api/config` and `/api/refresh` — return
`404` for every method. `POST` on a read-only path returns `405`.

Every response carries `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`. The HTML response
also carries:

```
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline';
  img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
```

The page has no JavaScript. `form-action 'self'` exists because the filters are
plain GET forms.

## Dashboard query parameters

All parameters are optional, and unknown or malformed values fall back to the
default instead of failing the request.

| Parameter | Values | Default | Meaning |
| --- | --- | --- | --- |
| `tab` | `ssl`, `domains` (aliases `domain`, `certificates`, `certs`) | `ssl` | Result set |
| `status` | `all`, `attention`, `soon`, `urgent`, `expired`, `issues`, `valid` | `all` | Row filter |
| `q` | text, max 120 chars | empty | Domain/host search |
| `group` | text, max 60 | empty | Exact group filter |
| `tag` | text, max 60 | empty | Tag filter |
| `sort` | `attention`, `days`, `domain`, `status`, `checked` | `attention` | Sort key |
| `dir` | `asc`, `desc` | `asc` | Sort direction |
| `open` | row key (`domain` or `domain\|port`) | empty | Details expanded |

Filters scope the list and the table. The KPI strip and the "Needs attention"
list describe the whole result file, which is why a filtered page can still
mention an item outside the filter.

A request never mixes runs: the three dashboard inputs are read under the same
lock that the publisher holds while replacing the public bundle.

## `ssl_results.json`

```json
{
  "generated_at": "2026-11-21 18:00 UTC",
  "total_domains": 2,
  "valid": 1,
  "expired": 0,
  "errors": 1,
  "results": [
    {
      "domain": "example.com",
      "host": "example.com",
      "port": 443,
      "status": "valid",
      "provider": "Let's Encrypt",
      "issued_on": "2026-09-01",
      "expires_on": "2026-12-01",
      "days_left": 10,
      "is_expired": false,
      "error": null,
      "checked_at": "2026-11-21 18:00 UTC",
      "trusted_chain": true,
      "hostname_matches": true,
      "common_name": "example.com",
      "san": ["example.com", "www.example.com"],
      "san_count": 2,
      "key_type": "ECDSA",
      "key_size": 256,
      "key_curve": "secp256r1",
      "key_strength": "acceptable",
      "tls_version": "TLSv1.3",
      "cipher": "TLS_AES_256_GCM_SHA384",
      "fingerprint_sha256": "AA:BB:…",
      "chain_length": 2,
      "hsts": {"applicable": true, "status": "present", "max_age": 31536000},
      "dns": {"checked": true, "ns": {"status": "present"}, "caa": {"status": "absent"}},
      "tags": ["public"],
      "group": "corporate"
    }
  ]
}
```

`status` values: `valid`, `expired`, `invalid`, `dns_error`, `timeout`,
`ssl_error`, `no_https`, `error`. `days_left` is floored for display; expiry is
decided by `is_expired` from the exact `not_after`. `hostname_matches` uses SANs
only. `revocation_status` is always `not_checked`; OCSP/CRL is not implemented.
`owner` and `notes` never appear.

Optional compatibility fields remain present: `resolved_via`, `fallback`,
`chain`, `chain_source`, `dns_name`, `legacy_tls`, `revocation`,
`serial_number`.

## `domain_results.json`

```json
{
  "generated_at": "2026-11-21 18:01 UTC",
  "total_domains": 1,
  "active": 1,
  "warning": 0,
  "urgent": 0,
  "expired": 0,
  "results": [
    {
      "domain": "example.com",
      "registrar": "Example Registrar",
      "purchase_date": "N/A",
      "expiry_date": "2027-11-21",
      "days_left": 365,
      "status": "active",
      "dns_name": "example.com",
      "dns": {"checked": true, "ns": {"status": "present"}},
      "tags": ["public"],
      "group": "corporate"
    }
  ]
}
```

`status` values: `active`, `warning`, `urgent`, `expired`, `unknown`.
`expiry_date`/`purchase_date` may be `"N/A"`; `days_left` may be `null`. A lookup
failure is `unknown`, never an invented expiry.

## `history.json`

```json
{
  "snapshots": [
    {
      "date": "2026-11-21",
      "ssl": [
        {"domain": "example.com", "days_left": 10, "status": "valid", "fingerprint_sha256": "AA:BB:…"}
      ],
      "domains": [
        {"domain": "example.com", "days_left": 365, "status": "active"}
      ]
    }
  ]
}
```

- At most one snapshot per UTC date; a second run that day replaces it.
- The newest `history_limit` snapshots are kept, ascending by date.
- Rows are sorted by `domain`; only the fields shown are emitted.
- A failed TLS probe keeps the last known fingerprint.
- The file is optional on a first run.

## `status.json` (summary feed)

```json
{
  "schema_version": 1,
  "generated_at": "2026-11-21T18:01:00Z",
  "overall_status": "warning",
  "checks": {
    "certificates": {"generated_at": "2026-11-21T18:00:00Z", "rows": 10},
    "registrations": {"generated_at": "2026-11-21T18:01:00Z", "rows": 10}
  },
  "links": {"calendar": "/expiries.ics", "badges": "/badges/manifest.json"},
  "summary": {
    "domains": {"total": 10, "ok": 9, "warning": 1, "critical": 0, "unknown": 0},
    "certificates": {"total": 10, "valid": 9, "expired": 0, "invalid": 0, "error": 1, "unknown": 0},
    "registrations": {"total": 10, "active": 10, "warning": 0, "urgent": 0, "expired": 0, "unknown": 0}
  },
  "domains": [
    {
      "domain": "example.com",
      "status": "ok",
      "badge": "/badges/example-com-0123456789abcdef0123456789abcdef.svg",
      "certificate": {
        "status": "valid", "category": "valid", "expires_on": "2026-12-01",
        "days_left": 10, "provider": "Let's Encrypt"
      },
      "registration": {
        "status": "active", "category": "active", "expires_on": "2027-11-21",
        "days_left": 365, "registrar": "Example Registrar"
      }
    }
  ]
}
```

Dashboard categories:

- certificate: `expired | today | urgent | warning | valid | invalid | error | unknown`
  (`days <= 0` today, `<= 7` urgent, `<= 30` warning)
- registration: `expired | urgent | warning | active | unknown`
- domain badge: `critical` when a certificate is expired/today/invalid or a
  registration is expired; `warning` when a configured check is missing,
  unreachable or inside a 30-day window; `unknown` when every configured check
  is unknown; otherwise `ok`. A check that is not configured for the deployment
  is ignored rather than treated as missing.

`certificate` or `registration` is `null` when that check is not configured.

`status.json`, `expiries.ics` and `badges/manifest.json` are published when at
least one result set has a row. A certificate-only or registration-only
deployment builds them from the checks it has.

## Badges

`badges/manifest.json`:

```json
{
  "schema_version": 1,
  "generated_at": "2026-11-21T18:01:00Z",
  "badges": {
    "example.com": {
      "path": "/badges/example-com-0123456789abcdef0123456789abcdef.svg",
      "status": "ok",
      "color": "#2f855a",
      "sha256": "<sha256 of the SVG bytes>"
    }
  }
}
```

File names are `<readable slug>-<sha256(domain)[:32]>.svg`. The slug is
cosmetic; the hash keeps `exa-mple.com` and `exa.mple.com` apart. Only
`[a-z0-9-]` slugs and exactly 32 hex characters are served. SVG text is escaped.

## `expiries.ics`

RFC 5545, CRLF, 75-octet folded lines, one all-day event per certificate and
registration expiry that has a real date. UID is
`sha256("<kind>|<domain>|<YYYY-MM-DD>")[:32]@certiwatch.pages.dev`, so a rebuild
updates instead of duplicating events. Sorted by start date, domain, kind.
`REFRESH-INTERVAL`/`X-PUBLISHED-TTL` are one hour.

## Health and readiness

| Path | Meaning |
| --- | --- |
| `GET /healthz` | process is alive: `200 {"status":"ok","uptime_seconds":N}` |
| `GET /readyz` | a snapshot exists: `200 {"status":"ready"}`, else `503` with `Retry-After: 30` |

Readiness deliberately stays ready when a later refresh fails, because the
previous snapshot is still served. `/readyz` is not a freshness check. The last
run summary is written to `/data/private/last_run.json` and logged, not exposed
over HTTP.

## Publish semantics clients can rely on

- At most one refresh is in flight; the scheduler owns it.
- `certiwatch.toml` is re-read on every run. An invalid file fails the run and
  leaves the previous snapshot alone.
- Every public file is replaced atomically, and dashboard reads take a shared
  lock, so a response never mixes two runs.
- A run in which no certificate was read is rejected before publishing, so a
  network outage cannot replace real data.
- `history.json` gains or replaces the current UTC date only on a published run.
- Discord is opt-in twice (TOML + webhook environment variable). Events are
  persisted before the first send and cleared only after acknowledgement.
