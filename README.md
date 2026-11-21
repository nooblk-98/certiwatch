# certiwatch


### SSL Certificates
![SSL Certificates](images/quickshot-2026-05-01-09-16-19.png)

### Domain Registrations
![Domain Registrations](images/quickshot-2026-05-01-09-16-24.png)

### Dashboard — Dark Mode
![Dashboard Dark Mode](images/quickshot-2026-05-01-09-17-23.png)

---

certiwatch is a lightweight monitoring toolkit for:

- SSL/TLS certificate health checks
- Domain expiry tracking
- Config validation and auto-cleaning

It reads domain lists from plain text config files, runs checks in parallel, and writes JSON outputs that can be consumed by the dashboard or automation.

## Features

- SSL certificate inspection
- Detects provider/issuer (Let's Encrypt, Cloudflare, DigiCert, and more)
- Reports issue date, expiry date, remaining days, and status
- Handles common SSL failures (expired, hostname mismatch, self-signed, DNS/timeout/no HTTPS)
- Domain expiry checks
- Uses RDAP and WHOIS fallback for global domains
- Uses register.domains.lk API helper for .lk domains
- Normalizes registrar names (for cleaner reporting)
- Validates malformed entries
- Removes duplicates
- Normalizes values (lowercase, strips protocol and path)
- Optional DNS reachability checks

## Project Files

- `domains.conf` - Input list for domain expiry checks
- `ssl.conf` - Input list for SSL certificate checks
- `index.html` - Dashboard (fetches both result files on load)
- `pages/_headers` - Cloudflare Pages cache policy for the result files
- `scripts/build_dist.py` - Stages the allowlisted Pages publish directory
- `scripts/test_build_dist.py` - Tests for the staging script
- `src/validate_conf.py` - Config validator + auto-fixer
- `src/domain/scripts/check_domains.py` - Domain expiry checker
- `src/domain/scripts/check_LK_domains.py` - .lk expiry helper
- `src/ssl/scripts/check_ssl.py` - SSL checker

Generated, not stored in Git:

- `ssl_results.json` - Output from the SSL checker
- `domain_results.json` - Output from the expiry checker
- `dist/` - Publish directory produced by `scripts/build_dist.py`

## Configuration Files

### domains.conf

Purpose:

- Used by the domain expiry checker
- One domain per line
- Supports comments and blank lines

Accepted examples:

```text
example.com
www.example.org
https://sample.net/path
```

What the tool does automatically:

- Converts to lowercase
- Removes http:// and https://
- Removes paths and trailing dots/spaces
- Removes leading `www.` for registration checks. TLS checks preserve it and accept `host:port`.
- Deduplicates entries

### ssl.conf

Purpose:

- Used by the SSL certificate checker
- One domain per line
- Supports comments and blank lines

Accepted examples:

```text
example.com
api.example.com
https://portal.example.org/login
```

What the tool does automatically:

- Converts to lowercase
- Removes protocol, path, trailing dots/spaces
- Deduplicates entries
- Skips obviously invalid malformed entries

## Requirements

- Python 3.10+
- Python package: cryptography

Install dependency:

```bash
python3 -m pip install -r requirements.txt
```

## Usage

Run from repository root.

### 1. Validate and clean config files (recommended first)

```bash
python3 src/validate_conf.py
```

Skip DNS checks for faster cleanup:

```bash
python3 src/validate_conf.py --no-dns
```

Validate only one file:

```bash
python3 src/validate_conf.py ssl.conf
```

### 2. Run SSL checks

```bash
python3 src/ssl/scripts/check_ssl.py
```

Output is written to `ssl_results.json`.

### 3. Run domain expiry checks

```bash
python3 src/domain/scripts/check_domains.py
```

Output is written to `domain_results.json`.

### 4. Preview the published bundle locally

```bash
python3 scripts/build_dist.py --out dist
python3 -m http.server --directory dist 8000
```

`dist/` is exactly what Cloudflare Pages receives. The build fails if a
required input is missing, empty or not valid result JSON.

## Generated data and Git

`ssl_results.json` and `domain_results.json` are build artifacts, not source:

- They are git-ignored and no longer committed. A fresh clone has neither file
  until you run the checkers.
- Every workflow run regenerates them on the runner and publishes only those
  generated copies. The repository keeps no result history, and each deployment
  replaces the live JSON, so the dashboard always shows the newest run.
- The workflow has `permissions: contents: read` and no commit step; it cannot
  write results back to `main`. What is in the repository and what the site
  serves therefore differ by design.
- Missing, empty, unparseable or zero-row result files fail the build before
  anything is deployed, rather than publishing an empty or broken dashboard.

## Environment Variables

- `DOMAIN_CHECK_DELAY_SEC` - Delay between outbound domain lookup requests (default: 0.35)
- `LK_CHECK_DELAY_SEC` - Delay for .lk API requests (default: 0.8)
- `LK_CHECK_MAX_RETRIES` - Retry count for .lk API failures (default: 3)

Example:

```bash
DOMAIN_CHECK_DELAY_SEC=0.5 LK_CHECK_MAX_RETRIES=5 python3 src/domain/scripts/check_domains.py
```

## Result Status Meanings

SSL status values commonly include:

- `valid`
- `expired`
- `invalid`
- `dns_error`
- `timeout`
- `ssl_error`
- `no_https`
- `error`

Domain expiry status values commonly include:

- `active`
- `warning`
- `urgent`
- `expired`
- `unknown`

## Suggested Workflow

1. Update `domains.conf` and `ssl.conf`.
2. Run `python3 src/validate_conf.py`.
3. Run SSL and domain checks.
4. Use `ssl_results.json` and `domain_results.json` in your dashboard/automation, or build `dist/` to preview exactly what will be published.

## GitHub Actions Automation

`.github/workflows/ssl-check.yml` runs the checks and publishes the dashboard to
Cloudflare Pages. It is the only deployment path; nothing is deployed by hand.

### Triggers

| Trigger | When |
|---|---|
| `schedule` | Every day at **06:00 Asia/Colombo (UTC+5:30)**, i.e. **00:30 UTC** |
| `push` to `main` | Only when a relevant file changes: `index.html`, `app.js`, `style.css`, `ssl.conf`, `domains.conf`, `pages/_headers`, the checker/validator scripts, the staging scripts, or the workflow itself |
| `workflow_dispatch` | Manual run from the GitHub Actions tab |

A publishing run is never cancelled mid-deploy: a second run waits behind it
(`concurrency: certiwatch-pages`).

### What a run does

1. Fails immediately when a required input is missing or empty (`ssl.conf`,
   `domains.conf`, `index.html`, `pages/_headers`, `scripts/build_dist.py`).
2. Validates and normalises `ssl.conf` and `domains.conf` (checkout copy only).
3. Runs the SSL and domain checkers, writing both result files on the runner.
4. Runs `scripts/test_build_dist.py` so the packaging rules are checked before
   anything can be published.
5. Stages the publish directory with `scripts/build_dist.py`.
6. Deploys `dist/` to Cloudflare Pages.

It does **not** commit the results back to `main`; see
[Generated data and Git](#generated-data-and-git).

### Published bundle

Only the files below are uploaded:

| Path in `dist/` | Source | Required |
|---|---|---|
| `index.html` | `index.html` | yes |
| `ssl_results.json` | generated by `check_ssl.py` | yes |
| `domain_results.json` | generated by `check_domains.py` | yes |
| `_headers` | `pages/_headers` | yes |
| `app.js` | `app.js` | no, copied when present |
| `style.css` | `style.css` | no, copied when present |

`scripts/build_dist.py` owns this list. Sources, images and workflow files never
reach the public site, and adding a runtime file means adding an explicit
allowlist entry in a reviewed change; the build fails if an allowlisted file is
missing.

`pages/_headers` sets `Cache-Control: no-cache, must-revalidate` on both JSON
files, so a new deployment is visible immediately and neither the edge nor the
browser serves a stale result.

### Required GitHub configuration

Add these under **Settings → Secrets and variables → Actions**:

| Name | Kind | Description |
|---|---|---|
| `CLOUDFLARE_API_TOKEN` | secret | Cloudflare API token with Pages edit permission |
| `CLOUDFLARE_ACCOUNT_ID` | secret | Cloudflare account ID |
| `CLOUDFLARE_PAGES_PROJECT` | variable, optional | Pages project name; defaults to `certiwatch` |

### Live Dashboard

The dashboard is deployed to Cloudflare Pages and updates after each workflow run:

**https://certiwatch.pages.dev**

A Pages hostname is `<project-name>.pages.dev`, so the workflow deploys to the
project `certiwatch`. The previous workflow targeted a project named
`ssl-domain-monitor`; that account mapping has not been verified here, because
confirming it needs Cloudflare dashboard access or a deploy. Before the first
run, check **Workers & Pages** in Cloudflare:

- if the project is already `certiwatch`, no change is needed;
- if it is still `ssl-domain-monitor` (which serves `ssl-domain-monitor.pages.dev`),
  either rename the project to `certiwatch`, or set the
  `CLOUDFLARE_PAGES_PROJECT` repository variable to the real project name and
  update this URL.

If neither exists, the first deploy creates the project.

### 60-day inactivity caveat

GitHub disables scheduled workflows in a repository after 60 days without
activity. If the project is untouched that long, the daily run stops silently
and the site keeps showing the last published data. Any push, manual run, or
re-enabling the workflow from the Actions tab restarts the schedule; after a long
pause, trigger one manual run and check the result files' `generated_at` values.

### Rollback

Cloudflare Pages keeps every deployment. To revert a bad publish, open
**Workers & Pages → certiwatch → Deployments**, pick the last known-good
deployment and choose **Rollback**. The site then serves that deployment's
bundle, including its result files, until the next successful run. No Git revert
is needed for a rollback; revert the offending commit separately if it also
changed the dashboard, configuration or checks.

The build step prints a manifest of every published file with its size and
SHA-256 prefix, so the log of a run identifies exactly what was deployed.
