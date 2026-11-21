# Rust dashboard design record

The server-rendered dashboard in `src/dashboard.rs` and `src/dashboard.css` was
built against the existing CertiWatch JSON contracts on `main` at
`d2d8347`. The brief required the
[dashboard-design skill](https://github.com/abdiraimov-otabek/dashboard-design-skill),
read at commit `463b8fdf62c640180ec1ba731f3616c2319bf68c` (website skill
`dashboard-design` 2.1.0).

## Interface

```rust
mod dashboard;

let query: DashboardQuery = serde_urlencoded::from_str(
    request_url.query().unwrap_or_default(),
)
.unwrap_or_default();

let html = dashboard::render_dashboard(
    ssl_json.as_ref(),        // Option<&serde_json::Value>
    domains_json.as_ref(),    // Option<&serde_json::Value>
    history_json.as_ref(),    // Option<&serde_json::Value>
    &query,
);
```

`DashboardQuery` is public, `Default` and `Deserialize`; every field is optional
and unknown or malformed values fall back to the default instead of rejecting
the request. `render_dashboard` renders at the current clock;
`render_dashboard_at(..., now_unix)` is the same page with an explicit UTC clock
for tests and offline previews.

The page embeds `DASHBOARD_CSS`. A deployment with a strict CSP that forbids
inline styles can serve `dashboard::DASHBOARD_CSS` as `/dashboard.css` and keep
the rest of the markup unchanged.

The module does not read files, make network calls, run browser JavaScript or
touch the feeds. Routes for `status.json`, `expiries.ics` and
`badges/manifest.json` are linked but stay the server's responsibility.

## The screen's question

> Is anything that expires okay today, and which item needs action first?

At first glance the strip answers it with six counts that partition the current
result set: valid/active, 8–30 days, ≤ 7 days (including today), expired, issues
(no expiry data), and the total. The problem list and the expiry bands sit
directly below, above the table.

## Rules applied

| Rule | Where it is applied |
| --- | --- |
| One question per screen, first glance | KPI strip: six partition counts; no chart is needed to learn whether anything is wrong. |
| Monitor: overview → attention → closer look → act | Header → KPIs → needs-attention list and expiry bands → filtered table with native details. |
| Attention lives on the data, action beside it | Each attention row is the link that filters to that host and opens its details. Expired and urgent bands are the warmest marks. |
| Wordless | Visible text is names, numbers, units, one- or two-word baselines ("next to renew", "1 today", "no expiry data"), control labels and chips. Explanations live in details/tooltips or the empty states. |
| Colour follows the entity; warm only for problems | One accent blue for interaction and healthy history; amber for 8–30 and ≤ 7 days; red for expired and unreadable rows; grey for healthy rows. Every state also carries its word, so colour is never the only signal. |
| Quiet healthy data | Healthy bars are pale blue-grey; only the expired/urgent chips and tile values are saturated. |
| Context for every number | Each tile names its band; the list says "Showing X of Y · most urgent first"; history names the peak and the previous checks. |
| Numbers | Tabular figures in tables, counts and axes; `—` for no data; dates as "18 Nov 2026"; percentages under 1% read `<1%`. |
| Say it once | Counts are computed once per block and reused; the KPI partition does not repeat the total inside every tile; the history table repeats chart values only as the accessible copy. |
| Density scale | 14 px base, 13 px tables/sub-lines, 12 px labels, 28 px KPI values, 16 px icons, 1.2 px strokes, medium weights. |
| Tokens before components | `src/dashboard.css` defines every colour once for light and dark (system scheme plus `data-theme`), with tints as token + alpha. |
| Layout grows with the screen | 2/3/6 KPI columns; main and lower panels go 1 → 7/5 at 900 px; content caps at 1240 px and reaches 1640 px from 1800 px. |
| No holes | Cards align at the top rather than stretching a short card; the timeline and attention cards hold comparable content. |
| Phones | 375 px: no page scroll, one column, rows fold into labelled blocks, the table header becomes visually hidden, filters stack, the sticky header is disabled, controls remain 30–36 px tall. |
| States | Setup (both files absent), per-check unavailable, empty result, no search matches, stale (>36 h), future timestamp, row checks older than 36 h, skipped rows, history missing/invalid/empty. |
| QA | Known totals from an independent script, words audit, salience test, screenshots at 375 / 768 / 1024 / 1440 / 1800 / 3440, light and dark, keyboard and contrast checks. |

## Deliberate deviations

1. **List filters scope the list, not the overview.** Status, search, group, tag
   and sort change the table only; the KPIs, attention list and bands describe
   the whole result set. On a monitoring screen those top answers must not move
   because someone searched a hostname. The table says "Showing X of Y", and the
   filter chips count the current search/group/tag scope, so the numbers agree
   with what a click will show.
2. **Thresholds are the default 30 / 7 days.** The agreed interface does not
   carry `certiwatch.toml`, so the page cannot read configured thresholds. A
   later backend change can pass them and change the band edges in one place.
3. **Four kinds of sentence remain, all in notices or empty states:** stale
   results, suspect timestamps, row-check age and setup/unavailable/empty
   guidance. The skill allows empty states; the stale notice is the problem's
   action ("The scheduled check may not be running"), not an insight restating a
   number.
4. **Green is not a data state.** It appears only on the live "updated" dot, as
   in the skill's house style. Valid/active rows and chips are neutral grey;
   problems are warm or red.
5. **No in-page theme toggle.** The page follows the OS and honours
   `data-theme="light|dark"` on `<html>`; adding a toggle would need either
   JavaScript or another query parameter, and both were out of scope for this
   brief.
6. **Details use native `<details>` rows.** Each record is followed by a compact
   disclosure row (chevron on desktop, "Details" on phones). This keeps keyboard
   operation without JavaScript; the `open` query parameter opens the requested
   row for a deep link.
7. **History is capped for display.** The chart draws the last 90 snapshots and
   the "Show numbers" table the last 30; the heading counts the whole series.
8. **ISO dates are formatted for scanning.** `expires_on`, `expiry_date`,
   `issued_on` and `purchase_date` become "18 Nov 2026" when parseable; the
   original exact timestamp stays in the cell `title` and the details list.

## Data handling

* `ssl_results.json` / `domain_results.json`: `generated_at` and `results[]`.
  Rows need a safe `domain`; a row without one is counted as skipped and never
  rendered. Ports may be in `port` or in `domain:port`; they are split, shown
  separately and only a plain HTTPS host (port 443 or absent) becomes a link.
* `history.json`: `snapshots[]` with `date`, `ssl[]` and `domains[]`. Invalid
  snapshots are skipped and reported; points are sorted and deduplicated by
  date. A renewal is a days-left increase or a changed certificate fingerprint
  between consecutive snapshots, matching the existing dashboard.
* Every value from a file or the query string is HTML-escaped; attribute values
  are quoted and escaped; query values in links are percent-encoded; the only
  generated URLs come from validated hosts. There is no `<script>`, inline
  handler, `javascript:` URL or user-controlled CSS.

## Known totals

`tests/fixtures/generate_dashboard_fixtures.py` builds the fixtures and these
answers without importing the dashboard. `dashboard_expected.json` is the
machine-readable copy the tests read.

| | Certificates | Domains |
| --- | ---: | ---: |
| Total | 12 | 8 |
| Healthy | 4 | 3 |
| 8–30 days | 2 | 1 |
| ≤ 7 days (incl. today) | 3 | 2 |
| Expired | 1 | 1 |
| Issues / unknown | 2 | 1 |
| Needs attention | 8 | 5 |
| History checks | 6 | 6 |
| History peak due ≤30 d | 5 | 4 |
| Renewals | 2 | 0 |

Attention order (certificates): `eta` (expired), `zeta` (today), `epsilon`,
`mu` (≤7), `theta` (timeout), `kappa` (invalid), `delta`, `gamma` (8–30).
Domains: `zeta`, `mu`, `epsilon`, `eta`, `delta`.

## QA record

Environment: Chromium 159 headless shell (`playwright chromium-headless-shell
v1255`), device scale factor 1, system light and dark, plus a pinned dark copy
for the `data-theme` path. The built-in browser could not start in this
container (Chromium refused without a usable sandbox), so the screenshot pass
used a local headless Chromium; no page had console errors and every page had
zero `<script>` elements.

| Width | Page scrollWidth | KPI columns | Main columns | Content |
| --- | ---: | ---: | --- | ---: |
| 375 | 375 | 2 | 1 | 343 |
| 768 | 768 | 3 | 1 | 720 |
| 1024 | 1024 | 6 | 560 / 400 | 976 |
| 1440 | 1440 | 6 | 686 / 490 | 1240 |
| 1800 | 1800 | 6 | 919 / 657 | 1640 |
| 3440 | 3440 | 6 | 919 / 657 | 1640 |

Measured contrast (WCAG 2.1, normal text):

| Pair | Ratio |
| --- | ---: |
| Muted text on card (light) | 5.70 |
| Muted text on soft filter surface (light) | 5.04 |
| Amber chip text on amber tint (light) | 6.04 |
| Red chip text on red tint (light) | 5.83 |
| Muted text on card (dark) | 5.52 |
| Amber chip text on amber tint (dark) | 7.76 |
| Red chip text on red tint (dark) | 7.35 |
| Footer muted on page (light) | 5.36 |

Keyboard: the first details summary receives focus, Enter opens the row and a
second Enter closes it; tab links, pills, selects, Apply and Clear are native
focusable controls with a visible focus ring; every chart has a text copy.

Automated checks run from an isolated harness crate (serde 1, serde_json 1,
offline), because the migration crate does not exist in this checkout yet:

```text
cargo test      # 17 tests: contracts, totals, history, filters, escaping,
                # states, freshness, links, ids, folding, garbage input, no JavaScript
cargo clippy    # clean, --all-targets
```

The suite covers known totals, every attention order and issuer count, history
peak/renewals/rows, status/search/group/tag/sort, query escaping, hostile
domains and fields, missing/empty/unavailable/stale/future states, safe HTTPS
links, unique detail ids, issuer folding, singular units, garbage input, and
one `<h1>` per page.

## Not verified here

* The Rust HTTP route, JSON loading and feed routes are the backend's; this
  patch only ships the renderer.
* The static preview cannot execute a GET route, so query-driven states were
  generated as separate HTML files; link and parameter correctness is asserted
  by unit tests but the final route needs an integration test on the backend.
* No HTML validator was installed; DOM validity was checked in Chromium (no
  duplicate ids, no console errors) and by the renderer's closed-tag tests.
* Deployment, CSP headers and cache policy are unchanged by this patch.
* The built-in browser limitation above should be rechecked on a host where the
  app's browser can launch.
