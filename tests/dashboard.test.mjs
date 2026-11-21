import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const require = createRequire(import.meta.url);
const app = require(join(root, "app.js"));

const html = readFileSync(join(root, "index.html"), "utf8");
const js = readFileSync(join(root, "app.js"), "utf8");
const css = readFileSync(join(root, "style.css"), "utf8");

test("index.html uses the split static assets and no third-party fonts", () => {
  const scriptTags = Array.from(html.matchAll(/<script\b[^>]*>/g), (match) => match[0]);
  assert.equal(scriptTags.length, 1, "exactly one external script");
  assert.match(scriptTags[0], /src="app\.js"/);
  assert.match(scriptTags[0], /\bdefer\b/);
  assert.match(html, /<link rel="stylesheet" href="style\.css"/);
  assert.doesNotMatch(html, /<style[\s>]/i);
  assert.doesNotMatch(html, /fonts\.googleapis|fonts\.gstatic/);
  assert.doesNotMatch(html, /\son[a-z]+=/i);
});

test("app.js has no HTML injection sinks and no cache-busting timestamp", () => {
  assert.doesNotMatch(js, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
  assert.doesNotMatch(js, /\?t=[\s\S]{0,40}Date\.now/);
  assert.match(js, /cache:\s*"no-cache"/);
  assert.match(js, /document\.addEventListener\("visibilitychange"/);
  assert.match(js, /setInterval\(updateFreshnessViews/);
  assert.match(js, /FUTURE_SKEW_MS/);
});

test("style.css follows the system theme and uses system fonts", () => {
  assert.match(css, /prefers-color-scheme:\s*light/);
  assert.match(css, /-apple-system/);
  assert.match(css, /ui-monospace/);
  assert.match(css, /prefers-reduced-motion/);
});

test("parseTimestamp reads legacy, ISO and epoch stamps", () => {
  const expected = Date.UTC(2026, 3, 26, 1, 10);
  assert.equal(app.parseTimestamp("2026-04-26 01:10 UTC"), expected);
  assert.equal(app.parseTimestamp("2026-04-26 01:10:00 UTC"), expected);
  assert.equal(app.parseTimestamp("2026-04-26T01:10:00Z"), expected);
  assert.equal(app.parseTimestamp("2026-04-26 01:10:00"), expected);
  assert.equal(app.parseTimestamp("2026-04-26T06:40:00+05:30"), expected);
  assert.equal(app.parseTimestamp("not a date"), null);
  assert.equal(app.parseTimestamp(null), null);
  assert.equal(app.parseTimestamp(1795249550928), 1795249550928);
  assert.equal(app.parseTimestamp("1795249550"), 1795249550000);
});

test("staleness uses a 36-hour limit and handles legacy timestamps", () => {
  const now = Date.UTC(2026, 4, 1, 0, 0);
  assert.equal(app.staleness("2026-04-30 23:00 UTC", now).stale, false);
  assert.equal(app.staleness("2026-04-29 11:00 UTC", now).stale, true); // 37 hours
  assert.equal(app.staleness("2026-04-30 12:00 UTC", now).stale, false); // exactly 36 hours
  assert.equal(app.staleness("2026-04-26 01:10 UTC", now).reason, "old");
  assert.equal(app.staleness(null, now).reason, "missing");
  assert.equal(app.staleness("2026-05-02 00:00 UTC", now).reason, "future");
  assert.equal(app.staleness(new Date(now + 30 * 1000).toISOString(), now).reason, "fresh");
  assert.equal(app.staleness(new Date(now + 2 * 60 * 1000).toISOString(), now).reason, "future");
  assert.equal(app.FUTURE_SKEW_MS, 60 * 1000);
});

test("SSL payload validation accepts good rows and reports skipped ones", () => {
  const payload = {
    generated_at: "2026-11-21 08:00 UTC",
    results: [
      { domain: "example.com", status: "valid", days_left: 12, provider: "DigiCert" },
      { domain: "", status: "valid" },
      { status: "valid" },
      "not an object"
    ]
  };
  const parsed = app.validateSslPayload(payload);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.rows.length, 1);
  assert.equal(parsed.rows[0].category, "warn");
  assert.equal(parsed.skipped, 3);
  assert.equal(parsed.generatedAt, "2026-11-21 08:00 UTC");
});

test("payload validation rejects wrong shapes instead of rendering them", () => {
  assert.equal(app.validateSslPayload([]).ok, false);
  assert.equal(app.validateSslPayload({ results: "nope" }).ok, false);
  assert.equal(app.validateSslPayload({ generated_at: "x" }).ok, false);
  assert.equal(app.validateSslPayload({ results: [{ bad: true }] }).ok, false);
  assert.equal(app.validateDomainPayload({ results: [{ domain: "example.com", status: "active" }] }).ok, true);
  assert.equal(app.validateDomainPayload({ results: [{}] }).reason, "no rows could be read");
});

test("certificate categories match the warning thresholds", () => {
  assert.equal(app.sslCategory({ status: "valid", days_left: 0 }), "today");
  assert.equal(app.sslCategory({ status: "valid", days_left: 0, is_expired: false }), "today");
  assert.equal(app.sslCategory({ status: "valid", days_left: 0, is_expired: true }), "expired");
  assert.equal(app.sslCategory({ status: "valid", days_left: 1 }), "urgent");
  assert.equal(app.sslCategory({ status: "valid", days_left: 7 }), "urgent");
  assert.equal(app.sslCategory({ status: "valid", days_left: 8 }), "warn");
  assert.equal(app.sslCategory({ status: "valid", days_left: 30 }), "warn");
  assert.equal(app.sslCategory({ status: "valid", days_left: 31 }), "valid");
  assert.equal(app.sslCategory({ status: "expired", days_left: 0 }), "expired");
  assert.equal(app.sslCategory({ status: "expired", days_left: null }), "expired");
  assert.equal(app.sslCategory({ status: "invalid", days_left: 100 }), "invalid");
  assert.equal(app.sslCategory({ status: "dns_error", days_left: null }), "error");
});

test("domain categories follow status and days left", () => {
  assert.equal(app.domainCategory({ status: "active", days_left: 3 }), "urgent");
  assert.equal(app.domainCategory({ status: "active", days_left: 20 }), "warning");
  assert.equal(app.domainCategory({ status: "active", days_left: 60 }), "active");
  assert.equal(app.domainCategory({ status: "active", days_left: 0 }), "expired");
  assert.equal(app.domainCategory({ status: "expired", days_left: -1 }), "expired");
  assert.equal(app.domainCategory({ status: "unknown", days_left: null }), "unknown");
});

test("still-valid zero-day certificates read as expires today in every view helper", () => {
  const todayRow = app.normalizeSslRow({
    domain: "today.example",
    status: "valid",
    days_left: 0,
    is_expired: false,
    not_after: "2026-11-21T18:00:00Z"
  });
  assert.equal(todayRow.category, "today");
  assert.equal(todayRow.is_expired, false);
  assert.equal(todayRow.not_after, "2026-11-21T18:00:00Z");
  assert.equal(app.expiryDaysText(todayRow), "Expires today");
  assert.equal(app.expiryStateText(todayRow), "expires today");
  assert.equal(app.matchesFilter("ssl", todayRow, "soon"), true);
  assert.equal(app.matchesFilter("ssl", todayRow, "urgent"), true);

  const expiredZero = app.normalizeSslRow({
    domain: "expired.example", status: "expired", days_left: 0, is_expired: true
  });
  assert.equal(expiredZero.category, "expired");
  assert.equal(app.expiryDaysText(expiredZero), "Expired");
  assert.equal(app.expiryStateText(expiredZero), "expired");
});

test("fallback stays a separate result and never changes the configured endpoint", () => {
  const primary = app.normalizeSslRow({
    domain: "example.com",
    status: "timeout",
    days_left: null,
    error: "Connection timed out",
    fallback: {
      domain: "www.example.com",
      status: "valid",
      days_left: 12,
      provider: "DigiCert",
      port: 443,
      is_expired: false,
      not_after: "2026-12-03T00:00:00Z"
    }
  });
  assert.equal(primary.category, "error");
  assert.equal(primary.status, "timeout");
  assert.equal(primary.error, "Connection timed out");

  const fallback = app.sslFallbackRow(primary.raw.fallback);
  assert.equal(fallback.domain, "www.example.com");
  assert.equal(fallback.status, "valid");
  assert.equal(fallback.category, "warn");
  assert.equal(fallback.port, 443);
  assert.deepEqual(
    app.filterAndSort("ssl", [primary], { filter: "all", q: "www.example", sort: "days_asc" }).map((row) => row.domain),
    ["example.com"]
  );

  assert.equal(app.sslFallbackRow(null), null);
  assert.equal(app.sslFallbackRow({ host: "www.example.com", port: 443, status: "valid" }).domain, "www.example.com");
  assert.equal(app.sslFallbackRow({ host: "www.example.com", port: 8443, status: "valid" }).domain, "www.example.com:8443");
});

test("filtering, searching and sorting keep one deterministic view", () => {
  const rows = [
    app.normalizeSslRow({ domain: "far.example", status: "valid", days_left: 200, provider: "DigiCert" }),
    app.normalizeSslRow({ domain: "soon.example", status: "valid", days_left: 12, provider: "Let's Encrypt" }),
    app.normalizeSslRow({ domain: "today.example", status: "valid", days_left: 0, is_expired: false, provider: "DigiCert" }),
    app.normalizeSslRow({ domain: "FaceBook.com", status: "valid", days_left: 3, provider: "DigiCert" }),
    app.normalizeSslRow({ domain: "broken.example", status: "timeout", days_left: null, error: "Connection timed out" }),
    app.normalizeSslRow({ domain: "gone.example", status: "expired", days_left: -2 })
  ];

  assert.deepEqual(
    app.filterAndSort("ssl", rows, { filter: "soon", q: "", sort: "days_asc" }).map((row) => row.domain),
    ["today.example", "FaceBook.com", "soon.example"]
  );
  assert.deepEqual(
    app.filterAndSort("ssl", rows, { filter: "urgent", q: "", sort: "days_asc" }).map((row) => row.domain),
    ["today.example", "FaceBook.com"]
  );
  assert.deepEqual(
    app.filterAndSort("ssl", rows, { filter: "all", q: "FACE", sort: "days_asc" }).map((row) => row.domain),
    ["FaceBook.com"]
  );
  assert.deepEqual(
    app.filterAndSort("ssl", rows, { filter: "error", q: "", sort: "days_asc" }).map((row) => row.domain),
    ["broken.example"]
  );
  assert.deepEqual(
    app.filterAndSort("ssl", rows, { filter: "all", q: "", sort: "domain_asc" }).map((row) => row.domain),
    ["broken.example", "FaceBook.com", "far.example", "gone.example", "soon.example", "today.example"]
  );
  assert.deepEqual(
    app.filterAndSort("ssl", rows, { filter: "all", q: "", sort: "days_asc" }).map((row) => row.domain),
    ["broken.example", "gone.example", "today.example", "FaceBook.com", "soon.example", "far.example"]
  );
  assert.equal(app.matchesFilter("ssl", rows[4], "soon"), false);
});

test("CSV output quotes fields and blocks spreadsheet formulas", () => {
  assert.equal(app.csvEscape("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0");
  assert.equal(app.csvEscape("+1"), "'+1");
  assert.equal(app.csvEscape("@x"), "'@x");
  assert.equal(app.csvEscape("a,b"), '"a,b"');
  assert.equal(app.csvEscape('say "hi"'), '"say ""hi"""');
  assert.equal(app.csvEscape(-5), "-5");
  assert.equal(app.csvEscape(0), "0");
  const csv = app.toCsv(["Domain", "Note"], [["example.com", "a,b"]]);
  assert.ok(csv.startsWith("\uFEFF"));
  assert.equal(csv, "\uFEFFDomain,Note\r\nexample.com,\"a,b\"\r\n");
});

test("only plain HTTPS hosts become links", () => {
  assert.equal(app.safeHttpsUrl("example.com"), "https://example.com/");
  assert.equal(app.safeHttpsUrl("example.com:8443"), "https://example.com:8443/");
  assert.equal(app.safeHttpsUrl("https://example.com"), null);
  assert.equal(app.safeHttpsUrl("javascript:alert(1)"), null);
  assert.equal(app.safeHttpsUrl("user@example.com"), null);
  assert.equal(app.safeHttpsUrl("example.com/path"), null);
  assert.equal(app.safeHttpsUrl("example .com"), null);
  assert.equal(app.safeHttpsUrl(""), null);
  assert.deepEqual(app.hostAndPort({ domain: "example.com:8443" }), { host: "example.com", port: 8443 });
  assert.deepEqual(app.hostAndPort({ domain: "example.com", port: 9443 }), { host: "example.com", port: 9443 });
});

test("URL hash state round-trips and tolerates bad values", () => {
  const hash = app.buildHashState({ tab: "domain", filter: "soon", q: "face book", sort: "domain_asc" });
  assert.equal(hash, "#tab=domain&filter=soon&q=face+book&sort=domain_asc");
  assert.deepEqual(app.parseHashState(hash), {
    tab: "domain", filter: "soon", q: "face book", sort: "domain_asc", tag: "", group: ""
  });
  assert.deepEqual(app.parseHashState("#domain"), {
    tab: "domain", filter: "all", q: "", sort: "days_asc", tag: "", group: ""
  });
  assert.deepEqual(app.parseHashState("#filter=soon"), {
    tab: "ssl", filter: "soon", q: "", sort: "days_asc", tag: "", group: ""
  });
  assert.deepEqual(app.parseHashState("#tab=ssl&filter=bogus&sort=bogus"), {
    tab: "ssl", filter: "all", q: "", sort: "days_asc", tag: "", group: ""
  });
  assert.equal(app.buildHashState({ tab: "ssl", filter: "bogus", sort: "bogus" }), "#ssl");
});

test("row normalization trims values and drops impossible ports", () => {
  const row = app.normalizeSslRow({
    domain: "  Example.COM  ",
    status: "VALID",
    days_left: "12",
    port: "70000",
    provider: "N/A"
  });
  assert.equal(row.domain, "Example.COM");
  assert.equal(row.status, "valid");
  assert.equal(row.days_left, 12);
  assert.equal(row.port, null);
  assert.equal(row.provider, "");
  assert.equal(row.category, "warn");

  assert.equal(app.normalizeSslRow({ domain: "bad host", status: "valid" }), null);
  assert.equal(app.normalizeSslRow({ domain: "javascript:alert(1)", status: "valid" }), null);
  assert.equal(app.normalizeSslRow({ domain: "example.com:70000", status: "valid" }), null);
  assert.equal(app.normalizeDomainRow({ domain: "", status: "active" }), null);
  assert.equal(app.normalizeDomainRow({ domain: "example.lk", status: "active", days_left: 10 }).category, "warning");
});

test("metadata is present for accessible tabs, status and exports", () => {
  assert.match(html, /role="tablist"/);
  assert.match(html, /role="tab"/);
  assert.match(html, /role="tabpanel"/);
  assert.match(html, /aria-selected="true"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /aria-pressed="true"/);
  assert.match(html, /for="ssl-search"/);
  assert.match(html, /for="dom-sort"/);
  assert.match(html, /id="ssl-export-csv"/);
  assert.match(html, /id="dom-export-json"/);
  assert.match(html, /id="ssl-stale"/);
  assert.match(html, /id="ssl-error"/);
  assert.match(html, /id="ssl-retry"/);
  assert.match(html, /data-f="soon"/);
});

test("optional tags and group are cleaned, deduplicated and filter the table", () => {
  const ssl = app.normalizeSslRow({
    domain: "api.example.com",
    status: "valid",
    days_left: 50,
    tags: ["prod", "Prod", "api", "", 7, null],
    group: "Platform"
  });
  assert.deepEqual(ssl.tags, ["prod", "api", "7"]);
  assert.equal(ssl.group, "Platform");
  assert.equal(app.matchesScope(ssl, "PROD", ""), true);
  assert.equal(app.matchesScope(ssl, "", "platform"), true);
  assert.equal(app.matchesScope(ssl, "staging", ""), false);
  assert.equal(app.matchesScope(ssl, "", "Finance"), false);

  const domain = app.normalizeDomainRow({ domain: "example.lk", status: "active", days_left: 60, tags: ["prod"], group: "Platform" });
  assert.deepEqual(domain.tags, ["prod"]);
  assert.equal(app.normalizeSslRow({ domain: "x.example", status: "valid", tags: "prod" }).tags.length, 0);

  const rows = [
    ssl,
    app.normalizeSslRow({ domain: "web.example.com", status: "valid", days_left: 80, tags: ["prod"], group: "Web" }),
    app.normalizeSslRow({ domain: "old.example.com", status: "valid", days_left: 90, tags: ["staging"], group: "Web" })
  ];
  assert.deepEqual(
    app.filterAndSort("ssl", rows, { filter: "all", q: "", sort: "domain_asc", tag: "prod" }).map((row) => row.domain),
    ["api.example.com", "web.example.com"]
  );
  assert.deepEqual(
    app.filterAndSort("ssl", rows, { filter: "all", q: "", sort: "domain_asc", group: "Web" }).map((row) => row.domain),
    ["old.example.com", "web.example.com"]
  );
  assert.deepEqual(
    app.filterAndSort("ssl", rows, { filter: "all", q: "platform", sort: "domain_asc" }).map((row) => row.domain),
    ["api.example.com"]
  );
});

test("scope values, options and hash state stay in sync", () => {
  assert.equal(app.scopeValue("prod", ""), "tag:prod");
  assert.equal(app.scopeValue("", "Platform"), "group:Platform");
  assert.equal(app.scopeValue("", ""), "");
  assert.deepEqual(app.parseScopeValue("tag:prod"), { tag: "prod", group: "" });
  assert.deepEqual(app.parseScopeValue("group:Platform"), { tag: "", group: "Platform" });
  assert.deepEqual(app.parseScopeValue("bogus"), { tag: "", group: "" });

  const rows = [
    { tags: ["prod", "api"], group: "Platform" },
    { tags: ["prod"], group: "Web" },
    { tags: [], group: "" }
  ];
  assert.deepEqual(app.collectScopes(rows), {
    tags: [{ name: "api", count: 1 }, { name: "prod", count: 2 }],
    groups: [{ name: "Platform", count: 1 }, { name: "Web", count: 1 }]
  });

  const tagHash = app.buildHashState({ tab: "ssl", filter: "all", q: "", sort: "days_asc", tag: "prod", group: "Platform" });
  assert.equal(tagHash, "#tag=prod");
  assert.deepEqual(app.parseHashState(tagHash), {
    tab: "ssl", filter: "all", q: "", sort: "days_asc", tag: "prod", group: ""
  });
  const groupHash = app.buildHashState({ tab: "domain", filter: "all", q: "", sort: "days_asc", tag: "", group: "Platform" });
  assert.equal(groupHash, "#tab=domain&group=Platform");
  assert.deepEqual(app.parseHashState(groupHash), {
    tab: "domain", filter: "all", q: "", sort: "days_asc", tag: "", group: "Platform"
  });
});

test("provider and registrar distribution ranks buckets and folds the tail", () => {
  const dist = app.summarizeBy([
    { provider: "A" }, { provider: "A" }, { provider: "B" }, { provider: "" }
  ], "provider", 2);
  assert.equal(dist.total, 4);
  assert.deepEqual(dist.buckets, [
    { name: "A", count: 2, share: 0.5 },
    { name: "B", count: 1, share: 0.25 },
    { name: "Other", count: 1, share: 0.25, other: true }
  ]);

  const missing = app.summarizeBy([{ registrar: "" }], "registrar");
  assert.equal(missing.total, 1);
  assert.equal(missing.buckets[0].name, "Not recorded");
  assert.equal(app.summarizeBy([], "provider").buckets.length, 0);
});

test("column header clicks use the same sort values as the select", () => {
  assert.equal(app.nextSortValue("days_asc", "days_asc", "days_desc"), "days_desc");
  assert.equal(app.nextSortValue("days_desc", "days_asc", "days_desc"), "days_asc");
  assert.equal(app.nextSortValue("days_asc", "domain_asc", ""), "domain_asc");
  assert.equal(app.nextSortValue("domain_asc", "domain_asc", ""), "domain_asc");
});

test("optional history is validated, sorted and never blocks current results", () => {
  const parsed = app.normalizeHistory({
    snapshots: [
      {
        date: "2026-11-20",
        ssl: [{ domain: "a.example", days_left: 10, status: "valid", fingerprint_sha256: "AAA" }],
        domains: [{ domain: "a.example", days_left: 20, status: "active" }]
      },
      {
        date: "2026-11-18",
        ssl: [{ domain: "a.example", days_left: 40, status: "valid", fingerprint_sha256: "BBB" }],
        domains: []
      },
      { date: "not-a-date", ssl: [] }
    ]
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.skipped, 1);
  assert.deepEqual(parsed.snapshots.map((snapshot) => snapshot.date), ["2026-11-18", "2026-11-20"]);
  assert.equal(parsed.snapshots[0].ssl[0].fingerprint_sha256, "bbb");
  assert.equal(parsed.snapshots[1].domains[0].days_left, 20);

  assert.equal(app.normalizeHistory({ snapshots: [] }).ok, true);
  assert.equal(app.normalizeHistory([]).ok, false);
  assert.equal(app.normalizeHistory({ snapshots: "nope" }).ok, false);
  assert.equal(app.normalizeHistory({ snapshots: [{ date: "bad" }] }).reason, "no snapshot had a valid date");
});

test("history series counts due-soon rows and marks renewals", () => {
  const series = app.buildHistorySeries("ssl", [
    {
      date: "2026-11-18",
      ssl: [
        { domain: "a.example", days_left: 10, status: "valid", fingerprint_sha256: "aa" },
        { domain: "b.example", days_left: 5, status: "valid", fingerprint_sha256: "bb" }
      ]
    },
    {
      date: "2026-11-19",
      ssl: [
        { domain: "a.example", days_left: 60, status: "valid", fingerprint_sha256: "aa" },
        { domain: "b.example", days_left: 4, status: "valid", fingerprint_sha256: "cc" }
      ]
    },
    {
      date: "2026-11-20",
      ssl: [
        { domain: "a.example", days_left: 59, status: "valid", fingerprint_sha256: "aa" },
        { domain: "b.example", days_left: 3, status: "valid", fingerprint_sha256: "cc" }
      ]
    }
  ]);
  assert.deepEqual(series.points.map((point) => point.dueSoon), [2, 1, 1]);
  assert.deepEqual(series.points.map((point) => point.total), [2, 2, 2]);
  assert.deepEqual(series.renewals, [
    { date: "2026-11-19", domains: ["a.example", "b.example"] }
  ]);

  const domains = app.buildHistorySeries("domain", [
    { date: "2026-11-18", domains: [{ domain: "example.lk", days_left: 5, status: "active" }] },
    { date: "2026-11-19", domains: [{ domain: "example.lk", days_left: 365, status: "active" }] }
  ]);
  assert.deepEqual(domains.renewals, [{ date: "2026-11-19", domains: ["example.lk"] }]);
});

test("sparkline geometry keeps points inside the drawing box", () => {
  const geometry = app.sparklineGeometry([
    { date: "2026-11-18", dueSoon: 0 },
    { date: "2026-11-19", dueSoon: 5 },
    { date: "2026-11-20", dueSoon: 2 }
  ], 100, 50, 10);
  assert.equal(geometry.max, 5);
  assert.equal(geometry.coords.length, 3);
  assert.equal(geometry.coords[0].x, 10);
  assert.equal(geometry.coords[2].x, 90);
  assert.equal(geometry.coords[0].y, 40);
  assert.equal(geometry.coords[1].y, 10);
  assert.ok(geometry.coords.every((coord) => coord.y >= 10 && coord.y <= 40));
  assert.match(geometry.path, /^M10 40 L50 10 L90 28$/);
  assert.deepEqual(app.sparklineGeometry([]).coords, []);
});

test("fetchJson times out a stalled body and can be retried", async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (url, options) => {
    calls += 1;
    if (calls === 1) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => new Promise((resolve, reject) => {
          const signal = options && options.signal;
          if (!signal) return;
          signal.addEventListener("abort", () => {
            const error = new Error("aborted");
            error.name = "AbortError";
            reject(error);
          }, { once: true });
        })
      });
    }
    return Promise.resolve({ ok: true, status: 200, json: async () => ({ runs: 2 }) });
  };
  try {
    await assert.rejects(app.fetchJson("history.json", 15), (error) => {
      assert.equal(error.code, "timeout");
      return true;
    });
    assert.deepEqual(await app.fetchJson("history.json", 200), { runs: 2 });
    assert.equal(calls, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("fetchJson reports HTTP failures with a retryable code", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: false, status: 404 });
  try {
    await assert.rejects(app.fetchJson("history.json"), (error) => {
      assert.equal(error.code, "http-404");
      return true;
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("new controls and optional-history surfaces are present and accessible", () => {
  assert.match(html, /id="refresh-btn"/);
  assert.match(html, /id="ssl-scope"/);
  assert.match(html, /id="dom-scope"/);
  assert.match(html, /for="ssl-scope"/);
  assert.match(html, /for="dom-scope"/);
  assert.match(html, /data-sort-field="days"/);
  assert.match(html, /data-sort-asc="days_asc"/);
  assert.match(html, /data-sort-desc="days_desc"/);
  assert.match(html, /aria-sort="none"/);
  assert.match(html, /id="ssl-dist-list"/);
  assert.match(html, /id="dom-dist-list"/);
  assert.match(html, /id="ssl-history-chart"/);
  assert.match(html, /id="dom-history-chart"/);
  assert.match(html, /id="ssl-note-action"/);
  assert.match(html, /id="dom-note-action"/);
  assert.doesNotMatch(html, /\son[a-z]+=/i);

  assert.match(css, /th\[aria-sort="ascending"\]/);
  assert.match(css, /\.sort-arrow::after/);
  assert.match(css, /\.dist-list/);
  assert.match(css, /\.spark-line/);
  assert.match(css, /\.history-table-wrap table \{ display: table; \}/);
});
