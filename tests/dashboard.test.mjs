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
  assert.equal(app.sslCategory({ status: "valid", days_left: 0 }), "expired");
  assert.equal(app.sslCategory({ status: "valid", days_left: 1 }), "urgent");
  assert.equal(app.sslCategory({ status: "valid", days_left: 7 }), "urgent");
  assert.equal(app.sslCategory({ status: "valid", days_left: 8 }), "warn");
  assert.equal(app.sslCategory({ status: "valid", days_left: 30 }), "warn");
  assert.equal(app.sslCategory({ status: "valid", days_left: 31 }), "valid");
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

test("filtering, searching and sorting keep one deterministic view", () => {
  const rows = [
    app.normalizeSslRow({ domain: "far.example", status: "valid", days_left: 200, provider: "DigiCert" }),
    app.normalizeSslRow({ domain: "soon.example", status: "valid", days_left: 12, provider: "Let's Encrypt" }),
    app.normalizeSslRow({ domain: "FaceBook.com", status: "valid", days_left: 3, provider: "DigiCert" }),
    app.normalizeSslRow({ domain: "broken.example", status: "timeout", days_left: null, error: "Connection timed out" }),
    app.normalizeSslRow({ domain: "gone.example", status: "expired", days_left: -2 })
  ];

  assert.deepEqual(
    app.filterAndSort("ssl", rows, { filter: "soon", q: "", sort: "days_asc" }).map((row) => row.domain),
    ["FaceBook.com", "soon.example"]
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
    ["broken.example", "FaceBook.com", "far.example", "gone.example", "soon.example"]
  );
  assert.deepEqual(
    app.filterAndSort("ssl", rows, { filter: "all", q: "", sort: "days_asc" }).map((row) => row.domain),
    ["broken.example", "gone.example", "FaceBook.com", "soon.example", "far.example"]
  );
  assert.equal(app.matchesFilter("ssl", rows[3], "soon"), false);
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
    tab: "domain", filter: "soon", q: "face book", sort: "domain_asc"
  });
  assert.deepEqual(app.parseHashState("#domain"), {
    tab: "domain", filter: "all", q: "", sort: "days_asc"
  });
  assert.deepEqual(app.parseHashState("#filter=soon"), {
    tab: "ssl", filter: "soon", q: "", sort: "days_asc"
  });
  assert.deepEqual(app.parseHashState("#tab=ssl&filter=bogus&sort=bogus"), {
    tab: "ssl", filter: "all", q: "", sort: "days_asc"
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
