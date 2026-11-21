/* CertiWatch dashboard.
 * Static, dependency-free UI for two generated JSON result files.
 * Everything read from JSON is rendered with textContent, never as markup.
 */
(function () {
  "use strict";

  var STALE_MS = 36 * 60 * 60 * 1000;
  var FETCH_TIMEOUT_MS = 15000;
  var DEFAULT_SORT = "days_asc";
  var THEME_KEY = "certiwatch-theme";

  var ALLOWED_FILTERS = {
    ssl: ["all", "valid", "warn", "urgent", "soon", "expired", "error"],
    domain: ["all", "active", "warn", "urgent", "soon", "expired", "unknown"]
  };
  var ALLOWED_SORTS = ["days_asc", "days_desc", "domain_asc", "provider_asc", "registrar_asc", "expires_asc"];

  /* ────────────────────────────── pure helpers ────────────────────────────── */

  function isPlainObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function cleanString(value, maxLength) {
    if (typeof value === "string") {
      var text = value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").trim();
      return text.slice(0, maxLength || 500);
    }
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
    return "";
  }

  function cleanDomain(value) {
    if (typeof value !== "string") return "";
    var text = value.trim();
    if (!text || text.length > 260) return "";
    if (/[\s\u0000-\u001f\u007f]/.test(text)) return "";
    if (text.indexOf("..") !== -1) return "";
    if (!/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?(?::[0-9]{1,5})?$/.test(text)) return "";
    var portMatch = /:([0-9]{1,5})$/.exec(text);
    if (portMatch) {
      var port = Number(portMatch[1]);
      if (!Number.isInteger(port) || port < 1 || port > 65535) return "";
    }
    return text;
  }

  function toNumberOrNull(value) {
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && /^-?\d+(?:\.\d+)?$/.test(value.trim())) {
      var parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : null;
    }
    return null;
  }

  /** Parse the legacy "YYYY-MM-DD HH:MM UTC" stamp, ISO stamps and epoch values. */
  function parseTimestamp(value) {
    if (value == null) return null;
    if (typeof value === "number" && Number.isFinite(value)) {
      return value > 1e12 ? value : value * 1000;
    }
    var text = String(value).trim();
    if (!text) return null;
    if (/^\d{13}$/.test(text)) return Number(text);
    if (/^\d{10}$/.test(text)) return Number(text) * 1000;

    var legacy = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)\s*(?:UTC|GMT|Z)$/i.exec(text);
    if (legacy) {
      var time = legacy[2].length === 5 ? legacy[2] + ":00" : legacy[2];
      var legacyMs = Date.parse(legacy[1] + "T" + time + "Z");
      return Number.isFinite(legacyMs) ? legacyMs : null;
    }

    var bare = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)$/.exec(text);
    if (bare) {
      var bareTime = bare[2].length === 5 ? bare[2] + ":00" : bare[2];
      var bareMs = Date.parse(bare[1] + "T" + bareTime + "Z");
      return Number.isFinite(bareMs) ? bareMs : null;
    }

    var parsedMs = Date.parse(text);
    return Number.isFinite(parsedMs) ? parsedMs : null;
  }

  function staleness(generatedAt, nowMs) {
    var now = typeof nowMs === "number" ? nowMs : Date.now();
    var ts = parseTimestamp(generatedAt);
    if (ts == null) return { stale: true, reason: "missing", ageMs: null, ts: null };
    var ageMs = now - ts;
    if (ageMs < -60 * 60 * 1000) return { stale: false, reason: "future", ageMs: ageMs, ts: ts };
    if (ageMs > STALE_MS) return { stale: true, reason: "old", ageMs: ageMs, ts: ts };
    return { stale: false, reason: "fresh", ageMs: ageMs, ts: ts };
  }

  function formatTimestamp(ts) {
    if (ts == null) return "unknown";
    try {
      return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(ts));
    } catch (error) {
      return new Date(ts).toISOString();
    }
  }

  function describeAge(ageMs) {
    if (ageMs == null || !Number.isFinite(ageMs)) return "age unknown";
    var abs = Math.abs(ageMs);
    var minutes = Math.round(abs / 60000);
    var hours = Math.round(abs / 3600000);
    var days = Math.round(abs / 86400000);
    try {
      var relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
      var sign = ageMs < 0 ? 1 : -1;
      if (minutes < 60) return relative.format(sign * minutes, "minute");
      if (hours < 48) return relative.format(sign * hours, "hour");
      if (days < 60) return relative.format(sign * days, "day");
      if (days < 730) return relative.format(sign * Math.round(days / 30), "month");
      return relative.format(sign * Math.round(days / 365), "year");
    } catch (error) {
      return days + " days ago";
    }
  }

  /** Only build an outbound URL for a plain hostname / host:port. */
  function safeHttpsUrl(value) {
    var host = cleanDomain(value);
    if (!host) return null;
    if (!/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?(?::[0-9]{1,5})?$/.test(host)) return null;
    if (host.indexOf("..") !== -1) return null;
    var url;
    try {
      url = new URL("https://" + host);
    } catch (error) {
      return null;
    }
    if (url.protocol !== "https:" || !url.hostname) return null;
    if (url.username || url.password) return null;
    if (url.port) {
      var port = Number(url.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
    }
    return url.href;
  }

  function hostAndPort(row) {
    if (!row || typeof row.domain !== "string") return null;
    var url;
    try {
      url = new URL("https://" + row.domain);
    } catch (error) {
      return null;
    }
    if (!url.hostname) return null;
    var port = row.port;
    if (!(typeof port === "number" && Number.isInteger(port) && port >= 1 && port <= 65535)) {
      port = url.port ? Number(url.port) : 443;
    }
    return { host: url.hostname, port: port };
  }

  function sslCategory(row) {
    var status = String(row.status || "").toLowerCase();
    var days = row.days_left;
    if (status === "expired" || (status === "valid" && days != null && days <= 0)) return "expired";
    if (status === "valid") {
      if (days == null) return "valid";
      if (days <= 7) return "urgent";
      if (days <= 30) return "warn";
      return "valid";
    }
    if (status === "invalid") return "invalid";
    return "error";
  }

  function domainCategory(row) {
    var status = String(row.status || "").toLowerCase();
    var days = row.days_left;
    if (status === "expired") return "expired";
    if (status === "active" || status === "valid") {
      if (days == null) return "active";
      if (days <= 0) return "expired";
      if (days <= 7) return "urgent";
      if (days <= 30) return "warning";
      return "active";
    }
    if (status === "urgent") return "urgent";
    if (status === "warning" || status === "warn") return "warning";
    return "unknown";
  }

  function normalizeSslRow(value) {
    if (!isPlainObject(value)) return null;
    var domain = cleanDomain(value.domain);
    if (!domain) return null;
    var port = toNumberOrNull(value.port);
    if (port != null && (!Number.isInteger(port) || port < 1 || port > 65535)) port = null;
    var row = {
      domain: domain,
      port: port,
      status: cleanString(value.status, 40).toLowerCase() || "error",
      provider: cleanString(value.provider, 120),
      issued_on: cleanString(value.issued_on, 40),
      expires_on: cleanString(value.expires_on, 40),
      days_left: toNumberOrNull(value.days_left),
      error: cleanString(value.error, 400),
      checked_at: cleanString(value.checked_at, 80),
      raw: value
    };
    ["provider", "issued_on", "expires_on", "error", "checked_at"].forEach(function (key) {
      if (row[key] === "N/A" || row[key] === "n/a") row[key] = "";
    });
    row.category = sslCategory(row);
    return row;
  }

  function normalizeDomainRow(value) {
    if (!isPlainObject(value)) return null;
    var domain = cleanDomain(value.domain);
    if (!domain) return null;
    var row = {
      domain: domain,
      status: cleanString(value.status, 40).toLowerCase() || "unknown",
      registrar: cleanString(value.registrar, 120),
      purchase_date: cleanString(value.purchase_date, 40),
      expiry_date: cleanString(value.expiry_date, 40),
      days_left: toNumberOrNull(value.days_left),
      raw: value
    };
    ["registrar", "purchase_date", "expiry_date"].forEach(function (key) {
      if (row[key] === "N/A" || row[key] === "n/a") row[key] = "";
    });
    row.category = domainCategory(row);
    return row;
  }

  function validatePayload(json, kind) {
    if (!isPlainObject(json)) return { ok: false, reason: "the top level is not a JSON object" };
    if (!Array.isArray(json.results)) return { ok: false, reason: "the results list is missing" };
    var normalize = kind === "ssl" ? normalizeSslRow : normalizeDomainRow;
    var rows = [];
    var skipped = 0;
    json.results.forEach(function (item) {
      var row = normalize(item);
      if (row) rows.push(row);
      else skipped += 1;
    });
    if (rows.length === 0 && json.results.length > 0) {
      return { ok: false, reason: "no rows could be read" };
    }
    return {
      ok: true,
      rows: rows,
      skipped: skipped,
      generatedAt: cleanString(json.generated_at, 80) || null
    };
  }

  function searchText(row) {
    return [
      row.domain, row.provider, row.registrar, row.status,
      row.port == null ? "" : row.port, row.error
    ].join(" ").toLowerCase();
  }

  function matchesFilter(key, row, filter) {
    if (filter === "all" || !filter) return true;
    var category = row.category;
    if (filter === "soon") {
      return row.days_left != null && row.days_left > 0 && row.days_left <= 30;
    }
    if (key === "ssl") {
      if (filter === "valid") return category === "valid";
      if (filter === "warn") return category === "warn";
      if (filter === "urgent") return category === "urgent";
      if (filter === "expired") return category === "expired";
      if (filter === "error") return category === "error" || category === "invalid";
      return false;
    }
    if (filter === "active") return category === "active";
    if (filter === "warn") return category === "warning";
    if (filter === "urgent") return category === "urgent";
    if (filter === "expired") return category === "expired";
    if (filter === "unknown") return category === "unknown";
    return false;
  }

  function expiryValue(row) {
    var value = row.expires_on || row.expiry_date || "";
    var ts = parseTimestamp(value);
    return ts == null ? null : ts;
  }

  function sortRows(key, rows, sort) {
    var copy = rows.slice();
    var ranks = key === "ssl"
      ? { error: 0, expired: 1, urgent: 2, warn: 3, invalid: 4, valid: 5 }
      : { unknown: 0, expired: 1, urgent: 2, warning: 3, active: 4 };
    function rank(row) {
      var value = ranks[row.category];
      return value == null ? 9 : value;
    }
    copy.sort(function (a, b) {
      if (sort === "domain_asc") {
        return a.domain.localeCompare(b.domain, undefined, { sensitivity: "base" });
      }
      if (sort === "provider_asc") {
        return (a.provider || "").localeCompare(b.provider || "", undefined, { sensitivity: "base" });
      }
      if (sort === "registrar_asc") {
        return (a.registrar || "").localeCompare(b.registrar || "", undefined, { sensitivity: "base" });
      }
      if (sort === "expires_asc") {
        var ea = expiryValue(a);
        var eb = expiryValue(b);
        if (ea == null && eb == null) return a.domain.localeCompare(b.domain);
        if (ea == null) return 1;
        if (eb == null) return -1;
        return (ea - eb) || a.domain.localeCompare(b.domain);
      }
      var ra = rank(a);
      var rb = rank(b);
      if (ra !== rb) return ra - rb;
      var da = a.days_left;
      var db = b.days_left;
      if (da == null && db == null) return a.domain.localeCompare(b.domain);
      if (da == null) return -1;
      if (db == null) return 1;
      if (da !== db) return sort === "days_desc" ? db - da : da - db;
      return a.domain.localeCompare(b.domain);
    });
    return copy;
  }

  function filterAndSort(key, rows, options) {
    var opts = options || {};
    var filter = opts.filter || "all";
    var query = String(opts.q || "").trim().toLowerCase();
    var sort = opts.sort || DEFAULT_SORT;
    var result = rows.filter(function (row) { return matchesFilter(key, row, filter); });
    if (query) {
      result = result.filter(function (row) { return searchText(row).indexOf(query) !== -1; });
    }
    return sortRows(key, result, sort);
  }

  function csvEscape(value) {
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
    var text = value == null ? "" : String(value);
    if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
    if (/[",\r\n]/.test(text)) text = '"' + text.replace(/"/g, '""') + '"';
    return text;
  }

  function toCsv(headers, rows) {
    var lines = [headers].concat(rows);
    return "\uFEFF" + lines.map(function (columns) {
      return columns.map(csvEscape).join(",");
    }).join("\r\n") + "\r\n";
  }

  function buildHashState(options) {
    var opts = options || {};
    var tab = opts.tab === "domain" ? "domain" : "ssl";
    var filter = opts.filter || "all";
    var sort = opts.sort || DEFAULT_SORT;
    var query = String(opts.q || "");
    var params = new URLSearchParams();
    if (tab === "domain") params.set("tab", "domain");
    if (filter !== "all" && ALLOWED_FILTERS[tab].indexOf(filter) !== -1) params.set("filter", filter);
    if (query) params.set("q", query.slice(0, 120));
    if (sort !== DEFAULT_SORT && ALLOWED_SORTS.indexOf(sort) !== -1) params.set("sort", sort);
    var serialized = params.toString();
    return serialized ? "#" + serialized : "#" + tab;
  }

  function parseHashState(hash) {
    var result = { tab: "ssl", filter: "all", q: "", sort: DEFAULT_SORT };
    var text = String(hash || "").replace(/^#/, "");
    if (text === "ssl" || text === "domain") {
      result.tab = text;
      return result;
    }
    var params = new URLSearchParams(text);
    if (params.get("tab") === "domain") result.tab = "domain";
    var filter = params.get("filter");
    if (filter && ALLOWED_FILTERS[result.tab].indexOf(filter) !== -1) result.filter = filter;
    var query = params.get("q");
    if (query) result.q = query.trim().slice(0, 120);
    var sort = params.get("sort");
    if (sort && ALLOWED_SORTS.indexOf(sort) !== -1) result.sort = sort;
    return result;
  }

  var pureApi = {
    STALE_MS: STALE_MS,
    DEFAULT_SORT: DEFAULT_SORT,
    parseTimestamp: parseTimestamp,
    staleness: staleness,
    normalizeSslRow: normalizeSslRow,
    normalizeDomainRow: normalizeDomainRow,
    validateSslPayload: function (json) { return validatePayload(json, "ssl"); },
    validateDomainPayload: function (json) { return validatePayload(json, "domain"); },
    sslCategory: sslCategory,
    domainCategory: domainCategory,
    matchesFilter: matchesFilter,
    sortRows: sortRows,
    filterAndSort: filterAndSort,
    csvEscape: csvEscape,
    toCsv: toCsv,
    safeHttpsUrl: safeHttpsUrl,
    hostAndPort: hostAndPort,
    buildHashState: buildHashState,
    parseHashState: parseHashState
  };

  if (typeof module !== "undefined" && module.exports) module.exports = pureApi;
  if (typeof document === "undefined") return;

  /* ────────────────────────────── DOM app ────────────────────────────── */

  var DATASETS = {
    ssl: {
      key: "ssl", prefix: "ssl", file: "ssl_results.json",
      short: "certificate results", noun: "certificates",
      tabCount: "ssl-tab-count", columnCount: 7
    },
    domain: {
      key: "domain", prefix: "dom", file: "domain_results.json",
      short: "domain results", noun: "domains",
      tabCount: "dom-tab-count", columnCount: 6
    }
  };

  var state = {
    tab: "ssl",
    ssl: newDataset(),
    domain: newDataset()
  };

  function newDataset() {
    return {
      rows: [], generatedAt: null, skipped: 0,
      status: "loading", error: null,
      filter: "all", q: "", sort: DEFAULT_SORT,
      open: new Set()
    };
  }

  function byId(id) { return document.getElementById(id); }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function DataError(message) {
    this.name = "DataError";
    this.message = message;
  }
  DataError.prototype = Object.create(Error.prototype);
  DataError.prototype.constructor = DataError;

  function fetchJson(url) {
    if (typeof fetch !== "function") {
      return Promise.reject(new DataError("This browser cannot fetch the result files."));
    }
    var controller = null;
    var timer = null;
    var options = { cache: "no-cache", headers: { Accept: "application/json" } };
    if (typeof AbortController === "function") {
      controller = new AbortController();
      options.signal = controller.signal;
      timer = setTimeout(function () { controller.abort(); }, FETCH_TIMEOUT_MS);
    }
    return fetch(url, options).then(function (response) {
      if (timer) clearTimeout(timer);
      if (!response.ok) throw new DataError("The server answered HTTP " + response.status + ".");
      return response.json().catch(function () {
        throw new DataError("The file is not valid JSON.");
      });
    }, function (error) {
      if (timer) clearTimeout(timer);
      if (error && error.name === "AbortError") throw new DataError("The request timed out.");
      throw new DataError("The request failed (network error).");
    });
  }

  function loadDataset(key) {
    var ds = state[key];
    var cfg = DATASETS[key];
    ds.status = "loading";
    ds.error = null;
    renderLoading(key);
    return fetchJson(cfg.file).then(function (payload) {
      var parsed = validatePayload(payload, key);
      if (!parsed.ok) {
        throw new DataError("The file did not contain the expected list of " + cfg.noun + " (" + parsed.reason + ").");
      }
      ds.rows = parsed.rows;
      ds.generatedAt = parsed.generatedAt;
      ds.skipped = parsed.skipped;
      ds.status = "ready";
      renderPanel(key);
    }).catch(function (error) {
      ds.rows = [];
      ds.generatedAt = null;
      ds.skipped = 0;
      ds.status = "error";
      ds.error = error instanceof DataError ? error.message : "The results could not be loaded.";
      renderError(key);
    }).then(function () {
      updateGlobalAlert();
    });
  }

  /* ── theme ── */

  function currentEffectiveTheme() {
    var chosen = document.documentElement.getAttribute("data-theme");
    if (chosen === "light" || chosen === "dark") return chosen;
    try {
      return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    } catch (error) {
      return "dark";
    }
  }

  function syncThemeButton() {
    var theme = currentEffectiveTheme();
    var icon = byId("theme-icon");
    var label = byId("theme-label");
    var button = byId("theme-toggle");
    if (icon) icon.textContent = theme === "dark" ? "🌙" : "☀️";
    if (label) label.textContent = theme === "dark" ? "Dark" : "Light";
    if (button) button.setAttribute("aria-label", "Switch to " + (theme === "dark" ? "light" : "dark") + " theme");
  }

  function initTheme() {
    var saved = null;
    try { saved = window.localStorage.getItem(THEME_KEY); } catch (error) { saved = null; }
    if (saved === "light" || saved === "dark") {
      document.documentElement.setAttribute("data-theme", saved);
    }
    syncThemeButton();
    var button = byId("theme-toggle");
    if (button) {
      button.addEventListener("click", function () {
        var next = currentEffectiveTheme() === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        try { window.localStorage.setItem(THEME_KEY, next); } catch (error) { /* private mode */ }
        syncThemeButton();
      });
    }
    try {
      window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", function () {
        if (!document.documentElement.getAttribute("data-theme")) syncThemeButton();
      });
    } catch (error) { /* older browser */ }
  }

  /* ── tabs and hash state ── */

  function switchTab(name, options) {
    if (name !== "ssl" && name !== "domain") return;
    state.tab = name;
    ["ssl", "domain"].forEach(function (key) {
      var active = key === name;
      var panel = byId("panel-" + key);
      var button = byId("tab-" + key + "-btn");
      if (panel) {
        panel.hidden = !active;
        panel.classList.toggle("active", active);
      }
      if (button) {
        button.classList.toggle("active", active);
        button.setAttribute("aria-selected", active ? "true" : "false");
        button.tabIndex = active ? 0 : -1;
      }
    });
    updateHeader();
    if (options && options.focusTab) byId("tab-" + name + "-btn").focus();
    if (!options || options.write !== false) writeHash();
  }

  function writeHash() {
    var ds = state[state.tab];
    var next = buildHashState({ tab: state.tab, filter: ds.filter, q: ds.q, sort: ds.sort });
    if (window.location.hash !== next) {
      try {
        window.history.replaceState(null, "", next);
      } catch (error) {
        window.location.hash = next;
      }
    }
  }

  function syncControls(key) {
    var cfg = DATASETS[key];
    var ds = state[key];
    var search = byId(cfg.prefix + "-search");
    var sort = byId(cfg.prefix + "-sort");
    var group = byId(cfg.prefix + "-filters");
    if (search) search.value = ds.q;
    if (sort) sort.value = ds.sort;
    if (group) {
      Array.prototype.forEach.call(group.querySelectorAll("button[data-f]"), function (button) {
        var on = button.getAttribute("data-f") === ds.filter;
        button.className = "fb" + (on ? " " + (button.getAttribute("data-cls") || "on") : "");
        button.setAttribute("aria-pressed", on ? "true" : "false");
      });
    }
  }

  function applyHashState(parsed) {
    state.tab = parsed.tab;
    var ds = state[parsed.tab];
    ds.filter = parsed.filter;
    ds.q = parsed.q;
    ds.sort = parsed.sort;
    syncControls(parsed.tab);
    switchTab(parsed.tab, { write: false });
    if (ds.status === "ready") renderTable(parsed.tab);
  }

  function wireTabs() {
    var buttons = Array.prototype.slice.call(document.querySelectorAll('[role="tab"][data-tab]'));
    buttons.forEach(function (button) {
      button.addEventListener("click", function () {
        switchTab(button.getAttribute("data-tab"), { write: true });
      });
    });
    var tablist = document.querySelector(".nav-tabs");
    if (!tablist) return;
    tablist.addEventListener("keydown", function (event) {
      var current = buttons.indexOf(document.activeElement);
      if (current === -1) return;
      var next = -1;
      if (event.key === "ArrowRight") next = (current + 1) % buttons.length;
      else if (event.key === "ArrowLeft") next = (current - 1 + buttons.length) % buttons.length;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = buttons.length - 1;
      else return;
      event.preventDefault();
      switchTab(buttons[next].getAttribute("data-tab"), { write: true, focusTab: true });
    });
  }

  /* ── rendering ── */

  function statCard(className, label, value, sub) {
    var card = el("div", "stat-card " + className);
    card.append(el("div", "stat-lbl", label), el("div", "stat-val", String(value)));
    if (sub) card.append(el("div", "stat-sub", sub));
    return card;
  }

  function countCategory(rows, category) {
    return rows.reduce(function (total, row) {
      return total + (row.category === category ? 1 : 0);
    }, 0);
  }

  function renderStats(key) {
    var ds = state[key];
    var cfg = DATASETS[key];
    var container = byId(cfg.prefix + "-stats");
    if (!container) return;
    container.hidden = false;
    var cards;
    if (key === "ssl") {
      var issues = countCategory(ds.rows, "error") + countCategory(ds.rows, "invalid");
      cards = [
        statCard("sc-total", "Total", ds.rows.length, "monitored"),
        statCard("sc-ok", "Valid", countCategory(ds.rows, "valid"), "> 30 days left"),
        statCard("sc-warn", "Warning", countCategory(ds.rows, "warn"), "8–30 days left"),
        statCard("sc-urgent", "Urgent", countCategory(ds.rows, "urgent"), "≤ 7 days left"),
        statCard("sc-exp", "Expired", countCategory(ds.rows, "expired"), "action needed"),
        statCard("sc-err", "Issues", issues, "invalid or unreachable")
      ];
      container.setAttribute("aria-label", "Certificate summary: " + ds.rows.length + " monitored, " +
        countCategory(ds.rows, "expired") + " expired, " + issues + " with errors");
    } else {
      cards = [
        statCard("sc-total", "Total", ds.rows.length, "monitored"),
        statCard("sc-ok", "Active", countCategory(ds.rows, "active"), "> 30 days left"),
        statCard("sc-warn", "Warning", countCategory(ds.rows, "warning"), "8–30 days left"),
        statCard("sc-urgent", "Urgent", countCategory(ds.rows, "urgent"), "≤ 7 days left"),
        statCard("sc-exp", "Expired", countCategory(ds.rows, "expired"), "action needed"),
        statCard("sc-err", "Unknown", countCategory(ds.rows, "unknown"), "lookup failed")
      ];
      container.setAttribute("aria-label", "Domain summary: " + ds.rows.length + " monitored, " +
        countCategory(ds.rows, "expired") + " expired, " + countCategory(ds.rows, "unknown") + " unknown");
    }
    container.replaceChildren.apply(container, cards);
  }

  function skeletonCards(count) {
    var cards = [];
    for (var index = 0; index < count; index += 1) {
      var card = el("div", "stat-card skeleton-card");
      card.setAttribute("aria-hidden", "true");
      card.append(el("span", "skeleton-line short"), el("span", "skeleton-line tall"));
      cards.push(card);
    }
    return cards;
  }

  function setSkeletonRows(key) {
    var cfg = DATASETS[key];
    var body = byId(cfg.prefix + "-tbody");
    if (!body) return;
    body.replaceChildren();
    for (var index = 0; index < 4; index += 1) {
      var row = el("tr", "skeleton-row");
      row.setAttribute("aria-hidden", "true");
      var cell = el("td");
      cell.colSpan = cfg.columnCount;
      cell.append(el("span", "skeleton-line"));
      row.append(cell);
      body.append(row);
    }
  }

  function renderTimelineEmpty(key, message) {
    var cfg = DATASETS[key];
    var container = byId(cfg.prefix + "-timeline");
    var legend = byId(cfg.prefix + "-timeline-legend");
    var summary = byId(cfg.prefix + "-timeline-summary");
    if (container) {
      container.replaceChildren();
      container.setAttribute("aria-label", message);
    }
    if (legend) legend.replaceChildren();
    if (summary) summary.textContent = message;
  }

  function setControlsEnabled(key, enabled) {
    var prefix = DATASETS[key].prefix;
    var search = byId(prefix + "-search");
    var sort = byId(prefix + "-sort");
    var group = byId(prefix + "-filters");
    if (search) search.disabled = !enabled;
    if (sort) sort.disabled = !enabled;
    if (group) {
      Array.prototype.forEach.call(group.querySelectorAll("button[data-f]"), function (button) {
        button.disabled = !enabled;
      });
    }
  }

  function renderLoading(key) {
    var cfg = DATASETS[key];
    var prefix = cfg.prefix;
    var panel = byId("panel-" + key);
    if (panel) panel.setAttribute("aria-busy", "true");
    setControlsEnabled(key, false);
    var stats = byId(prefix + "-stats");
    if (stats) {
      stats.hidden = false;
      stats.replaceChildren.apply(stats, skeletonCards(6));
      stats.setAttribute("aria-label", "Loading " + cfg.noun + " summary");
    }
    [prefix + "-stale", prefix + "-error", prefix + "-note", prefix + "-attention"].forEach(function (id) {
      var node = byId(id);
      if (node) node.hidden = true;
    });
    renderTimelineEmpty(key, "Loading…");
    setSkeletonRows(key);
    var noRows = byId(prefix + "-norows");
    if (noRows) noRows.hidden = true;
    var status = byId(prefix + "-status");
    if (status) status.textContent = "Loading " + cfg.noun + "…";
    var count = byId(cfg.tabCount);
    if (count) count.textContent = "—";
    updateExportState();
    updateHeader();
  }

  function renderError(key) {
    var cfg = DATASETS[key];
    var prefix = cfg.prefix;
    var ds = state[key];
    var panel = byId("panel-" + key);
    if (panel) panel.setAttribute("aria-busy", "false");
    setControlsEnabled(key, false);
    var stats = byId(prefix + "-stats");
    if (stats) {
      stats.replaceChildren();
      stats.hidden = true;
    }
    var stale = byId(prefix + "-stale");
    if (stale) stale.hidden = true;
    var errorBox = byId(prefix + "-error");
    var errorText = byId(prefix + "-error-text");
    if (errorBox) errorBox.hidden = false;
    if (errorText) errorText.textContent = "The " + cfg.noun + " could not be loaded. " + (ds.error || "Unknown error.") + " The rest of the page is still usable.";
    var note = byId(prefix + "-note");
    if (note) note.hidden = true;
    var attention = byId(prefix + "-attention");
    if (attention) attention.hidden = true;
    renderTimelineEmpty(key, "Unavailable");
    var body = byId(prefix + "-tbody");
    if (body) body.replaceChildren();
    var noRows = byId(prefix + "-norows");
    if (noRows) {
      noRows.hidden = false;
      noRows.textContent = "Results are unavailable.";
    }
    var status = byId(prefix + "-status");
    if (status) status.textContent = "The " + cfg.noun + " are unavailable.";
    var count = byId(cfg.tabCount);
    if (count) count.textContent = "—";
    updateExportState();
    updateHeader();
  }

  function countOldChecks(rows) {
    var now = Date.now();
    return rows.reduce(function (total, row) {
      var ts = parseTimestamp(row.checked_at);
      return total + (ts != null && now - ts > STALE_MS ? 1 : 0);
    }, 0);
  }

  function renderStale(key) {
    var cfg = DATASETS[key];
    var ds = state[key];
    var box = byId(cfg.prefix + "-stale");
    var text = byId(cfg.prefix + "-stale-text");
    if (!box || !text) return;
    if (ds.status !== "ready") {
      box.hidden = true;
      return;
    }
    var info = staleness(ds.generatedAt);
    var oldChecks = countOldChecks(ds.rows);
    if (info.reason === "fresh" && oldChecks === 0) {
      box.hidden = true;
      return;
    }
    var message;
    if (info.reason === "missing") {
      message = "These results do not include a readable generated time, so their freshness cannot be confirmed.";
    } else if (info.reason === "future") {
      message = "The generated time is in the future (" + formatTimestamp(info.ts) + "). Check the clock on the machine that ran the check.";
    } else if (info.reason === "fresh") {
      message = oldChecks + " row check" + (oldChecks === 1 ? " is" : "s are") + " older than 36 hours, even though the file was generated recently.";
    } else {
      message = "Results are stale: last generated " + formatTimestamp(info.ts) + " (" + describeAge(info.ageMs) + "), beyond the 36-hour limit. The scheduled check may not be running.";
      if (oldChecks > 0) {
        message += " " + oldChecks + " row check" + (oldChecks === 1 ? " is" : "s are") + " also older than 36 hours.";
      }
    }
    box.hidden = false;
    text.textContent = message;
  }

  function statusLabel(key, row) {
    var category = row.category;
    if (key === "ssl") {
      if (category === "valid") return "Valid";
      if (category === "warn") return "Warning";
      if (category === "urgent") return "Urgent";
      if (category === "expired") return "Expired";
      if (category === "invalid") return "Invalid";
      var labels = {
        dns_error: "DNS error", timeout: "Timeout", ssl_error: "SSL error",
        no_https: "No HTTPS", error: "Error"
      };
      return labels[row.status] || "Error";
    }
    if (category === "active") return "Active";
    if (category === "warning") return "Warning";
    if (category === "urgent") return "Urgent";
    if (category === "expired") return "Expired";
    return "Unknown";
  }

  function badgeFor(key, row) {
    var category = row.category;
    var cls;
    var icon;
    if (key === "ssl") {
      if (category === "valid") { cls = "b-green"; icon = "✓"; }
      else if (category === "warn") { cls = "b-yellow"; icon = "⚠"; }
      else if (category === "urgent") { cls = "b-orange"; icon = "⚡"; }
      else if (category === "expired") { cls = "b-red"; icon = "✗"; }
      else if (category === "invalid") { cls = "b-yellow"; icon = "⚠"; }
      else { cls = "b-gray"; icon = "—"; }
    } else {
      if (category === "active") { cls = "b-green"; icon = "✓"; }
      else if (category === "warning") { cls = "b-yellow"; icon = "⚠"; }
      else if (category === "urgent") { cls = "b-orange"; icon = "⚡"; }
      else if (category === "expired") { cls = "b-red"; icon = "✗"; }
      else { cls = "b-gray"; icon = "—"; }
    }
    var badge = el("span", "badge " + cls);
    var iconNode = el("span", "badge-icon", icon);
    iconNode.setAttribute("aria-hidden", "true");
    badge.append(iconNode, document.createTextNode(statusLabel(key, row)));
    if (row.error) badge.title = row.error;
    return badge;
  }

  function daysSentence(row) {
    if (row.category === "error" || row.category === "invalid" || row.category === "unknown") {
      return "No expiry data";
    }
    if (row.days_left == null) return "No expiry data";
    if (row.days_left <= 0) return "Expired";
    return row.days_left + "d left";
  }

  function attentionScore(key, category) {
    var ssl = { expired: 0, urgent: 1, error: 2, invalid: 3, warn: 4 };
    var domain = { expired: 0, urgent: 1, unknown: 2, warning: 3 };
    var table = key === "ssl" ? ssl : domain;
    var score = table[category];
    return score == null ? 99 : score;
  }

  function renderAttention(key) {
    var cfg = DATASETS[key];
    var ds = state[key];
    var card = byId(cfg.prefix + "-attention");
    var list = byId(cfg.prefix + "-attention-list");
    var summary = byId(cfg.prefix + "-attention-summary");
    if (!card || !list || !summary) return;
    var rows = ds.rows.filter(function (row) {
      return attentionScore(key, row.category) < 99;
    }).sort(function (a, b) {
      var scoreDiff = attentionScore(key, a.category) - attentionScore(key, b.category);
      if (scoreDiff !== 0) return scoreDiff;
      return (a.days_left == null ? 999999 : a.days_left) - (b.days_left == null ? 999999 : b.days_left);
    });
    card.hidden = false;
    card.classList.toggle("is-ok", rows.length === 0);
    list.replaceChildren();
    if (rows.length === 0) {
      summary.textContent = "Nothing needs attention right now.";
      return;
    }
    summary.textContent = rows.length + (rows.length === 1 ? " item needs attention" : " items need attention");
    rows.slice(0, 6).forEach(function (row) {
      var item = el("li", "attention-item");
      item.append(badgeFor(key, row));
      item.append(el("span", "attention-domain", row.domain));
      item.append(el("span", "attention-days", daysSentence(row)));
      list.append(item);
    });
    if (rows.length > 6) list.append(el("li", "attention-more", "+" + (rows.length - 6) + " more"));
  }

  function renderTimeline(key) {
    var cfg = DATASETS[key];
    var ds = state[key];
    var container = byId(cfg.prefix + "-timeline");
    var legend = byId(cfg.prefix + "-timeline-legend");
    var summary = byId(cfg.prefix + "-timeline-summary");
    if (!container || !legend || !summary) return;
    var buckets = [
      { id: "expired", label: "Expired", cls: "seg-expired", match: function (d) { return d != null && d <= 0; } },
      { id: "d7", label: "≤ 7 days", cls: "seg-d7", match: function (d) { return d != null && d > 0 && d <= 7; } },
      { id: "d30", label: "8–30 days", cls: "seg-d30", match: function (d) { return d != null && d > 7 && d <= 30; } },
      { id: "d90", label: "31–90 days", cls: "seg-d90", match: function (d) { return d != null && d > 30 && d <= 90; } },
      { id: "d365", label: "91–365 days", cls: "seg-d365", match: function (d) { return d != null && d > 90 && d <= 365; } },
      { id: "later", label: "> 365 days", cls: "seg-later", match: function (d) { return d != null && d > 365; } },
      { id: "unknown", label: "No date", cls: "seg-unknown", match: function (d) { return d == null; } }
    ];
    var counts = {};
    buckets.forEach(function (bucket) { counts[bucket.id] = 0; });
    ds.rows.forEach(function (row) {
      for (var index = 0; index < buckets.length; index += 1) {
        if (buckets[index].match(row.days_left)) {
          counts[buckets[index].id] += 1;
          return;
        }
      }
    });
    var total = ds.rows.length;
    container.replaceChildren();
    legend.replaceChildren();
    buckets.forEach(function (bucket) {
      var count = counts[bucket.id];
      var item = el("li");
      var dot = el("span", "legend-dot " + bucket.cls);
      dot.setAttribute("aria-hidden", "true");
      item.append(dot, el("span", null, bucket.label), el("span", "legend-count", String(count)));
      legend.append(item);
      if (count > 0 && total > 0) {
        var segment = el("div", "timeline-seg " + bucket.cls);
        segment.style.width = (count / total * 100).toFixed(3) + "%";
        segment.title = bucket.label + ": " + count;
        container.append(segment);
      }
    });
    var due = counts.d7 + counts.d30;
    var parts = [];
    if (total === 0) {
      parts.push("No expiry data available.");
    } else {
      if (due > 0) parts.push(due + " due within 30 days");
      if (counts.expired > 0) parts.push(counts.expired + " expired");
      if (counts.unknown > 0) parts.push(counts.unknown + " without expiry data");
      if (parts.length === 0) parts.push("Nothing expires within 30 days");
    }
    summary.textContent = parts.join(" · ");
    container.setAttribute("aria-label", cfg.noun + " expiry timeline: " + buckets.map(function (bucket) {
      return bucket.label + " " + counts[bucket.id];
    }).join(", "));
  }

  function providerMeta(kind, name) {
    var providers = {
      "Let's Encrypt": { cls: "p-green", ab: "LE" },
      "Cloudflare SSL": { cls: "p-orange", ab: "CF" },
      "Sectigo / Comodo": { cls: "p-blue", ab: "SC" },
      "DigiCert": { cls: "p-purple", ab: "DC" },
      "GeoTrust": { cls: "p-blue", ab: "GT" },
      "GlobalSign": { cls: "p-purple", ab: "GS" },
      "GoDaddy": { cls: "p-green", ab: "GD" },
      "Amazon / AWS": { cls: "p-orange", ab: "AW" },
      "ZeroSSL": { cls: "p-gray", ab: "ZS" }
    };
    var registrars = {
      "GoDaddy": { cls: "p-green", ab: "GD" },
      "domains.lk": { cls: "p-blue", ab: "DL" },
      "Namecheap": { cls: "p-orange", ab: "NC" },
      "Hostpoint": { cls: "p-purple", ab: "HP" },
      "Cloudflare": { cls: "p-orange", ab: "CF" },
      "MarkMonitor Inc.": { cls: "p-blue", ab: "MM" },
      "CSC Corporate Domains, Inc.": { cls: "p-purple", ab: "CS" },
      "RegistrarSafe, LLC": { cls: "p-green", ab: "RS" }
    };
    var map = kind === "ssl" ? providers : registrars;
    if (map[name]) return map[name];
    return { cls: "p-gray", ab: initials(name) };
  }

  function initials(name) {
    var words = String(name || "").replace(/[^A-Za-z0-9]+/g, " ").trim().split(/\s+/).filter(Boolean);
    if (!words.length) return "?";
    return (words[0].charAt(0) + (words.length > 1 ? words[1].charAt(0) : "")).toUpperCase();
  }

  function toneForDays(days) {
    if (days == null) return "tone-gray";
    if (days <= 0) return "tone-red";
    if (days <= 7) return "tone-orange";
    if (days <= 30) return "tone-yellow";
    return "tone-green";
  }

  function buildDays(days) {
    var wrap = el("div", "bar-wrap");
    if (days == null) {
      wrap.append(el("span", "tone-gray", "N/A"));
      wrap.setAttribute("aria-label", "Days left not available");
      return wrap;
    }
    var percent = Math.max(0, Math.min(100, (Math.max(0, days) / 365) * 100));
    var bar = el("div", "bar");
    var fill = el("div", "bar-fill " + toneForDays(days));
    fill.style.width = percent.toFixed(2) + "%";
    bar.append(fill);
    var tone = toneForDays(days);
    wrap.append(bar, el("span", "bar-num " + tone, days + "d"));
    wrap.setAttribute("aria-label", days <= 0 ? "Expired " + Math.abs(days) + " days ago" : days + " days left");
    return wrap;
  }

  function makeCell(label, className) {
    var cell = el("td", className || "");
    cell.setAttribute("data-label", label);
    cell.setAttribute("role", "cell");
    return cell;
  }

  function buildRow(key, row, index) {
    var cfg = DATASETS[key];
    var prefix = cfg.prefix;
    var detailId = prefix + "-detail-" + index;
    var open = state[key].open.has(row.domain + "|" + (row.port == null ? "" : row.port));
    var tr = el("tr", "row");
    tr.setAttribute("role", "row");
    tr.setAttribute("data-status", row.category);

    var domainCell = makeCell("Domain", "cell-domain");
    var url = safeHttpsUrl(row.domain);
    if (url) {
      var link = el("a", null, row.domain);
      link.href = url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.title = "Open " + row.domain + " in a new tab";
      domainCell.append(link);
    } else {
      domainCell.append(document.createTextNode(row.domain));
    }

    var providerLabel = key === "ssl" ? "Provider" : "Registrar";
    var providerCell = makeCell(providerLabel);
    var name = key === "ssl" ? row.provider : row.registrar;
    if (name) {
      var meta = providerMeta(key, name);
      var pill = el("span", "pi " + meta.cls, meta.ab);
      pill.setAttribute("aria-hidden", "true");
      providerCell.append(pill, document.createTextNode(name));
    } else {
      providerCell.append(document.createTextNode("—"));
    }

    var dateCell;
    var daysCell = makeCell("Days Left");
    daysCell.append(buildDays(row.days_left));
    var statusCell = makeCell("Status");
    statusCell.append(badgeFor(key, row));
    var detailCell = makeCell("Details", "cell-details");

    var toggle = el("button", "row-toggle");
    toggle.type = "button";
    toggle.setAttribute("data-row-key", row.domain + "|" + (row.port == null ? "" : row.port));
    toggle.setAttribute("data-domain", row.domain);
    toggle.setAttribute("aria-controls", detailId);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    toggle.setAttribute("aria-label", (open ? "Hide" : "Show") + " details for " + row.domain);
    toggle.title = (open ? "Hide" : "Show") + " details";
    var chevron = el("span", "chevron", "⌄");
    chevron.setAttribute("aria-hidden", "true");
    toggle.append(chevron);
    detailCell.append(toggle);

    if (key === "ssl") {
      tr.append(domainCell, providerCell);
      var issuedCell = makeCell("Issued On", "cell-muted");
      issuedCell.append(document.createTextNode(row.issued_on || "—"));
      dateCell = makeCell("Expires On", "cell-muted");
      dateCell.append(document.createTextNode(row.expires_on || "—"));
      tr.append(issuedCell, dateCell, daysCell, statusCell, detailCell);
    } else {
      tr.append(domainCell, providerCell);
      dateCell = makeCell("Expiry Date", "cell-muted");
      dateCell.append(document.createTextNode(row.expiry_date || "—"));
      tr.append(dateCell, daysCell, statusCell, detailCell);
    }

    return { row: tr, detail: buildDetailRow(key, row, detailId, open), id: detailId };
  }

  function formatOptional(value) {
    if (value == null) return "";
    if (typeof value === "boolean") return value ? "Yes" : "No";
    if (Array.isArray(value)) {
      return value.map(function (item) {
        return typeof item === "string" ? item : String(item);
      }).filter(Boolean).join(", ").slice(0, 600);
    }
    if (typeof value === "object") {
      try {
        var keys = Object.keys(value);
        if (!keys.length || keys.length > 8) return "";
        return keys.map(function (key) { return key + ": " + value[key]; }).join("; ").slice(0, 600);
      } catch (error) {
        return "";
      }
    }
    var text = String(value).trim();
    if (!text || text === "N/A") return "";
    return text.slice(0, 600);
  }

  var SSL_OPTIONAL_FIELDS = [
    ["subject", "Subject"], ["issuer", "Issuer"],
    ["serial_number", "Serial number"], ["serial", "Serial number"],
    ["signature_algorithm", "Signature algorithm"],
    ["key_type", "Key type"], ["key_size", "Key size"], ["key_algorithm", "Key algorithm"],
    ["tls_version", "TLS version"],
    ["subject_alt_names", "Subject alternative names"], ["sans", "Subject alternative names"], ["san", "Subject alternative names"],
    ["chain", "Certificate chain"], ["chain_valid", "Chain valid"], ["chain_length", "Chain length"],
    ["fingerprint_sha256", "SHA-256 fingerprint"], ["fingerprint", "Fingerprint"],
    ["ocsp_status", "OCSP status"], ["resolved_via", "Resolved via"]
  ];

  var DOMAIN_OPTIONAL_FIELDS = [
    ["nameservers", "Nameservers"], ["dnssec", "DNSSEC"], ["caa", "CAA records"],
    ["owner", "Owner"], ["tags", "Tags"], ["notes", "Notes"], ["checked_at", "Checked at"]
  ];

  function appendOptionalPairs(pairs, raw, fields) {
    if (!isPlainObject(raw)) return;
    var seen = {};
    fields.forEach(function (entry) {
      var key = entry[0];
      var label = entry[1];
      if (seen[label]) return;
      if (!Object.prototype.hasOwnProperty.call(raw, key)) return;
      var value = formatOptional(raw[key]);
      if (!value) return;
      seen[label] = true;
      pairs.push([label, value]);
    });
  }

  function detailPairs(key, row) {
    var pairs = [];
    pairs.push(["Status", statusLabel(key, row)]);
    if (key === "ssl") {
      pairs.push(["Provider", row.provider || "Not available"]);
      pairs.push(["Issued on", row.issued_on || "Not available"]);
      pairs.push(["Expires on", row.expires_on || "Not available"]);
      pairs.push(["Days left", row.days_left == null ? "Not available" : String(row.days_left)]);
      var target = hostAndPort(row);
      pairs.push(["Port", target ? String(target.port) : "Not available"]);
      pairs.push(["Checked at", row.checked_at || "Not recorded"]);
      appendOptionalPairs(pairs, row.raw, SSL_OPTIONAL_FIELDS);
      if (row.error) pairs.push(["Error", row.error]);
    } else {
      pairs.push(["Registrar", row.registrar || "Not available"]);
      pairs.push(["Purchase date", row.purchase_date || "Not available"]);
      pairs.push(["Expiry date", row.expiry_date || "Not available"]);
      pairs.push(["Days left", row.days_left == null ? "Not available" : String(row.days_left)]);
      appendOptionalPairs(pairs, row.raw, DOMAIN_OPTIONAL_FIELDS);
    }
    return pairs;
  }

  function opensslCommand(row) {
    var target = hostAndPort(row);
    if (!target) return "";
    return "openssl s_client -connect " + target.host + ":" + target.port +
      " -servername " + target.host +
      " -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256";
  }

  function buildDetailRow(key, row, detailId, open) {
    var cfg = DATASETS[key];
    var tr = el("tr", "detail-row");
    tr.id = detailId;
    tr.hidden = !open;
    tr.setAttribute("role", "row");
    var cell = el("td");
    cell.colSpan = cfg.columnCount;
    cell.setAttribute("role", "cell");
    var panel = el("div", "detail-panel");
    panel.append(el("h3", null, key === "ssl" ? "Certificate details" : "Domain details"));
    var list = el("dl", "detail-grid");
    detailPairs(key, row).forEach(function (pair) {
      var item = el("div", "detail-item");
      item.append(el("dt", null, pair[0]), el("dd", null, pair[1]));
      list.append(item);
    });
    panel.append(list);
    if (key === "ssl") {
      var command = opensslCommand(row);
      if (command) {
        var box = el("div", "detail-command");
        var head = el("div", "detail-command-head");
        head.append(el("span", null, "OpenSSL check"));
        var copy = el("button", "copy-btn", "Copy command");
        copy.type = "button";
        copy.setAttribute("data-copy", command);
        copy.setAttribute("data-status-id", detailId + "-copy");
        head.append(copy);
        box.append(head, el("code", null, command));
        panel.append(box);
        var copyStatus = el("span", "copy-status");
        copyStatus.id = detailId + "-copy";
        copyStatus.setAttribute("role", "status");
        copyStatus.setAttribute("aria-live", "polite");
        panel.append(copyStatus);
      }
    }
    cell.append(panel);
    tr.append(cell);
    return tr;
  }

  function filterLabel(key, filter) {
    var labels = key === "ssl"
      ? { valid: "valid", warn: "8–30 days", urgent: "≤ 7 days", soon: "next 30 days", expired: "expired", error: "errors" }
      : { active: "active", warn: "8–30 days", urgent: "≤ 7 days", soon: "next 30 days", expired: "expired", unknown: "unknown" };
    return labels[filter] || "";
  }

  function renderTable(key) {
    var cfg = DATASETS[key];
    var ds = state[key];
    if (ds.status !== "ready") return;
    var body = byId(cfg.prefix + "-tbody");
    var noRows = byId(cfg.prefix + "-norows");
    var status = byId(cfg.prefix + "-status");
    if (!body) return;
    var rows = filterAndSort(key, ds.rows, { filter: ds.filter, q: ds.q, sort: ds.sort });
    body.replaceChildren();
    rows.forEach(function (row, index) {
      var built = buildRow(key, row, index);
      body.append(built.row, built.detail);
    });
    if (noRows) {
      noRows.hidden = rows.length > 0;
      noRows.textContent = ds.rows.length === 0
        ? "No " + cfg.noun + " are available in this result file."
        : "No results match this search or filter.";
    }
    if (status) {
      var pieces = ["Showing " + rows.length + " of " + ds.rows.length + " " + cfg.noun];
      var label = filterLabel(key, ds.filter);
      if (label) pieces.push(label);
      var query = ds.q.trim();
      if (query) pieces.push("search “" + query.slice(0, 80) + "”");
      status.textContent = pieces.join(" · ");
    }
    var count = byId(cfg.tabCount);
    if (count) count.textContent = String(ds.rows.length);
    updateExportState();
  }

  function renderNote(key) {
    var cfg = DATASETS[key];
    var ds = state[key];
    var box = byId(cfg.prefix + "-note");
    var text = byId(cfg.prefix + "-note-text");
    if (!box || !text) return;
    if (ds.status !== "ready" || !ds.skipped) {
      box.hidden = true;
      return;
    }
    box.hidden = false;
    text.textContent = ds.skipped + " row" + (ds.skipped === 1 ? "" : "s") +
      " in this result file could not be read and " + (ds.skipped === 1 ? "was" : "were") + " skipped.";
  }

  function renderPanel(key) {
    var panel = byId("panel-" + key);
    if (panel) panel.setAttribute("aria-busy", "false");
    setControlsEnabled(key, true);
    renderStats(key);
    renderStale(key);
    renderAttention(key);
    renderTimeline(key);
    renderTable(key);
    renderNote(key);
    updateExportState();
    updateHeader();
  }

  function updateExportState() {
    ["ssl", "domain"].forEach(function (key) {
      var cfg = DATASETS[key];
      var enabled = state[key].status === "ready";
      ["-export-csv", "-export-json"].forEach(function (suffix) {
        var button = byId(cfg.prefix + suffix);
        if (button) button.disabled = !enabled;
      });
    });
  }

  function updateHeader() {
    var text = byId("last-updated");
    var dot = byId("live-dot");
    if (!text || !dot) return;
    var ds = state[state.tab];
    dot.classList.remove("stale");
    text.removeAttribute("title");
    if (ds.status === "loading") {
      text.textContent = "Loading…";
      return;
    }
    if (ds.status === "error") {
      text.textContent = "Unavailable";
      dot.classList.add("stale");
      return;
    }
    if (!ds.generatedAt) {
      text.textContent = "Updated —";
      text.title = "The results do not include a generated timestamp.";
      dot.classList.add("stale");
      return;
    }
    var info = staleness(ds.generatedAt);
    text.textContent = "Updated " + formatTimestamp(info.ts);
    text.title = "Generated: " + ds.generatedAt;
    if (info.reason !== "fresh" || countOldChecks(ds.rows) > 0) dot.classList.add("stale");
  }

  function updateGlobalAlert() {
    var node = byId("global-alert");
    var text = byId("global-alert-text");
    if (!node || !text) return;
    var failed = ["ssl", "domain"].filter(function (key) {
      return state[key].status === "error";
    });
    if (!failed.length) {
      node.hidden = true;
      text.textContent = "";
      return;
    }
    node.hidden = false;
    if (failed.length === 2) {
      text.textContent = "No results could be loaded: both result files failed. The panels below show what went wrong.";
    } else {
      text.textContent = "Showing partial data: the " + DATASETS[failed[0]].short +
        " could not be loaded. The other panel is still available.";
    }
  }

  /* ── exports and details ── */

  function pad2(value) { return value < 10 ? "0" + value : String(value); }

  function datedName(kind, extension) {
    var now = new Date();
    return "certiwatch-" + kind + "-" + now.getFullYear() + "-" + pad2(now.getMonth() + 1) + "-" + pad2(now.getDate()) + "." + extension;
  }

  function downloadText(filename, mimeType, text) {
    var blob = new Blob([text], { type: mimeType });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function exportCsv(key) {
    var ds = state[key];
    if (ds.status !== "ready") return;
    var rows = filterAndSort(key, ds.rows, { filter: ds.filter, q: ds.q, sort: ds.sort });
    var headers;
    var matrix;
    if (key === "ssl") {
      headers = ["Domain", "Port", "Status", "Provider", "Issued On", "Expires On", "Days Left", "Checked At", "Error"];
      matrix = rows.map(function (row) {
        return [row.domain, row.port == null ? "" : row.port, row.status, row.provider,
          row.issued_on, row.expires_on, row.days_left == null ? "" : row.days_left, row.checked_at, row.error];
      });
    } else {
      headers = ["Domain", "Status", "Registrar", "Purchase Date", "Expiry Date", "Days Left"];
      matrix = rows.map(function (row) {
        return [row.domain, row.status, row.registrar, row.purchase_date, row.expiry_date,
          row.days_left == null ? "" : row.days_left];
      });
    }
    downloadText(datedName(key, "csv"), "text/csv;charset=utf-8", toCsv(headers, matrix));
  }

  function exportJson(key) {
    var ds = state[key];
    if (ds.status !== "ready") return;
    var rows = filterAndSort(key, ds.rows, { filter: ds.filter, q: ds.q, sort: ds.sort });
    var payload = {
      generated_at: ds.generatedAt,
      exported_at: new Date().toISOString(),
      source: DATASETS[key].file,
      filters: { filter: ds.filter, search: ds.q, sort: ds.sort },
      count: rows.length,
      results: rows.map(function (row) { return row.raw; })
    };
    downloadText(datedName(key, "json"), "application/json;charset=utf-8", JSON.stringify(payload, null, 2));
  }

  function copyText(text) {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.top = "-1000px";
      document.body.append(area);
      area.select();
      var copied = false;
      try { copied = document.execCommand("copy"); } catch (error) { copied = false; }
      area.remove();
      if (copied) resolve();
      else reject(new Error("Copy failed"));
    });
  }

  function wirePanelEvents(key) {
    var cfg = DATASETS[key];
    var prefix = cfg.prefix;
    var body = byId(prefix + "-tbody");
    if (body) {
      body.addEventListener("click", function (event) {
        var toggle = event.target.closest(".row-toggle");
        if (toggle) {
          var rowKey = toggle.getAttribute("data-row-key");
          var detail = byId(toggle.getAttribute("aria-controls"));
          var open = state[key].open.has(rowKey);
          if (open) state[key].open.delete(rowKey);
          else state[key].open.add(rowKey);
          toggle.setAttribute("aria-expanded", open ? "false" : "true");
          if (detail) detail.hidden = open;
          var domain = toggle.getAttribute("data-domain") || "this row";
          toggle.setAttribute("aria-label", (open ? "Show" : "Hide") + " details for " + domain);
          return;
        }
        var copyButton = event.target.closest(".copy-btn");
        if (copyButton) {
          var value = copyButton.getAttribute("data-copy") || "";
          var statusNode = byId(copyButton.getAttribute("data-status-id"));
          copyText(value).then(function () {
            if (statusNode) statusNode.textContent = "Copied to clipboard.";
          }).catch(function () {
            if (statusNode) statusNode.textContent = "Copy failed. Select the command and copy it manually.";
          });
        }
      });
    }

    var group = byId(prefix + "-filters");
    if (group) {
      group.addEventListener("click", function (event) {
        var button = event.target.closest("button[data-f]");
        if (!button) return;
        var ds = state[key];
        ds.filter = button.getAttribute("data-f");
        if (ALLOWED_FILTERS[key].indexOf(ds.filter) === -1) ds.filter = "all";
        syncControls(key);
        renderTable(key);
        writeHash();
      });
    }

    var search = byId(prefix + "-search");
    if (search) {
      search.addEventListener("input", function () {
        state[key].q = search.value;
        renderTable(key);
        writeHash();
      });
    }

    var sort = byId(prefix + "-sort");
    if (sort) {
      sort.addEventListener("change", function () {
        state[key].sort = ALLOWED_SORTS.indexOf(sort.value) === -1 ? DEFAULT_SORT : sort.value;
        renderTable(key);
        writeHash();
      });
    }

    var exportCsvButton = byId(prefix + "-export-csv");
    if (exportCsvButton) exportCsvButton.addEventListener("click", function () { exportCsv(key); });
    var exportJsonButton = byId(prefix + "-export-json");
    if (exportJsonButton) exportJsonButton.addEventListener("click", function () { exportJson(key); });

    var retry = byId(prefix + "-retry");
    if (retry) retry.addEventListener("click", function () { loadDataset(key); });
  }

  function boot() {
    wireTabs();
    wirePanelEvents("ssl");
    wirePanelEvents("domain");
    initTheme();

    var initial = parseHashState(window.location.hash);
    applyHashState(initial);
    if (!window.location.hash) {
      window.history.replaceState(null, "", buildHashState({
        tab: state.tab,
        filter: state[state.tab].filter,
        q: state[state.tab].q,
        sort: state[state.tab].sort
      }));
    }

    renderLoading("ssl");
    renderLoading("domain");
    updateGlobalAlert();

    var globalRetry = byId("global-retry");
    if (globalRetry) {
      globalRetry.addEventListener("click", function () {
        ["ssl", "domain"].forEach(function (key) {
          if (state[key].status === "error") loadDataset(key);
        });
      });
    }

    window.addEventListener("hashchange", function () {
      applyHashState(parseHashState(window.location.hash));
    });

    loadDataset("ssl");
    loadDataset("domain");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
