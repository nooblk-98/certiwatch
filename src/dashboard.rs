//! CertiWatch dashboard: one server-rendered page, no browser JavaScript.
//!
//! Public interface (agreed with the Rust migration):
//!
//! ```ignore
//! let html = render_dashboard(ssl_json.as_ref(), domains_json.as_ref(),
//!                             history_json.as_ref(), &DashboardQuery::default());
//! ```
//!
//! `ssl` and `domains` are the existing `ssl_results.json` and
//! `domain_results.json` contracts (`{"generated_at": "...", "results": [...]}`).
//! `history` is the existing public `history.json` contract
//! (`{"snapshots": [...]}`) and is optional.
//!
//! Design rules applied from
//! <https://github.com/abdiraimov-otabek/dashboard-design-skill> pinned at
//! 463b8fdf62c640180ec1ba731f3616c2319bf68c (website dashboard-design 2.1.0):
//! one question per screen ("is everything that expires okay?"), first-glance
//! KPI strip, problems in the monitoring view above the table, warm colour only
//! on what needs attention, wordless labels and numeric facts, a 14 px density
//! scale, one accent hue, hairline surfaces, share bars, a hand-built sparkline,
//! known-total fixtures, and the three-width QA pass. Deviations are recorded in
//! `docs/rust-dashboard-design.md`.

// The Expiry history card is no longer rendered; its parsing and drawing code is kept for now.
#![allow(dead_code)]

use serde::Deserialize;
use serde_json::Value;
use std::fmt::Write as _;

/// The dashboard stylesheet. The page embeds it, and a server may also expose
/// it as a static asset if a strict CSP forbids inline styles.
pub const DASHBOARD_CSS: &str = include_str!("dashboard.css");

const STALE_AFTER_SECS: i64 = 36 * 60 * 60;
const FUTURE_SKEW_SECS: i64 = 60;
const HISTORY_CHART_POINTS: usize = 90;
const HISTORY_TABLE_POINTS: usize = 30;

// ── Query ────────────────────────────────────────────────────────────────────

/// Which result set is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DashboardTab {
    #[default]
    Ssl,
    #[serde(alias = "domain", alias = "certificates", alias = "certs")]
    Domains,
}

impl DashboardTab {
    pub fn as_str(self) -> &'static str {
        match self {
            DashboardTab::Ssl => "ssl",
            DashboardTab::Domains => "domains",
        }
    }

    fn label(self) -> &'static str {
        match self {
            DashboardTab::Ssl => "Certificates",
            DashboardTab::Domains => "Domains",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            DashboardTab::Ssl => "certificate",
            DashboardTab::Domains => "domain",
        }
    }

    fn noun_plural(self) -> &'static str {
        match self {
            DashboardTab::Ssl => "certificates",
            DashboardTab::Domains => "domains",
        }
    }

    fn other(self) -> DashboardTab {
        match self {
            DashboardTab::Ssl => DashboardTab::Domains,
            DashboardTab::Domains => DashboardTab::Ssl,
        }
    }
}

/// Status filter for the list. `Attention` means every row that is not plain
/// valid, `Soon` means due within 30 days.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatusFilter {
    #[default]
    All,
    #[serde(alias = "needs-attention")]
    Attention,
    #[serde(alias = "expiring")]
    Soon,
    Urgent,
    Expired,
    Issues,
    #[serde(alias = "ok", alias = "active")]
    Valid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortKey {
    #[default]
    #[serde(alias = "urgency")]
    Attention,
    #[serde(alias = "expiry")]
    Days,
    #[serde(alias = "name")]
    Domain,
    Status,
    Checked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDir {
    #[default]
    #[serde(alias = "ascending")]
    Asc,
    #[serde(alias = "descending")]
    Desc,
}

impl SortDir {
    fn flip(self) -> SortDir {
        match self {
            SortDir::Asc => SortDir::Desc,
            SortDir::Desc => SortDir::Asc,
        }
    }
}

/// GET parameters for the dashboard. Every field has a default, and unknown or
/// malformed values fall back to that default instead of failing the request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DashboardQuery {
    #[serde(default, deserialize_with = "lenient")]
    pub tab: DashboardTab,
    #[serde(default, deserialize_with = "lenient")]
    pub status: StatusFilter,
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default, deserialize_with = "lenient")]
    pub sort: SortKey,
    #[serde(default, deserialize_with = "lenient")]
    pub dir: SortDir,
    /// Row key (`domain` or `domain|port`) whose details start expanded.
    #[serde(default)]
    pub open: String,
    /// `light` or `dark`. Never part of generated links: the server remembers it in a cookie.
    #[serde(default)]
    pub theme: String,
}

fn lenient<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(T::deserialize(de).unwrap_or_default())
}

impl DashboardQuery {
    fn normalized(mut self) -> Self {
        self.q = clip(self.q.trim(), 120);
        self.group = clip(self.group.trim(), 60);
        self.tag = clip(self.tag.trim(), 60);
        self.open = clip(self.open.trim(), 300);
        if self.theme != "light" {
            self.theme = "dark".to_string();
        }
        self
    }

    fn apply(&self, change: impl FnOnce(&mut DashboardQuery)) -> String {
        let mut next = self.clone();
        change(&mut next);
        next.to_url()
    }

    fn to_url(&self) -> String {
        let mut pairs: Vec<(&str, String)> = Vec::new();
        if self.tab != DashboardTab::Ssl {
            pairs.push(("tab", self.tab.as_str().to_string()));
        }
        if self.status != StatusFilter::All {
            pairs.push(("status", status_param(self.status).to_string()));
        }
        if !self.q.is_empty() {
            pairs.push(("q", self.q.clone()));
        }
        if !self.group.is_empty() {
            pairs.push(("group", self.group.clone()));
        }
        if !self.tag.is_empty() {
            pairs.push(("tag", self.tag.clone()));
        }
        if self.sort != SortKey::Attention {
            pairs.push(("sort", sort_param(self.sort).to_string()));
        }
        if self.dir != SortDir::Asc {
            pairs.push(("dir", "desc".to_string()));
        }
        if !self.open.is_empty() {
            pairs.push(("open", self.open.clone()));
        }
        if pairs.is_empty() {
            return "?".to_string();
        }
        let encoded: Vec<String> = pairs
            .into_iter()
            .map(|(key, value)| format!("{key}={}", url_encode(&value)))
            .collect();
        format!("?{}", encoded.join("&"))
    }
}

fn status_param(status: StatusFilter) -> &'static str {
    match status {
        StatusFilter::All => "all",
        StatusFilter::Attention => "attention",
        StatusFilter::Soon => "soon",
        StatusFilter::Urgent => "urgent",
        StatusFilter::Expired => "expired",
        StatusFilter::Issues => "issues",
        StatusFilter::Valid => "valid",
    }
}

fn sort_param(sort: SortKey) -> &'static str {
    match sort {
        SortKey::Attention => "attention",
        SortKey::Days => "days",
        SortKey::Domain => "domain",
        SortKey::Status => "status",
        SortKey::Checked => "checked",
    }
}

// ── Escaping ─────────────────────────────────────────────────────────────────

fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\u{0}' => out.push('\u{fffd}'),
            _ => out.push(ch),
        }
    }
    out
}

fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char)
            }
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

fn clip(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index >= max_chars {
            out.push('…');
            break;
        }
        if ch == '\u{0}' {
            continue;
        }
        out.push(ch);
    }
    out
}

// ── Time ─────────────────────────────────────────────────────────────────────

fn now_unix() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(_) => 0,
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parses the stamps the checks already write: `YYYY-MM-DD HH:MM UTC`,
/// RFC 3339 with `Z` or an offset, a plain `YYYY-MM-DD HH:MM:SS`, a date, or
/// epoch seconds/milliseconds. Returns UTC seconds.
fn parse_timestamp(value: &str) -> Option<i64> {
    let text = value.trim();
    if text.is_empty() {
        return None;
    }
    if text.chars().all(|ch| ch.is_ascii_digit()) {
        let number: i64 = text.parse().ok()?;
        return Some(if number > 100_000_000_000 {
            number / 1000
        } else {
            number
        });
    }
    let bytes = text.as_bytes();
    if bytes.len() < 10
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || !bytes[8..10].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let year: i64 = text.get(0..4)?.parse().ok()?;
    let month: i64 = text.get(5..7)?.parse().ok()?;
    let day: i64 = text.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut rest = text.get(10..).unwrap_or("").trim();
    if let Some(stripped) = rest.strip_prefix('T') {
        rest = stripped;
    } else if let Some(stripped) = rest.strip_prefix(' ') {
        rest = stripped;
    }
    let mut hour = 0;
    let mut minute = 0;
    let mut second = 0;
    let mut offset = 0;
    if !rest.is_empty() && !rest.eq_ignore_ascii_case("utc") {
        let (clock, tail) = match rest.find(|ch: char| {
            ch == ' ' || ch == 'Z' || ch == 'z' || ch == '+' || (ch == '-' && rest.len() > 8)
        }) {
            Some(index) => (&rest[..index], rest[index..].trim()),
            None => (rest, ""),
        };
        let mut parts = clock.split(':');
        let hour_text = parts.next().unwrap_or("");
        if hour_text.len() != 2 || !hour_text.chars().all(|ch| ch.is_ascii_digit()) {
            return None;
        }
        hour = hour_text.parse().ok()?;
        if let Some(minute_text) = parts.next() {
            minute = minute_text.parse().ok()?;
        }
        if let Some(second_text) = parts.next() {
            let second_text = second_text.split('.').next().unwrap_or("");
            second = second_text.parse().ok()?;
        }
        let tail = tail.trim();
        if tail.starts_with('+') || tail.starts_with('-') {
            let sign = if tail.starts_with('-') { -1 } else { 1 };
            let digits: String = tail[1..].chars().filter(|ch| ch.is_ascii_digit()).collect();
            if digits.len() >= 4 {
                let hours: i64 = digits[0..2].parse().ok()?;
                let minutes: i64 = digits[2..4].parse().ok()?;
                offset = sign * (hours * 3600 + minutes * 60);
            }
        }
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

fn format_stamp(timestamp: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = timestamp.div_euclid(86_400);
    let seconds = timestamp.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let name = MONTHS
        .get((month - 1).clamp(0, 11) as usize)
        .copied()
        .unwrap_or("?");
    format!(
        "{day} {name} {year}, {:02}:{:02} UTC",
        seconds / 3600,
        (seconds % 3600) / 60
    )
}

fn exact_stamp(raw: &str) -> String {
    parse_timestamp(raw)
        .map(format_stamp)
        .unwrap_or_else(|| raw.to_string())
}

fn format_date(timestamp: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (year, month, day) = civil_from_days(timestamp.div_euclid(86_400));
    let name = MONTHS
        .get((month - 1).clamp(0, 11) as usize)
        .copied()
        .unwrap_or("?");
    format!("{day} {name} {year}")
}

/// A contract date rendered for reading, or the original text when it is not
/// a date this module understands.
fn friendly_date(raw: &str) -> String {
    let text = raw.trim();
    if text.len() >= 10 {
        if let Some(timestamp) = parse_timestamp(text) {
            return format_date(timestamp);
        }
    }
    text.to_string()
}

fn short_date(value: &str) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let text = value.trim();
    if text.len() >= 10 {
        let year = text.get(0..4).and_then(|part| part.parse::<i64>().ok());
        let month = text.get(5..7).and_then(|part| part.parse::<usize>().ok());
        let day = text.get(8..10).and_then(|part| part.parse::<i64>().ok());
        if let (Some(_), Some(month), Some(day)) = (year, month, day) {
            if let Some(name) = MONTHS.get(month.wrapping_sub(1)) {
                return format!("{day} {name}");
            }
        }
    }
    text.to_string()
}

fn age_text(seconds: i64) -> String {
    let age = seconds.max(0);
    if age < 60 {
        "just now".to_string()
    } else if age < 3600 {
        format!("{} min ago", age / 60)
    } else if age < 86_400 {
        format!("{} h ago", age / 3600)
    } else {
        format!("{} d ago", age / 86_400)
    }
}

fn span_text(seconds: i64) -> String {
    let seconds = seconds.abs();
    if seconds < 60 {
        "under a minute".to_string()
    } else if seconds < 3600 {
        format!("{} min", seconds / 60)
    } else if seconds < 86_400 {
        format!("{} h", seconds / 3600)
    } else {
        format!("{} d", seconds / 86_400)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Freshness {
    Fresh,
    Old,
    Future,
    Unknown,
}

fn freshness(generated_at: Option<&str>, now: i64) -> (Freshness, Option<i64>) {
    let Some(raw) = generated_at else {
        return (Freshness::Unknown, None);
    };
    let Some(timestamp) = parse_timestamp(raw) else {
        return (Freshness::Unknown, None);
    };
    let age = now - timestamp;
    if age < -FUTURE_SKEW_SECS {
        (Freshness::Future, Some(age))
    } else if age > STALE_AFTER_SECS {
        (Freshness::Old, Some(age))
    } else {
        (Freshness::Fresh, Some(age))
    }
}

// ── Input contracts ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Cat {
    Expired,
    Today,
    Urgent,
    Warn,
    Error,
    Invalid,
    Unknown,
    Ok,
}

impl Cat {
    fn is_problem(self) -> bool {
        !matches!(self, Cat::Ok)
    }

    fn severity(self, tab: DashboardTab) -> u8 {
        match (tab, self) {
            (_, Cat::Expired) => 0,
            (DashboardTab::Ssl, Cat::Today) => 1,
            (_, Cat::Urgent) => {
                if tab == DashboardTab::Ssl {
                    2
                } else {
                    1
                }
            }
            (DashboardTab::Ssl, Cat::Error) => 3,
            (DashboardTab::Ssl, Cat::Invalid) => 4,
            (_, Cat::Warn) => {
                if tab == DashboardTab::Ssl {
                    5
                } else {
                    3
                }
            }
            (_, Cat::Unknown) => {
                if tab == DashboardTab::Ssl {
                    6
                } else {
                    2
                }
            }
            (_, Cat::Ok) => 99,
            _ => 7,
        }
    }

    fn chip_class(self) -> &'static str {
        match self {
            Cat::Expired => "chip chip-expired",
            Cat::Today => "chip chip-today",
            Cat::Urgent => "chip chip-urgent",
            Cat::Warn => "chip chip-warn",
            Cat::Error | Cat::Invalid | Cat::Unknown => "chip chip-issue",
            Cat::Ok => "chip chip-ok",
        }
    }
}

#[derive(Debug, Clone)]
struct Row {
    key: String,
    domain: String,
    port: Option<u16>,
    provider: String,
    status: String,
    issued_on: String,
    expires_on: String,
    days: Option<i64>,
    is_expired: Option<bool>,
    not_before: String,
    not_after: String,
    error: String,
    checked_at: String,
    tags: Vec<String>,
    group: String,
    raw: Value,
    cat: Cat,
}

impl Row {
    fn search_text(&self) -> String {
        let fallback = self
            .raw
            .get("fallback")
            .and_then(|value| value.get("domain").or_else(|| value.get("host")))
            .and_then(Value::as_str)
            .unwrap_or("");
        let port = self.port.map(|port| port.to_string()).unwrap_or_default();
        format!(
            "{} {} {} {} {} {} {} {} {}",
            self.domain,
            port,
            self.provider,
            self.status,
            self.error,
            fallback,
            self.tags.join(" "),
            self.group,
            self.issued_on
        )
        .to_lowercase()
    }
}

#[derive(Debug, Clone, Default)]
struct Payload {
    rows: Vec<Row>,
    generated_at: Option<String>,
    skipped: usize,
}

#[derive(Debug, Clone)]
enum Load {
    Missing,
    Invalid(&'static str),
    Ready(Payload),
}

impl Load {
    fn rows(&self) -> &[Row] {
        match self {
            Load::Ready(payload) => &payload.rows,
            _ => &[],
        }
    }

    fn is_ready(&self) -> bool {
        matches!(self, Load::Ready(_))
    }
}

fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(clip(text.trim(), 600)),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(if *flag { "Yes" } else { "No" }.to_string()),
        _ => None,
    }
}

fn clean_string(value: Option<&Value>, max_chars: usize) -> String {
    match value {
        Some(Value::String(text)) => clip(text.trim(), max_chars),
        Some(Value::Number(number)) => clip(&number.to_string(), max_chars),
        Some(Value::Bool(flag)) => (if *flag { "true" } else { "false" }).to_string(),
        _ => String::new(),
    }
}

fn number_i64(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|float| float.trunc() as i64)),
        Some(Value::String(text)) => {
            let trimmed = text.trim();
            trimmed.parse::<i64>().ok().or_else(|| {
                trimmed
                    .parse::<f64>()
                    .ok()
                    .map(|float| float.trunc() as i64)
            })
        }
        _ => None,
    }
}

fn clean_domain(value: Option<&Value>) -> String {
    let text = match value {
        Some(Value::String(text)) => text.trim(),
        _ => return String::new(),
    };
    if text.is_empty() || text.chars().count() > 260 {
        return String::new();
    }
    if text
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control() || ch == '/' || ch == '\\')
    {
        return String::new();
    }
    if text.contains("..") {
        return String::new();
    }
    let (host, port) = split_host_port(text);
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.starts_with('-')
        || host.ends_with('-')
    {
        return String::new();
    }
    if !host
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
    {
        return String::new();
    }
    match port {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

fn split_host_port(text: &str) -> (String, Option<u16>) {
    match text.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && !port.is_empty() => {
            let ok = port.chars().all(|ch| ch.is_ascii_digit())
                && port
                    .parse::<u32>()
                    .map(|value| (1..=65535).contains(&value))
                    .unwrap_or(false);
            if ok {
                (host.to_string(), port.parse::<u16>().ok())
            } else {
                (String::new(), None)
            }
        }
        Some(_) => (String::new(), None),
        None => (text.to_string(), None),
    }
}

fn clean_tags(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    let mut tags: Vec<String> = Vec::new();
    for item in items {
        let Some(text) = scalar_text(item) else {
            continue;
        };
        let text = clip(text.trim(), 40);
        if text.is_empty() {
            continue;
        }
        if tags
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&text))
        {
            continue;
        }
        tags.push(text);
    }
    tags.truncate(12);
    tags
}

fn ssl_category(status: &str, days: Option<i64>, is_expired: Option<bool>) -> Cat {
    let status = status.to_lowercase();
    if is_expired == Some(true) || status == "expired" {
        return Cat::Expired;
    }
    if status == "valid" {
        return match days {
            None => Cat::Ok,
            Some(days) if days < 0 => Cat::Expired,
            Some(0) => Cat::Today,
            Some(days) if days <= 7 => Cat::Urgent,
            Some(days) if days <= 30 => Cat::Warn,
            Some(_) => Cat::Ok,
        };
    }
    if status == "invalid" {
        Cat::Invalid
    } else {
        Cat::Error
    }
}

fn domain_category(status: &str, days: Option<i64>) -> Cat {
    let status = status.to_lowercase();
    if status == "expired" {
        return Cat::Expired;
    }
    if status == "active" || status == "valid" {
        return match days {
            None => Cat::Ok,
            Some(days) if days <= 0 => Cat::Expired,
            Some(days) if days <= 7 => Cat::Urgent,
            Some(days) if days <= 30 => Cat::Warn,
            Some(_) => Cat::Ok,
        };
    }
    if status == "urgent" {
        return Cat::Urgent;
    }
    if status == "warning" || status == "warn" {
        return Cat::Warn;
    }
    Cat::Unknown
}

fn parse_row(value: &Value, tab: DashboardTab) -> Option<Row> {
    if !value.is_object() {
        return None;
    }
    let cleaned = clean_domain(value.get("domain"));
    if cleaned.is_empty() {
        return None;
    }
    let (host, embedded_port) = split_host_port(&cleaned);
    if host.is_empty() {
        return None;
    }
    let mut port = number_i64(value.get("port"));
    if let Some(port_value) = port {
        if !(1..=65535).contains(&port_value) {
            port = None;
        }
    }
    let port = match port {
        Some(port_value) => Some(port_value as u16),
        None => embedded_port,
    };
    let status = {
        let text = clean_string(value.get("status"), 40).to_lowercase();
        if text.is_empty() {
            match tab {
                DashboardTab::Ssl => "error".to_string(),
                DashboardTab::Domains => "unknown".to_string(),
            }
        } else {
            text
        }
    };
    let days = number_i64(value.get("days_left")).map(|days| days.clamp(-100_000, 100_000));
    let is_expired = value.get("is_expired").and_then(Value::as_bool);
    let cat = match tab {
        DashboardTab::Ssl => ssl_category(&status, days, is_expired),
        DashboardTab::Domains => domain_category(&status, days),
    };
    let (provider, issued_on, expires_on) = match tab {
        DashboardTab::Ssl => (
            clean_string(value.get("provider"), 120),
            clean_string(value.get("issued_on"), 40),
            clean_string(value.get("expires_on"), 40),
        ),
        DashboardTab::Domains => (
            clean_string(value.get("registrar"), 120),
            clean_string(value.get("purchase_date"), 40),
            clean_string(value.get("expiry_date"), 40),
        ),
    };
    let mut row = Row {
        key: match port {
            Some(port) => format!("{host}|{port}"),
            None => host.clone(),
        },
        domain: host,
        port,
        provider: tidy_optional(provider),
        status,
        issued_on: tidy_optional(issued_on),
        expires_on: tidy_optional(expires_on),
        days,
        is_expired,
        not_before: clean_string(value.get("not_before"), 40),
        not_after: clean_string(value.get("not_after"), 40),
        error: tidy_optional(clean_string(value.get("error"), 400)),
        checked_at: clean_string(value.get("checked_at"), 80),
        tags: clean_tags(value.get("tags")),
        group: clean_string(value.get("group"), 60),
        raw: value.clone(),
        cat,
    };
    if tab == DashboardTab::Domains {
        row.is_expired = None;
    }
    Some(row)
}

fn tidy_optional(text: String) -> String {
    if text.eq_ignore_ascii_case("n/a") {
        String::new()
    } else {
        text
    }
}

fn parse_payload(value: Option<&Value>, tab: DashboardTab) -> Load {
    let Some(value) = value else {
        return Load::Missing;
    };
    let Some(object) = value.as_object() else {
        return Load::Invalid("The result file is not a JSON object");
    };
    let Some(results) = object.get("results") else {
        return Load::Invalid("The result file has no results list");
    };
    let Some(results) = results.as_array() else {
        return Load::Invalid("The results field is not a list");
    };
    let mut rows = Vec::new();
    let mut skipped = 0;
    for item in results {
        match parse_row(item, tab) {
            Some(row) => rows.push(row),
            None => skipped += 1,
        }
    }
    if rows.is_empty() && !results.is_empty() {
        return Load::Invalid("No row in the result file could be read");
    }
    Load::Ready(Payload {
        rows,
        generated_at: object
            .get("generated_at")
            .and_then(scalar_text)
            .map(|text| clip(text.trim(), 80))
            .filter(|text| !text.is_empty()),
        skipped,
    })
}

// ── History contract ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct HistPoint {
    date: String,
    total: usize,
    due: usize,
    expired: usize,
    renewals: usize,
}

#[derive(Debug, Clone)]
struct Renewal {
    date: String,
    domains: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct Series {
    points: Vec<HistPoint>,
    renewals: Vec<Renewal>,
}

#[derive(Debug, Clone, Default)]
struct History {
    ssl: Series,
    domains: Series,
    skipped: usize,
}

#[derive(Debug, Clone)]
enum HistLoad {
    Missing,
    Invalid,
    Ready(History),
}

fn parse_history(value: Option<&Value>) -> HistLoad {
    let Some(value) = value else {
        return HistLoad::Missing;
    };
    let Some(object) = value.as_object() else {
        return HistLoad::Invalid;
    };
    let Some(snapshots) = object.get("snapshots") else {
        return HistLoad::Invalid;
    };
    let Some(snapshots) = snapshots.as_array() else {
        return HistLoad::Invalid;
    };

    let mut entries: Vec<(String, &Value)> = Vec::new();
    let mut skipped = 0;
    for snapshot in snapshots {
        let Some(entry) = snapshot.as_object() else {
            skipped += 1;
            continue;
        };
        let Some(date) = entry.get("date").and_then(Value::as_str) else {
            skipped += 1;
            continue;
        };
        let date = clip(date.trim(), 10);
        let valid_date = date.len() == 10
            && date.is_ascii()
            && date.as_bytes().get(4) == Some(&b'-')
            && date.as_bytes().get(7) == Some(&b'-')
            && date[0..4].chars().all(|ch| ch.is_ascii_digit())
            && date[5..7].chars().all(|ch| ch.is_ascii_digit())
            && date[8..10].chars().all(|ch| ch.is_ascii_digit());
        if !valid_date
            || entry.get("ssl").and_then(Value::as_array).is_none()
            || entry.get("domains").and_then(Value::as_array).is_none()
        {
            skipped += 1;
            continue;
        }
        entries.push((date, snapshot));
    }
    if entries.is_empty() && !snapshots.is_empty() {
        return HistLoad::Invalid;
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries.dedup_by(|left, right| left.0 == right.0);

    let mut history = History {
        skipped,
        ..History::default()
    };
    #[derive(Clone, Default)]
    struct Previous {
        days: Option<i64>,
        fingerprint: Option<String>,
    }

    let mut previous_ssl: std::collections::BTreeMap<String, Previous> =
        std::collections::BTreeMap::new();
    let mut previous_domains: std::collections::BTreeMap<String, Previous> =
        std::collections::BTreeMap::new();

    for (date, snapshot) in entries {
        let ssl_rows = snapshot
            .get("ssl")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let domain_rows = snapshot
            .get("domains")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let mut ssl_point = point_from(ssl_rows, &date);
        let mut domain_point = point_from(domain_rows, &date);

        let mut renewed_ssl = Vec::new();
        for row in ssl_rows {
            let Some(domain) = row.get("domain").and_then(Value::as_str) else {
                continue;
            };
            let days = number_i64(row.get("days_left"));
            let fingerprint = row
                .get("fingerprint_sha256")
                .or_else(|| row.get("fingerprint"))
                .and_then(Value::as_str)
                .map(str::to_string);
            if let Some(previous) = previous_ssl.get(domain) {
                let jumped = days
                    .zip(previous.days)
                    .map(|(current, before)| current > before)
                    .unwrap_or(false);
                let changed = fingerprint
                    .as_deref()
                    .zip(previous.fingerprint.as_deref())
                    .map(|(current, before)| current != before)
                    .unwrap_or(false);
                if jumped || changed {
                    ssl_point.renewals += 1;
                    renewed_ssl.push(domain.to_string());
                }
            }
            previous_ssl.insert(domain.to_string(), Previous { days, fingerprint });
        }

        let mut renewed_domains = Vec::new();
        for row in domain_rows {
            let Some(domain) = row.get("domain").and_then(Value::as_str) else {
                continue;
            };
            let days = number_i64(row.get("days_left"));
            let fingerprint = row
                .get("fingerprint_sha256")
                .or_else(|| row.get("fingerprint"))
                .and_then(Value::as_str)
                .map(str::to_string);
            if let Some(previous) = previous_domains.get(domain) {
                let jumped = days
                    .zip(previous.days)
                    .map(|(current, before)| current > before)
                    .unwrap_or(false);
                let changed = fingerprint
                    .as_deref()
                    .zip(previous.fingerprint.as_deref())
                    .map(|(current, before)| current != before)
                    .unwrap_or(false);
                if jumped || changed {
                    domain_point.renewals += 1;
                    renewed_domains.push(domain.to_string());
                }
            }
            previous_domains.insert(domain.to_string(), Previous { days, fingerprint });
        }

        if !renewed_ssl.is_empty() {
            history.ssl.renewals.push(Renewal {
                date: date.clone(),
                domains: renewed_ssl,
            });
        }
        if !renewed_domains.is_empty() {
            history.domains.renewals.push(Renewal {
                date: date.clone(),
                domains: renewed_domains,
            });
        }
        history.ssl.points.push(ssl_point);
        history.domains.points.push(domain_point);
    }

    HistLoad::Ready(history)
}

fn point_from(rows: &[Value], date: &str) -> HistPoint {
    let mut point = HistPoint {
        date: date.to_string(),
        total: 0,
        due: 0,
        expired: 0,
        renewals: 0,
    };
    for row in rows {
        if !row.is_object() {
            continue;
        }
        let days = number_i64(row.get("days_left"));
        let status = row.get("status").and_then(Value::as_str).unwrap_or("");
        let expired = status.eq_ignore_ascii_case("expired")
            || row.get("is_expired").and_then(Value::as_bool) == Some(true)
            || days.map(|days| days < 0).unwrap_or(false);
        point.total += 1;
        if expired {
            point.expired += 1;
        } else if days.map(|days| days <= 30).unwrap_or(false) {
            point.due += 1;
        }
    }
    point
}

// ── Page state ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default)]
struct Counts {
    all: usize,
    attention: usize,
    soon: usize,
    urgent: usize,
    expired: usize,
    issues: usize,
    valid: usize,
}

struct Page {
    ssl: Load,
    domains: Load,
    history: HistLoad,
    q: DashboardQuery,
    now: i64,
}

impl Page {
    fn load(&self, tab: DashboardTab) -> &Load {
        match tab {
            DashboardTab::Ssl => &self.ssl,
            DashboardTab::Domains => &self.domains,
        }
    }

    fn rows(&self, tab: DashboardTab) -> &[Row] {
        self.load(tab).rows()
    }

    fn generated_at(&self, tab: DashboardTab) -> Option<&str> {
        match self.load(tab) {
            Load::Ready(payload) => payload.generated_at.as_deref(),
            _ => None,
        }
    }

    fn series(&self, tab: DashboardTab) -> Option<&Series> {
        match &self.history {
            HistLoad::Ready(history) => Some(match tab {
                DashboardTab::Ssl => &history.ssl,
                DashboardTab::Domains => &history.domains,
            }),
            _ => None,
        }
    }

    fn visible_rows(&self) -> Vec<&Row> {
        let needle = self.q.q.to_lowercase();
        let mut rows: Vec<&Row> = self
            .rows(self.q.tab)
            .iter()
            .filter(|row| self.status_matches(row))
            .filter(|row| self.group_matches(row))
            .filter(|row| self.tag_matches(row))
            .filter(|row| needle.is_empty() || row.search_text().contains(&needle))
            .collect();
        self.sort_rows(&mut rows);
        rows
    }

    fn status_matches(&self, row: &Row) -> bool {
        match self.q.status {
            StatusFilter::All => true,
            StatusFilter::Attention => row.cat.is_problem(),
            StatusFilter::Soon => matches!(row.cat, Cat::Today | Cat::Urgent | Cat::Warn),
            StatusFilter::Urgent => matches!(row.cat, Cat::Today | Cat::Urgent),
            StatusFilter::Expired => row.cat == Cat::Expired,
            StatusFilter::Issues => matches!(row.cat, Cat::Error | Cat::Invalid | Cat::Unknown),
            StatusFilter::Valid => row.cat == Cat::Ok,
        }
    }

    fn group_matches(&self, row: &Row) -> bool {
        self.q.group.is_empty() || row.group.eq_ignore_ascii_case(&self.q.group)
    }

    fn tag_matches(&self, row: &Row) -> bool {
        self.q.tag.is_empty()
            || row
                .tags
                .iter()
                .any(|tag| tag.eq_ignore_ascii_case(&self.q.tag))
    }

    fn sort_rows(&self, rows: &mut [&Row]) {
        let tab = self.q.tab;
        rows.sort_by(|left, right| {
            let base = match self.q.sort {
                SortKey::Attention => left
                    .cat
                    .severity(tab)
                    .cmp(&right.cat.severity(tab))
                    .then_with(|| days_cmp(left.days, right.days)),
                SortKey::Days => days_cmp(left.days, right.days),
                SortKey::Domain => left
                    .domain
                    .to_lowercase()
                    .cmp(&right.domain.to_lowercase())
                    .then_with(|| left.port.cmp(&right.port)),
                SortKey::Status => left
                    .cat
                    .severity(tab)
                    .cmp(&right.cat.severity(tab))
                    .then_with(|| days_cmp(left.days, right.days)),
                SortKey::Checked => {
                    let left_stamp = parse_timestamp(&left.checked_at).unwrap_or(0);
                    let right_stamp = parse_timestamp(&right.checked_at).unwrap_or(0);
                    left_stamp.cmp(&right_stamp)
                }
            };
            if self.q.dir == SortDir::Desc {
                base.reverse()
            } else {
                base
            }
        });
        // Rows without a date are not part of a day order.
        if matches!(self.q.sort, SortKey::Attention | SortKey::Days) {
            rows.sort_by_key(|row| row.days.is_none());
        }
    }

    fn scoped_counts(&self) -> Counts {
        let tab = self.q.tab;
        let needle = self.q.q.to_lowercase();
        let mut counts = Counts::default();
        for row in self.rows(tab) {
            if !self.group_matches(row) || !self.tag_matches(row) {
                continue;
            }
            if !needle.is_empty() && !row.search_text().contains(&needle) {
                continue;
            }
            counts.all += 1;
            if row.cat.is_problem() {
                counts.attention += 1;
            }
            if matches!(row.cat, Cat::Today | Cat::Urgent | Cat::Warn) {
                counts.soon += 1;
            }
            if matches!(row.cat, Cat::Today | Cat::Urgent) {
                counts.urgent += 1;
            }
            if row.cat == Cat::Expired {
                counts.expired += 1;
            }
            if matches!(row.cat, Cat::Error | Cat::Invalid | Cat::Unknown) {
                counts.issues += 1;
            }
            if row.cat == Cat::Ok {
                counts.valid += 1;
            }
        }
        counts
    }

    fn groups(&self) -> Vec<String> {
        let mut values: Vec<String> = Vec::new();
        for row in self.rows(self.q.tab) {
            if row.group.is_empty() {
                continue;
            }
            if !values
                .iter()
                .any(|value| value.eq_ignore_ascii_case(&row.group))
            {
                values.push(row.group.clone());
            }
        }
        values.sort_by_key(|value| value.to_lowercase());
        values
    }

    fn tags(&self) -> Vec<String> {
        let mut values: Vec<String> = Vec::new();
        for row in self.rows(self.q.tab) {
            for tag in &row.tags {
                if !values.iter().any(|value| value.eq_ignore_ascii_case(tag)) {
                    values.push(tag.clone());
                }
            }
        }
        values.sort_by_key(|value| value.to_lowercase());
        values
    }

    fn open_key(&self) -> Option<&str> {
        if self.q.open.is_empty() {
            None
        } else {
            Some(self.q.open.as_str())
        }
    }

    fn row_open(&self, row: &Row) -> bool {
        match self.open_key() {
            Some(open) => {
                open.eq_ignore_ascii_case(&row.key)
                    || open.eq_ignore_ascii_case(&row.domain)
                    || open
                        .replace('|', ":")
                        .eq_ignore_ascii_case(&row.key.replace('|', ":"))
            }
            None => false,
        }
    }
}

fn days_cmp(left: Option<i64>, right: Option<i64>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

// ── Rendering ────────────────────────────────────────────────────────────────

/// Render the dashboard for the current time.
pub fn render_dashboard(
    ssl: Option<&Value>,
    domains: Option<&Value>,
    history: Option<&Value>,
    query: &DashboardQuery,
) -> String {
    render_dashboard_at(ssl, domains, history, query, now_unix())
}

/// Same as [`render_dashboard`], with an explicit UTC clock in seconds. Used by
/// tests and offline previews so freshness output is reproducible.
pub fn render_dashboard_at(
    ssl: Option<&Value>,
    domains: Option<&Value>,
    history: Option<&Value>,
    query: &DashboardQuery,
    now: i64,
) -> String {
    let page = Page {
        ssl: parse_payload(ssl, DashboardTab::Ssl),
        domains: parse_payload(domains, DashboardTab::Domains),
        history: parse_history(history),
        q: query.clone().normalized(),
        now,
    };
    page.render()
}

impl Page {
    fn render(&self) -> String {
        let mut out = String::with_capacity(96 * 1024);
        self.render_head(&mut out);
        out.push_str("<body>");
        out.push_str("<a class=\"skip\" href=\"#main\">Skip to results</a>");
        self.render_header(&mut out);
        out.push_str("<main id=\"main\" class=\"wrap main\" tabindex=\"-1\">");
        if matches!(self.ssl, Load::Missing) && matches!(self.domains, Load::Missing) {
            self.render_setup(&mut out);
        } else if let Load::Ready(payload) = self.load(self.q.tab) {
            if payload.rows.is_empty() {
                self.render_empty(&mut out);
            } else {
                self.render_active(&mut out, payload);
            }
        } else {
            self.render_unavailable(&mut out);
        }
        self.render_footer(&mut out);
        out.push_str("</main></body></html>");
        out
    }

    fn render_head(&self, out: &mut String) {
        let title = format!("CertiWatch · {}", self.q.tab.label());
        let _ = write!(
            out,
            "<!doctype html><html lang=\"en\" data-theme=\"{}\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <meta name=\"color-scheme\" content=\"dark light\">\
             <meta name=\"description\" content=\"Certificate and domain expiry monitor. Results are generated by the CertiWatch service and served as JSON.\">\
             <title>{}</title><link rel=\"icon\" href=\"data:,\">\
             <link rel=\"alternate\" type=\"application/json\" href=\"status.json\" title=\"Machine-readable status\">\
             <link rel=\"alternate\" type=\"text/calendar\" href=\"expiries.ics\" title=\"Renewal calendar\">\
             <style>{}</style></head>",
            self.q.theme,
            esc(&title),
            DASHBOARD_CSS
        );
    }

    fn render_header(&self, out: &mut String) {
        out.push_str("<header class=\"top\"><div class=\"wrap top-inner\">");
        out.push_str(
            "<div class=\"brand\"><svg class=\"brand-mark\" viewBox=\"0 0 24 24\" aria-hidden=\"true\" focusable=\"false\">\
             <path d=\"M12 2.6 19 5.4v5.3c0 4.2-2.9 7.6-7 9.1-4.1-1.5-7-4.9-7-9.1V5.4L12 2.6Z\"/>\
             <path d=\"m8.6 11.6 2.3 2.3 4.5-4.7\"/></svg>\
             <span class=\"brand-name\">CertiWatch</span></div>",
        );
        out.push_str("<nav class=\"tabs\" aria-label=\"Result type\">");
        for tab in [DashboardTab::Ssl, DashboardTab::Domains] {
            let active = tab == self.q.tab;
            let count = match self.load(tab) {
                Load::Ready(payload) => payload.rows.len().to_string(),
                Load::Missing => "—".to_string(),
                Load::Invalid(_) => "!".to_string(),
            };
            let href = self.q.apply(|next| {
                next.tab = tab;
                next.open.clear();
            });
            let _ = write!(
                out,
                "<a class=\"tab{}\" href=\"{}\"{}>{}<span class=\"tab-count\">{}</span></a>",
                if active { " is-on" } else { "" },
                esc(&href),
                if active { " aria-current=\"page\"" } else { "" },
                tab.label(),
                esc(&count)
            );
        }
        out.push_str("</nav><div class=\"toolbar\">");
        self.render_theme_switch(out);
        let (kind, age) = freshness(self.generated_at(self.q.tab), self.now);
        let (class, text, title) = match kind {
            Freshness::Fresh => (
                "fresh fresh-live",
                format!("Updated {}", age_text(age.unwrap_or(0))),
                self.generated_at(self.q.tab).unwrap_or("").to_string(),
            ),
            Freshness::Old => (
                "fresh fresh-stale",
                format!("Stale · {}", span_text(age.unwrap_or(0))),
                self.generated_at(self.q.tab).unwrap_or("").to_string(),
            ),
            Freshness::Future => (
                "fresh fresh-bad",
                format!("Clock skew · +{}", span_text(age.unwrap_or(0))),
                self.generated_at(self.q.tab).unwrap_or("").to_string(),
            ),
            Freshness::Unknown => (
                "fresh fresh-unknown",
                "Freshness unknown".to_string(),
                String::new(),
            ),
        };
        let _ = write!(
            out,
            "<span class=\"{}\" role=\"status\"{}><span class=\"dot\" aria-hidden=\"true\"></span>{}</span>",
            class,
            if title.is_empty() {
                String::new()
            } else {
                format!(" title=\"Generated {}\"", esc(&title))
            },
            esc(&text)
        );
        out.push_str("</div></div></header>");
    }

    fn render_theme_switch(&self, out: &mut String) {
        let base = self.q.to_url();
        let join = if base == "?" { "" } else { "&" };
        out.push_str("<nav class=\"theme-switch\" aria-label=\"Colour theme\">");
        for (value, label, icon) in [("dark", "Dark", "☾"), ("light", "Light", "☀")] {
            let on = self.q.theme == value;
            let _ = write!(
                out,
                "<a class=\"theme-opt{}\" href=\"{}{}theme={}\" rel=\"nofollow\"{} title=\"{} theme\"><span aria-hidden=\"true\">{}</span><span class=\"theme-label\">{}</span></a>",
                if on { " is-on" } else { "" },
                esc(&base),
                join,
                value,
                if on { " aria-current=\"true\"" } else { "" },
                label,
                icon,
                label
            );
        }
        out.push_str("</nav>");
    }

    fn render_setup(&self, out: &mut String) {
        out.push_str("<section class=\"card setup\">");
        out.push_str(SETUP_ICON);
        out.push_str("<h1>No results yet</h1>");
        out.push_str("<p class=\"setup-lead\">The dashboard reads two files written by the scheduled checks. Nothing is wrong: they have not been published on this host.</p>");
        out.push_str("<ol class=\"steps\">");
        out.push_str("<li><span class=\"step-num\">1</span><div><strong>Add targets</strong><span>List the hosts to watch in <code>certiwatch.toml</code>.</span></div></li>");
        out.push_str("<li><span class=\"step-num\">2</span><div><strong>Run the checks</strong><span><code>certiwatch check</code> writes both result files in one pass.</span></div></li>");
        out.push_str("<li><span class=\"step-num\">3</span><div><strong>Publish</strong><span>The next scheduled run fills this page and the feeds below.</span></div></li>");
        out.push_str("</ol>");
        out.push_str("</section>");
    }

    fn render_empty(&self, out: &mut String) {
        let tab = self.q.tab;
        let _ = write!(
            out,
            "<section class=\"card setup\">{}<h1>No {} configured</h1>\
             <p class=\"setup-lead\">The results file is readable and contains no rows yet. Add targets to <code>certiwatch.toml</code> and run the {} check.</p>",
            SETUP_ICON,
            tab.noun_plural(),
            tab.noun()
        );
        out.push_str("</section>");
    }

    fn render_unavailable(&self, out: &mut String) {
        let tab = self.q.tab;
        let other = tab.other();
        let reason = match self.load(tab) {
            Load::Missing => "No result file has been loaded for this check.",
            Load::Invalid(message) => message,
            Load::Ready(_) => "The result file could not be read.",
        };
        let _ = write!(
            out,
            "<section class=\"card setup\"><div class=\"state-icon state-warn\" aria-hidden=\"true\">{}</div>\
             <h1>{} unavailable</h1>\
             <p class=\"setup-lead\">{}. The other tab and the public feeds are unaffected.</p>",
            ALERT_ICON,
            esc(tab.label()),
            esc(reason)
        );
        if self.load(other).is_ready() {
            let href = self.q.apply(|next| {
                next.tab = other;
                next.open.clear();
            });
            let _ = write!(
                out,
                "<p class=\"setup-actions\"><a class=\"button\" href=\"{}\">Open {}</a></p>",
                esc(&href),
                other.label()
            );
        }
        out.push_str("</section>");
    }

    fn render_active(&self, out: &mut String, payload: &Payload) {
        self.render_notes(out, payload);
        self.render_banner(out);
        self.render_kpis(out, payload);
        out.push_str("<div class=\"cc-grid\"><div class=\"cc-primary\">");
        self.render_list(out, payload);
        out.push_str("</div><aside class=\"cc-side\" aria-label=\"Overview\">");
        self.render_timeline(out);
        self.render_attention(out);
        self.render_distribution(out, payload);
        out.push_str("</aside></div>");
    }

    fn render_banner(&self, out: &mut String) {
        let rows = self.rows(self.q.tab);
        let expired = rows.iter().filter(|row| row.cat == Cat::Expired).count();
        let urgent = rows
            .iter()
            .filter(|row| matches!(row.cat, Cat::Today | Cat::Urgent))
            .count();
        let broken = rows
            .iter()
            .filter(|row| matches!(row.cat, Cat::Error | Cat::Invalid))
            .count();
        let (tone, head, detail) = if rows.is_empty() {
            ("idle", "NO DATA", "no targets reported yet".to_string())
        } else if expired > 0 {
            (
                "bad",
                "CRITICAL",
                format!("{expired} expired · {urgent} expiring ≤ 7 d · {broken} unreachable"),
            )
        } else if urgent > 0 || broken > 0 {
            (
                "warn",
                "WARNING",
                format!("{urgent} expiring ≤ 7 d · {broken} unreachable"),
            )
        } else {
            ("ok", "ALL CLEAR", format!("{} monitored", rows.len()))
        };
        let _ = write!(
            out,
            "<div class=\"banner banner-{}\" role=\"status\"><span class=\"banner-led\" aria-hidden=\"true\"></span>\
             <strong>{}</strong><span class=\"banner-detail\">{}</span>\
             <a class=\"banner-link\" href=\"#inventory\">Inventory <span aria-hidden=\"true\">↓</span></a></div>",
            tone,
            head,
            esc(&detail)
        );
    }

    fn render_notes(&self, out: &mut String, payload: &Payload) {
        let tab = self.q.tab;
        let (kind, age) = freshness(payload.generated_at.as_deref(), self.now);
        if matches!(kind, Freshness::Old | Freshness::Future) {
            let stamp = payload
                .generated_at
                .as_deref()
                .and_then(parse_timestamp)
                .map(format_stamp)
                .unwrap_or_else(|| payload.generated_at.clone().unwrap_or_default());
            let (class, label, detail) = match kind {
                Freshness::Old => (
                    "note note-warn",
                    "Stale results",
                    format!(
                        "Last generated {stamp}, {} beyond the 36-hour limit. The scheduled check may not be running.",
                        span_text(age.unwrap_or(0))
                    ),
                ),
                _ => (
                    "note note-bad",
                    "Suspect timestamp",
                    format!("The file says it was generated {stamp}, which is ahead of this server's clock."),
                ),
            };
            let _ = write!(
                out,
                "<div class=\"{}\" role=\"status\"><strong>{}</strong><span>{}</span><a href=\"{}\">{}</a></div>",
                class,
                label,
                esc(&detail),
                esc(&format!("{}_results.json", if tab == DashboardTab::Ssl { "ssl" } else { "domain" })),
                esc(&format!("{}_results.json", if tab == DashboardTab::Ssl { "ssl" } else { "domain" }))
            );
        }
        let old_checks = payload
            .rows
            .iter()
            .filter(|row| {
                parse_timestamp(&row.checked_at)
                    .map(|stamp| self.now - stamp > STALE_AFTER_SECS)
                    .unwrap_or(false)
            })
            .count();
        if old_checks > 0 {
            let _ = write!(
                out,
                "<div class=\"note note-warn\" role=\"status\"><strong>{} row check{}</strong><span>older than 36 hours in this result file.</span></div>",
                old_checks,
                if old_checks == 1 { "" } else { "s" }
            );
        }
        if payload.skipped > 0 {
            let _ = write!(
                out,
                "<div class=\"note\" role=\"status\"><strong>{} row{}</strong><span>could not be read and {} skipped.</span></div>",
                payload.skipped,
                if payload.skipped == 1 { "" } else { "s" },
                if payload.skipped == 1 { "was" } else { "were" }
            );
        }
    }

    fn render_kpis(&self, out: &mut String, payload: &Payload) {
        let tab = self.q.tab;
        let rows = &payload.rows;
        let mut ok = 0;
        let mut warn = 0;
        let mut urgent = 0;
        let mut today = 0;
        let mut expired = 0;
        let mut issues = 0;
        for row in rows {
            match row.cat {
                Cat::Ok => ok += 1,
                Cat::Warn => warn += 1,
                Cat::Urgent => urgent += 1,
                Cat::Today => today += 1,
                Cat::Expired => expired += 1,
                Cat::Error | Cat::Invalid | Cat::Unknown => issues += 1,
            }
        }
        let total = rows.len();
        let tiles: [(&str, usize, String, &str, &str); 6] = [
            (
                if tab == DashboardTab::Ssl {
                    "Valid"
                } else {
                    "Active"
                },
                ok,
                "> 30 days".to_string(),
                "ok",
                CHECK_ICON,
            ),
            (
                "8–30 days",
                warn,
                "next to renew".to_string(),
                "warm",
                CLOCK_ICON,
            ),
            (
                "≤ 7 days",
                urgent + today,
                if today > 0 {
                    format!("{today} today")
                } else {
                    "action window".to_string()
                },
                "hot",
                ALERT_ICON,
            ),
            (
                "Expired",
                expired,
                "past expiry".to_string(),
                "bad",
                BAN_ICON,
            ),
            (
                if tab == DashboardTab::Ssl {
                    "Issues"
                } else {
                    "Unknown"
                },
                issues,
                "no expiry data".to_string(),
                "bad",
                PLUG_ICON,
            ),
            (
                "Total",
                total,
                if total == 1 {
                    tab.noun()
                } else {
                    tab.noun_plural()
                }
                .to_string(),
                "total",
                LAYERS_ICON,
            ),
        ];
        out.push_str("<section class=\"kpis\" aria-label=\"Summary\">");
        for (label, value, base, tone, icon) in tiles {
            let _ = write!(
                out,
                "<article class=\"kpi kpi-{}\"><span class=\"kpi-icon\" aria-hidden=\"true\">{}</span>\
                 <h2 class=\"kpi-label\">{}</h2><p class=\"kpi-value\">{}</p><p class=\"kpi-base\">{}</p></article>",
                tone,
                icon,
                esc(label),
                value,
                esc(&base)
            );
        }
        out.push_str("</section>");
    }

    fn attention_rows(&self) -> Vec<&Row> {
        let tab = self.q.tab;
        let mut rows: Vec<&Row> = self
            .rows(tab)
            .iter()
            .filter(|row| row.cat.is_problem())
            .collect();
        rows.sort_by(|left, right| {
            left.cat
                .severity(tab)
                .cmp(&right.cat.severity(tab))
                .then_with(|| days_cmp(left.days, right.days))
                .then_with(|| left.domain.to_lowercase().cmp(&right.domain.to_lowercase()))
        });
        rows
    }

    fn render_attention(&self, out: &mut String) {
        let tab = self.q.tab;
        let rows = self.attention_rows();
        out.push_str("<section class=\"card attention\" aria-labelledby=\"attention-title\">");
        let _ = write!(
            out,
            "<div class=\"card-head\"><h2 id=\"attention-title\">Needs attention</h2>\
             <p class=\"card-fact\">{}</p></div>",
            if rows.is_empty() {
                "0 items".to_string()
            } else if rows.len() == 1 {
                "1 item".to_string()
            } else {
                format!("{} items", rows.len())
            }
        );
        if rows.is_empty() {
            let next = self
                .rows(tab)
                .iter()
                .filter_map(|row| row.days)
                .filter(|days| *days > 30)
                .min();
            out.push_str("<p class=\"empty-state\">Nothing expires within 30 days.</p>");
            if let Some(days) = next {
                let _ = write!(
                    out,
                    "<p class=\"empty-meta\">Next expiry in <strong>{} d</strong></p>",
                    days
                );
            }
        } else {
            out.push_str("<ul class=\"attn-list\">");
            for row in rows.iter().take(6) {
                let href = self.q.apply(|next| {
                    next.tab = tab;
                    next.status = StatusFilter::All;
                    next.q = row.domain.clone();
                    next.group.clear();
                    next.tag.clear();
                    next.open = row.key.clone();
                    next.sort = SortKey::Days;
                    next.dir = SortDir::Asc;
                });
                let _ = write!(
                    out,
                    "<li class=\"attn-item\"><a class=\"attn-link\" href=\"{}#inventory\"><span class=\"attn-domain\">{}</span>{}<span class=\"attn-days\">{}</span><span class=\"attn-arrow\" aria-hidden=\"true\">›</span></a></li>",
                    esc(&href),
                    esc(&row.domain),
                    self.chip(row),
                    esc(&self.days_text(row))
                );
            }
            out.push_str("</ul>");
            if rows.len() > 6 {
                let more = self.q.apply(|next| {
                    next.status = StatusFilter::Attention;
                    next.q.clear();
                    next.group.clear();
                    next.tag.clear();
                    next.open.clear();
                });
                let _ = write!(
                    out,
                    "<a class=\"more-link\" href=\"{}#inventory\">View all {} needing attention <span aria-hidden=\"true\">→</span></a>",
                    esc(&more),
                    rows.len()
                );
            }
        }
        out.push_str("</section>");
    }

    fn render_timeline(&self, out: &mut String) {
        let tab = self.q.tab;
        let rows = self.rows(tab);
        let mut counts = [0usize; 7];
        for row in rows {
            let index = match row.cat {
                Cat::Expired => 0,
                Cat::Today | Cat::Urgent => 1,
                Cat::Warn => 2,
                Cat::Ok => match row.days {
                    Some(days) if days <= 90 => 3,
                    Some(days) if days <= 365 => 4,
                    Some(_) => 5,
                    None => 6,
                },
                _ => 6,
            };
            counts[index] += 1;
        }
        let labels = [
            "Expired",
            "≤ 7 days",
            "8–30 days",
            "31–90 days",
            "91–365 days",
            "> 365 days",
            "No date",
        ];
        let classes = [
            "t-expired",
            "t-urgent",
            "t-warn",
            "t-far",
            "t-distant",
            "t-veryfar",
            "t-none",
        ];
        let aria = labels
            .iter()
            .zip(counts.iter())
            .map(|(label, count)| format!("{label} {count}"))
            .collect::<Vec<String>>()
            .join(", ");
        let due = counts[1] + counts[2];
        let short = ["Expired", "≤7d", "8–30d", "31–90d", "91–365d", ">365d", "None"];
        let peak = counts.iter().copied().max().unwrap_or(0).max(1);
        out.push_str("<section class=\"card timeline-card\" aria-labelledby=\"timeline-title\">");
        let _ = write!(
            out,
            "<div class=\"card-head\"><h2 id=\"timeline-title\">Expiry radar</h2>\
             <p class=\"card-fact\">{} due ≤ 30 d</p></div>\
             <div class=\"radar\" role=\"img\" aria-label=\"Expiry radar: {}\">",
            due,
            esc(&aria)
        );
        for (index, count) in counts.iter().enumerate() {
            let height = if *count == 0 {
                2.0
            } else {
                (*count as f64 / peak as f64 * 100.0).max(8.0)
            };
            let _ = write!(
                out,
                "<div class=\"rcol{}\"><span class=\"rcount\">{}</span><span class=\"rbar {}\" style=\"height:{:.1}%\"></span><span class=\"rlabel\">{}</span></div>",
                if *count == 0 { " is-zero" } else { "" },
                count,
                classes[index],
                height,
                short[index]
            );
        }
        out.push_str("</div>");
        out.push_str("</section>");
    }

    fn render_list(&self, out: &mut String, payload: &Payload) {
        let tab = self.q.tab;
        let rows = self.visible_rows();
        let total = payload.rows.len();
        let counts = self.scoped_counts();
        out.push_str("<section class=\"card list-card\" aria-labelledby=\"inventory\">");
        let _ = write!(
            out,
            "<div class=\"card-head\"><div><h2 id=\"inventory\" tabindex=\"-1\">{}</h2>\
             <p class=\"card-fact\">Showing {} of {} · {}</p></div>",
            tab.label(),
            rows.len(),
            total,
            esc(&self.sort_label())
        );
        out.push_str("</div>");
        self.render_controls(out, counts);
        if rows.is_empty() {
            out.push_str("<div class=\"no-rows\"><p>No results match these filters.</p>");
            let clear = self.q.apply(|next| {
                next.status = StatusFilter::All;
                next.q.clear();
                next.group.clear();
                next.tag.clear();
                next.open.clear();
            });
            let _ = write!(
                out,
                "<a class=\"button button-ghost\" href=\"{}#inventory\">Clear filters</a></div>",
                esc(&clear)
            );
        } else {
            self.render_table(out, &rows);
        }
        out.push_str("</section>");
    }

    fn render_controls(&self, out: &mut String, counts: Counts) {
        let tab = self.q.tab;
        out.push_str(
            "<form class=\"filters\" method=\"get\" action=\"#inventory\" role=\"search\">",
        );
        let _ = write!(
            out,
            "<input type=\"hidden\" name=\"tab\" value=\"{}\">",
            tab.as_str()
        );
        if self.q.status != StatusFilter::All {
            let _ = write!(
                out,
                "<input type=\"hidden\" name=\"status\" value=\"{}\">",
                status_param(self.q.status)
            );
        }
        out.push_str("<div class=\"field field-grow\"><label for=\"q\">Search</label>");
        let _ = write!(
            out,
            "<input id=\"q\" type=\"search\" name=\"q\" value=\"{}\" placeholder=\"Domain, {}, tag\" autocomplete=\"off\">",
            esc(&self.q.q),
            if tab == DashboardTab::Ssl { "issuer" } else { "registrar" }
        );
        out.push_str("</div>");
        self.render_select(
            out,
            "group",
            "Group",
            "All groups",
            &self.groups(),
            &self.q.group,
        );
        self.render_select(out, "tag", "Tag", "All tags", &self.tags(), &self.q.tag);
        out.push_str("<div class=\"field\"><label for=\"sort\">Sort</label><select id=\"sort\" name=\"sort\">");
        for (key, label) in [
            (SortKey::Attention, "Urgency"),
            (SortKey::Days, "Days left"),
            (SortKey::Domain, "Name"),
            (SortKey::Status, "Status"),
            (SortKey::Checked, "Last checked"),
        ] {
            let _ = write!(
                out,
                "<option value=\"{}\"{}>{}</option>",
                sort_param(key),
                if key == self.q.sort { " selected" } else { "" },
                label
            );
        }
        out.push_str("</select></div><div class=\"field\"><label for=\"dir\">Order</label><select id=\"dir\" name=\"dir\">");
        for (dir, label) in [(SortDir::Asc, "Ascending"), (SortDir::Desc, "Descending")] {
            let _ = write!(
                out,
                "<option value=\"{}\"{}>{}</option>",
                if dir == SortDir::Asc { "asc" } else { "desc" },
                if dir == self.q.dir { " selected" } else { "" },
                label
            );
        }
        out.push_str("</select></div><div class=\"field field-actions\">");
        out.push_str("<button class=\"button\" type=\"submit\">Apply</button>");
        let clear = self.q.apply(|next| {
            next.status = StatusFilter::All;
            next.q.clear();
            next.group.clear();
            next.tag.clear();
            next.open.clear();
        });
        let _ = write!(
            out,
            "<a class=\"button button-ghost\" href=\"{}#inventory\">Clear</a></div></form>",
            esc(&clear)
        );
        out.push_str("<nav class=\"pills\" aria-label=\"Filter by status\">");
        for (filter, label, count, name) in [
            (StatusFilter::All, "All", counts.all, "all"),
            (
                StatusFilter::Attention,
                "Needs attention",
                counts.attention,
                "attention",
            ),
            (StatusFilter::Soon, "≤ 30 days", counts.soon, "soon"),
            (StatusFilter::Urgent, "≤ 7 days", counts.urgent, "urgent"),
            (StatusFilter::Expired, "Expired", counts.expired, "expired"),
            (
                StatusFilter::Issues,
                if tab == DashboardTab::Ssl {
                    "Issues"
                } else {
                    "Unknown"
                },
                counts.issues,
                "issues",
            ),
            (
                StatusFilter::Valid,
                if tab == DashboardTab::Ssl {
                    "Valid"
                } else {
                    "Active"
                },
                counts.valid,
                "valid",
            ),
        ] {
            let active = filter == self.q.status;
            let href = self.q.apply(|next| {
                next.status = filter;
                next.open.clear();
            });
            let _ = write!(
                out,
                "<a class=\"pill{}\" href=\"{}#inventory\"{} data-filter=\"{}\">{}<span class=\"pill-count\">{}</span></a>",
                if active { " is-on" } else { "" },
                esc(&href),
                if active { " aria-current=\"true\"" } else { "" },
                name,
                esc(label),
                count
            );
        }
        out.push_str("</nav>");
    }

    fn render_select(
        &self,
        out: &mut String,
        id: &str,
        label: &str,
        all_label: &str,
        values: &[String],
        current: &str,
    ) {
        let _ = write!(
            out,
            "<div class=\"field\"><label for=\"{id}\">{label}</label><select id=\"{id}\" name=\"{id}\"><option value=\"\">{all_label}</option>",
            id = id,
            label = label,
            all_label = all_label
        );
        let mut found = values
            .iter()
            .any(|value| value.eq_ignore_ascii_case(current));
        for value in values {
            let _ = write!(
                out,
                "<option value=\"{}\"{}>{}</option>",
                esc(value),
                if value.eq_ignore_ascii_case(current) {
                    " selected"
                } else {
                    ""
                },
                esc(value)
            );
        }
        if !current.is_empty() && !found {
            found = true;
            let _ = write!(
                out,
                "<option value=\"{}\" selected>{}</option>",
                esc(current),
                esc(current)
            );
        }
        let _ = found;
        out.push_str("</select></div>");
    }

    fn render_table(&self, out: &mut String, rows: &[&Row]) {
        let tab = self.q.tab;
        let _ = write!(
            out,
            "<div class=\"table-scroll\"><table><caption class=\"sr-only\">{}: {} rows, {}</caption><thead><tr>",
            tab.label(),
            rows.len(),
            esc(&self.sort_label())
        );
        self.render_sort_header(out, "Domain", SortKey::Domain, "col-domain");
        self.render_sort_header(out, "Status", SortKey::Status, "col-status");
        self.render_sort_header(out, "Days left", SortKey::Days, "col-days");
        let _ = write!(
            out,
            "<th scope=\"col\" class=\"col-provider\">{}</th>",
            if tab == DashboardTab::Ssl {
                "Issuer"
            } else {
                "Registrar"
            }
        );
        out.push_str("<th scope=\"col\" class=\"col-expires\">Expires</th>");
        out.push_str("<th scope=\"col\" class=\"col-toggle\"><span class=\"sr-only\">Details</span></th>");
        out.push_str("</tr></thead><tbody>");
        for (index, row) in rows.iter().enumerate() {
            self.render_row(out, row, index);
        }
        out.push_str("</tbody></table></div>");
    }

    fn render_sort_header(&self, out: &mut String, label: &str, key: SortKey, class: &str) {
        let active = self.q.sort == key;
        let _ = write!(
            out,
            "<th scope=\"col\" class=\"{class}\"{}>",
            if active {
                format!(
                    " aria-sort=\"{}\"",
                    if self.q.dir == SortDir::Asc {
                        "ascending"
                    } else {
                        "descending"
                    }
                )
            } else {
                String::new()
            }
        );
        self.render_sort_header_inner(out, label, key);
        out.push_str("</th>");
    }

    fn render_sort_header_inner(&self, out: &mut String, label: &str, key: SortKey) {
        let active = self.q.sort == key;
        let next_dir = if active {
            self.q.dir.flip()
        } else {
            SortDir::Asc
        };
        let href = self.q.apply(|next| {
            next.sort = key;
            next.dir = next_dir;
            next.open.clear();
        });
        let _ = write!(
            out,
            "<a class=\"sort-link{}\" href=\"{}#inventory\"{}>{}<span class=\"sort-arrow\" aria-hidden=\"true\">{}</span></a>",
            if active { " is-on" } else { "" },
            esc(&href),
            if active {
                format!(
                    " aria-label=\"{} sorted {}. Reverse order\"",
                    esc(label),
                    if self.q.dir == SortDir::Asc { "ascending" } else { "descending" }
                )
            } else {
                String::new()
            },
            esc(label),
            if active {
                if self.q.dir == SortDir::Asc { "↑" } else { "↓" }
            } else {
                ""
            }
        );
        if active {
            let _ = write!(
                out,
                "<span class=\"sr-only\">sorted {}</span>",
                if self.q.dir == SortDir::Asc {
                    "ascending"
                } else {
                    "descending"
                }
            );
        }
    }

    fn render_row(&self, out: &mut String, row: &Row, index: usize) {
        let tab = self.q.tab;
        let open = self.row_open(row);
        let detail_id = format!("{}-{index}", stable_id(&row.key));
        out.push_str("<tr class=\"row\">");
        let _ = write!(
            out,
            "<th scope=\"row\" class=\"cell-domain\" data-label=\"Domain\">{}</th>",
            self.domain_html(row),
        );
        let _ = write!(
            out,
            "<td class=\"cell-status\" data-label=\"Status\">{}</td>",
            self.chip(row)
        );
        let _ = write!(
            out,
            "<td class=\"cell-days\" data-label=\"Days left\">{}</td>",
            self.days_html(row)
        );
        let _ = write!(
            out,
            "<td class=\"cell-provider\" data-label=\"{}\">{}</td>",
            if tab == DashboardTab::Ssl {
                "Issuer"
            } else {
                "Registrar"
            },
            if row.provider.is_empty() {
                "<span class=\"muted\">—</span>".to_string()
            } else {
                format!(
                    "<span title=\"{}\">{}</span>",
                    esc(&row.provider),
                    esc(&row.provider)
                )
            }
        );
        let expires = if row.expires_on.is_empty() {
            "<span class=\"muted\">—</span>".to_string()
        } else {
            format!(
                "<span title=\"{}\">{}</span>",
                esc(&row.not_after_title()),
                esc(&friendly_date(&row.expires_on))
            )
        };
        let _ = write!(
            out,
            "<td class=\"cell-expires\" data-label=\"Expires\">{}</td>",
            expires
        );
        let _ = write!(
            out,
            "<td class=\"cell-toggle\"><details{}><summary><span class=\"chev\" aria-hidden=\"true\"></span>\
             <span class=\"summary-word\" aria-hidden=\"true\">Details</span>\
             <span class=\"sr-only\">Details for {}</span></summary></details></td></tr>",
            if open { " open" } else { "" },
            esc(&row.domain)
        );
        let _ = write!(
            out,
            "<tr class=\"detail-row\" id=\"{}\"><td colspan=\"6\">",
            esc(&detail_id)
        );
        self.render_details(out, row);
        out.push_str("</td></tr>");
    }

    fn domain_html(&self, row: &Row) -> String {
        let port = match row.port {
            Some(port) if port != 443 => format!("<span class=\"port\">:{port}</span>"),
            _ => String::new(),
        };
        match https_url(row) {
            Some(url) => format!(
                "<a class=\"domain\" href=\"{}\" rel=\"noopener noreferrer\" title=\"Open {} in a new tab\">{}</a>{}",
                esc(&url),
                esc(&row.domain),
                esc(&row.domain),
                port
            ),
            None => format!("<span class=\"domain\">{}</span>{}", esc(&row.domain), port),
        }
    }

    fn render_details(&self, out: &mut String, row: &Row) {
        let tab = self.q.tab;
        out.push_str("<div class=\"detail-body\"><dl class=\"detail-grid\">");
        self.pair(out, "Status", &self.status_label(row));
        self.pair(
            out,
            if tab == DashboardTab::Ssl {
                "Issuer"
            } else {
                "Registrar"
            },
            non_empty(&row.provider, "Not available"),
        );
        self.pair(
            out,
            if tab == DashboardTab::Ssl {
                "Issued on"
            } else {
                "Purchased on"
            },
            &if row.issued_on.is_empty() {
                "Not available".to_string()
            } else {
                friendly_date(&row.issued_on)
            },
        );
        self.pair(
            out,
            if tab == DashboardTab::Ssl {
                "Expires on"
            } else {
                "Expiry date"
            },
            &if row.expires_on.is_empty() {
                "Not available".to_string()
            } else {
                friendly_date(&row.expires_on)
            },
        );
        self.pair(out, "Days left", &self.days_detail(row));
        if tab == DashboardTab::Ssl {
            if !row.not_after.is_empty() {
                self.pair(out, "Exact expiry", &exact_stamp(&row.not_after));
            }
            if !row.not_before.is_empty() {
                self.pair(out, "Not before", &exact_stamp(&row.not_before));
            }
            if let Some(port) = row.port {
                self.pair(out, "Port", &port.to_string());
            }
            if !row.checked_at.is_empty() {
                self.pair(out, "Checked at", &row.checked_at);
            }
            const SSL_OPTIONAL: &[(&str, &str)] = &[
                ("subject", "Subject"),
                ("issuer", "Issuer"),
                ("common_name", "Common name"),
                ("serial_number", "Serial number"),
                ("serial", "Serial number"),
                ("signature_algorithm", "Signature algorithm"),
                ("key_type", "Key type"),
                ("key_size", "Key size"),
                ("key_algorithm", "Key algorithm"),
                ("key_curve", "Key curve"),
                ("tls_version", "TLS version"),
                ("cipher", "Cipher"),
                ("subject_alt_names", "Subject alternative names"),
                ("sans", "Subject alternative names"),
                ("san", "Subject alternative names"),
                ("san_count", "SAN count"),
                ("wildcard", "Wildcard"),
                ("hostname_matches", "Hostname matches"),
                ("chain", "Certificate chain"),
                ("chain_valid", "Chain valid"),
                ("chain_length", "Chain length"),
                ("trusted_chain", "Trusted chain"),
                ("chain_source", "Chain source"),
                ("chain_error", "Chain error"),
                ("fingerprint_sha256", "SHA-256 fingerprint"),
                ("fingerprint", "Fingerprint"),
                ("ocsp_status", "OCSP status"),
                ("revocation_status", "Revocation status"),
                ("resolved_via", "Resolved via"),
            ];
            let mut seen_labels: Vec<&str> = Vec::new();
            for (key, label) in SSL_OPTIONAL {
                if seen_labels.contains(label) {
                    continue;
                }
                if let Some(value) = raw_field(&row.raw, key) {
                    seen_labels.push(label);
                    self.pair(out, label, &value);
                }
            }
            if !row.group.is_empty() {
                self.pair(out, "Group", &row.group);
            }
            if !row.tags.is_empty() {
                self.pair(out, "Tags", &row.tags.join(", "));
            }
            if !row.error.is_empty() {
                self.pair(out, "Error", &row.error);
            }
            if let Some(fallback) = row.raw.get("fallback") {
                let host = fallback
                    .get("domain")
                    .or_else(|| fallback.get("host"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !host.is_empty() {
                    self.pair(out, "Fallback host", host);
                    self.pair(
                        out,
                        "Fallback status",
                        fallback
                            .get("status")
                            .and_then(Value::as_str)
                            .unwrap_or("—"),
                    );
                }
            }
            if let Some(command) = openssl_command(row) {
                let _ = write!(
                    out,
                    "</dl><div class=\"command\"><p class=\"command-label\">OpenSSL check</p><code>{}</code></div>",
                    esc(&command)
                );
                out.push_str("</div>");
                return;
            }
        } else {
            if !row.checked_at.is_empty() {
                self.pair(out, "Checked at", &row.checked_at);
            }
            const DOMAIN_OPTIONAL: &[(&str, &str)] = &[
                ("nameservers", "Nameservers"),
                ("dnssec", "DNSSEC"),
                ("caa", "CAA records"),
                ("owner", "Owner"),
                ("tags", "Tags"),
                ("notes", "Notes"),
            ];
            let mut seen_labels: Vec<&str> = Vec::new();
            for (key, label) in DOMAIN_OPTIONAL {
                if seen_labels.contains(label) || *label == "Tags" && !row.tags.is_empty() {
                    continue;
                }
                if let Some(value) = raw_field(&row.raw, key) {
                    seen_labels.push(label);
                    self.pair(out, label, &value);
                }
            }
            if !row.group.is_empty() {
                self.pair(out, "Group", &row.group);
            }
            if !row.tags.is_empty() {
                self.pair(out, "Tags", &row.tags.join(", "));
            }
        }
        out.push_str("</dl></div>");
    }

    fn pair(&self, out: &mut String, label: &str, value: &str) {
        let _ = write!(
            out,
            "<div class=\"pair\"><dt>{}</dt><dd>{}</dd></div>",
            esc(label),
            esc(value)
        );
    }

    fn render_history(&self, out: &mut String) {
        let tab = self.q.tab;
        out.push_str("<section class=\"card history\" aria-labelledby=\"history-title\">");
        out.push_str("<div class=\"card-head\"><h2 id=\"history-title\">Expiry history</h2>");
        let series = self.series(tab);
        match (&self.history, series) {
            (HistLoad::Missing, _) => {
                out.push_str("</div><p class=\"empty-state\">History is not published yet.</p>");
                out.push_str("<p class=\"empty-meta\">It starts after the next scheduled run.</p>");
            }
            (HistLoad::Invalid, _) => {
                out.push_str("</div><p class=\"empty-state\">History could not be read.</p>");
                out.push_str("<p class=\"empty-meta\">Current results are unaffected.</p>");
            }
            (_, None) => {
                out.push_str("</div><p class=\"empty-state\">History is not available.</p>");
            }
            (_, Some(series)) if series.points.is_empty() => {
                out.push_str("</div><p class=\"empty-state\">No history snapshots yet.</p>");
            }
            (_, Some(series)) => {
                let peak = series
                    .points
                    .iter()
                    .map(|point| point.due)
                    .max()
                    .unwrap_or(0);
                let renewals = series
                    .points
                    .iter()
                    .map(|point| point.renewals)
                    .sum::<usize>();
                let _ = write!(
                    out,
                    "<p class=\"card-fact\">{} check{} · peak {} due ≤ 30 d · {} renewal{}</p></div>",
                    series.points.len(),
                    if series.points.len() == 1 { "" } else { "s" },
                    peak,
                    renewals,
                    if renewals == 1 { "" } else { "s" }
                );
                self.render_spark(out, series);
                out.push_str("<p class=\"axis-caption\" aria-hidden=\"true\"><span>");
                let _ = write!(out, "{}", esc(&short_date(&series.points[0].date)));
                out.push_str("</span><span>");
                let _ = write!(
                    out,
                    "{}",
                    esc(&short_date(&series.points[series.points.len() - 1].date))
                );
                out.push_str("</span></p>");
                if !series.renewals.is_empty() {
                    out.push_str("<p class=\"renewal-fact\">Renewed ");
                    for (index, renewal) in series.renewals.iter().rev().take(3).enumerate() {
                        if index > 0 {
                            out.push_str(" · ");
                        }
                        let _ = write!(
                            out,
                            "<span title=\"{}\">{}</span>",
                            esc(&renewal.domains.join(", ")),
                            esc(&short_date(&renewal.date))
                        );
                    }
                    out.push_str("</p>");
                }
                if let HistLoad::Ready(history) = &self.history {
                    if history.skipped > 0 {
                        let _ = write!(
                            out,
                            "<p class=\"rank-note\">{} snapshot{} could not be read.</p>",
                            history.skipped,
                            if history.skipped == 1 { "" } else { "s" }
                        );
                    }
                }
                let hidden_points = series.points.len().saturating_sub(HISTORY_TABLE_POINTS);
                if hidden_points > 0 {
                    let _ = write!(
                        out,
                        "<details class=\"history-data\"><summary>Show numbers (last {})</summary>",
                        HISTORY_TABLE_POINTS
                    );
                } else {
                    out.push_str("<details class=\"history-data\"><summary>Show numbers</summary>");
                }
                out.push_str("<table><caption class=\"sr-only\">Daily snapshots</caption><thead><tr><th scope=\"col\">Date</th><th scope=\"col\">Total</th><th scope=\"col\">≤ 30 d</th><th scope=\"col\">Expired</th></tr></thead><tbody>");
                let start = series.points.len().saturating_sub(HISTORY_TABLE_POINTS);
                for point in &series.points[start..] {
                    let _ = write!(
                        out,
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        esc(&point.date),
                        point.total,
                        point.due,
                        point.expired
                    );
                }
                out.push_str("</tbody></table></details>");
            }
        }
        out.push_str("</section>");
    }

    fn render_spark(&self, out: &mut String, series: &Series) {
        let points: Vec<&HistPoint> = {
            let start = series.points.len().saturating_sub(HISTORY_CHART_POINTS);
            series.points[start..].iter().collect()
        };
        let width = 560.0;
        let height = 128.0;
        let pad_x = 16.0;
        let pad_y = 16.0;
        let max = points
            .iter()
            .map(|point| point.due.max(point.expired))
            .max()
            .unwrap_or(0)
            .max(1) as f64;
        let count = points.len();
        let step = if count > 1 {
            (width - pad_x * 2.0) / (count - 1) as f64
        } else {
            0.0
        };
        let mut coords: Vec<(f64, f64, &HistPoint)> = Vec::new();
        for (index, point) in points.iter().enumerate() {
            let x = pad_x + step * index as f64;
            let y = height - pad_y - (point.due as f64 / max) * (height - pad_y * 2.0);
            coords.push((x, y, point));
        }
        let window_peak = points.iter().map(|point| point.due).max().unwrap_or(0);
        let overall_peak = series
            .points
            .iter()
            .map(|point| point.due)
            .max()
            .unwrap_or(0);
        let show_peak = window_peak == overall_peak;
        let total_checks = series.points.len();
        let renewals: Vec<(f64, &str)> = coords
            .iter()
            .filter(|(_, _, point)| point.renewals > 0)
            .map(|(x, _, point)| (*x, point.date.as_str()))
            .collect();
        let renewal_total = series
            .points
            .iter()
            .map(|point| point.renewals)
            .sum::<usize>();
        let renewal_word = if renewal_total == 1 {
            "renewal"
        } else {
            "renewals"
        };
        let label = if total_checks > points.len() {
            format!(
                "{} expiry history: last {} of {} checks, peak {} due within 30 days, {} {}",
                self.q.tab.label(),
                points.len(),
                total_checks,
                overall_peak,
                renewal_total,
                renewal_word
            )
        } else {
            format!(
                "{} expiry history: {} check{}, peak {} due within 30 days, {} {}",
                self.q.tab.label(),
                total_checks,
                if total_checks == 1 { "" } else { "s" },
                overall_peak,
                renewal_total,
                renewal_word
            )
        };
        let _ = write!(
            out,
            "<div class=\"chart\"><svg class=\"spark\" viewBox=\"0 0 {width} {height}\" role=\"img\" aria-label=\"{}\">",
            esc(&label)
        );
        out.push_str("<line class=\"grid\" x1=\"16\" y1=\"112\" x2=\"544\" y2=\"112\"></line>");
        out.push_str("<line class=\"grid\" x1=\"16\" y1=\"16\" x2=\"544\" y2=\"16\"></line>");
        if !coords.is_empty() {
            let mut area = format!("M{:.1} 112", coords[0].0);
            for (x, y, _) in &coords {
                area.push_str(&format!(" L{x:.1} {y:.1}"));
            }
            area.push_str(&format!(" L{:.1} 112 Z", coords[coords.len() - 1].0));
            let mut line = String::new();
            for (index, (x, y, _)) in coords.iter().enumerate() {
                line.push_str(if index == 0 { "M" } else { " L" });
                line.push_str(&format!("{x:.1} {y:.1}"));
            }
            let _ = write!(
                out,
                "<path class=\"area\" d=\"{}\"></path><path class=\"line\" d=\"{}\"></path>",
                area, line
            );
        }
        for (x, date) in &renewals {
            let _ = write!(
                out,
                "<line class=\"renewal-line\" x1=\"{x:.1}\" y1=\"16\" x2=\"{x:.1}\" y2=\"112\"><title>Renewal on {}</title></line>",
                esc(date)
            );
        }
        for (x, y, point) in &coords {
            let _ = write!(
                out,
                "<circle class=\"pt\" cx=\"{x:.1}\" cy=\"{y:.1}\" r=\"3\"><title>{}: {} due ≤ 30 d, {} expired</title></circle>",
                esc(&point.date),
                point.due,
                point.expired
            );
        }
        if let Some((x, y, _)) = coords.last() {
            let _ = write!(
                out,
                "<circle class=\"last\" cx=\"{x:.1}\" cy=\"{y:.1}\" r=\"4\"></circle>"
            );
        }
        if show_peak && window_peak > 0 {
            if let Some((x, y, _)) = coords.iter().max_by_key(|(_, _, point)| point.due) {
                let _ = write!(
                    out,
                    "<text class=\"peak\" x=\"{:.1}\" y=\"{:.1}\">peak {}</text>",
                    x.min(width - 76.0).max(16.0),
                    (y - 8.0).max(14.0),
                    window_peak
                );
            }
        }
        out.push_str("</svg></div>");
    }

    fn render_distribution(&self, out: &mut String, payload: &Payload) {
        let tab = self.q.tab;
        let field = if tab == DashboardTab::Ssl {
            "Issuer"
        } else {
            "Registrar"
        };
        let mut counts: Vec<(String, usize)> = Vec::new();
        for row in &payload.rows {
            let name = if row.provider.is_empty() {
                "Not recorded".to_string()
            } else {
                row.provider.clone()
            };
            match counts
                .iter_mut()
                .find(|(key, _)| key.eq_ignore_ascii_case(&name))
            {
                Some((_, count)) => *count += 1,
                None => counts.push((name, 1)),
            }
        }
        counts.sort_by(|left, right| {
            right
                .1
                .cmp(&left.1)
                .then_with(|| left.0.to_lowercase().cmp(&right.0.to_lowercase()))
        });
        let total = payload.rows.len().max(1);
        let distinct = counts.len();
        let mut folded = false;
        if counts.len() > 6 {
            let tail: usize = counts[6..].iter().map(|(_, count)| count).sum();
            counts.truncate(6);
            counts.push(("Other".to_string(), tail));
            folded = true;
        }
        out.push_str("<section class=\"card distribution\" aria-labelledby=\"dist-title\">");
        let _ = write!(
            out,
            "<div class=\"card-head\"><h2 id=\"dist-title\">{}</h2><p class=\"card-fact\">{} {} · {} {}</p></div>",
            if tab == DashboardTab::Ssl { "Issuers" } else { "Registrars" },
            distinct,
            match (tab, distinct == 1) {
                (DashboardTab::Ssl, true) => "issuer",
                (DashboardTab::Ssl, false) => "issuers",
                (DashboardTab::Domains, true) => "registrar",
                (DashboardTab::Domains, false) => "registrars",
            },
            payload.rows.len(),
            if payload.rows.len() == 1 { tab.noun() } else { tab.noun_plural() }
        );
        if counts.is_empty() {
            let _ = write!(
                out,
                "<p class=\"empty-state\">No {} data.</p>",
                field.to_lowercase()
            );
        } else {
            out.push_str("<ul class=\"ranks\">");
            for (name, count) in &counts {
                let percent = share_text(*count, total);
                let _ = write!(
                    out,
                    "<li class=\"rank\"><span class=\"rank-name\" title=\"{}\">{}</span><span class=\"rank-count\">{}</span><span class=\"rank-share\">{}</span><span class=\"rank-track\" aria-hidden=\"true\"><span class=\"rank-fill\" style=\"width:{:.1}%\"></span></span><span class=\"sr-only\">{} of {} {}</span></li>",
                    esc(name),
                    esc(name),
                    count,
                    percent,
                    (*count as f64 / total as f64) * 100.0,
                    count,
                    total,
                    if total == 1 { tab.noun() } else { tab.noun_plural() }
                );
            }
            out.push_str("</ul>");
            if folded {
                out.push_str("<p class=\"rank-note\">Top 6 shown</p>");
            }
        }
        out.push_str("</section>");
    }

    fn render_footer(&self, out: &mut String) {
        let _ = write!(
            out,
            "<footer class=\"foot\"><span class=\"foot-name\">CertiWatch <span class=\"foot-version\">v{}</span></span>\
             <a class=\"foot-repo\" href=\"https://github.com/nooblk-98/certiwatch\" target=\"_blank\" rel=\"noopener noreferrer\">\
             <svg viewBox=\"0 0 16 16\" width=\"14\" height=\"14\" aria-hidden=\"true\" focusable=\"false\"><path fill=\"currentColor\" d=\"M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z\"/></svg>\
             GitHub</a></footer>",
            env!("CARGO_PKG_VERSION")
        );
    }

    // ── Cell helpers ────────────────────────────────────────────────────────

    fn chip(&self, row: &Row) -> String {
        format!(
            "<span class=\"{}\"><span class=\"chip-dot\" aria-hidden=\"true\"></span>{}</span>",
            row.cat.chip_class(),
            esc(&self.status_label(row))
        )
    }

    fn status_label(&self, row: &Row) -> String {
        let tab = self.q.tab;
        match row.cat {
            Cat::Expired => "Expired".to_string(),
            Cat::Today => "Expires today".to_string(),
            Cat::Urgent => "≤ 7 days".to_string(),
            Cat::Warn => "8–30 days".to_string(),
            Cat::Ok => {
                if tab == DashboardTab::Ssl {
                    "Valid".to_string()
                } else {
                    "Active".to_string()
                }
            }
            Cat::Invalid => "Invalid".to_string(),
            Cat::Unknown => "Unknown".to_string(),
            Cat::Error => match row.status.as_str() {
                "dns_error" => "DNS error".to_string(),
                "timeout" => "Timeout".to_string(),
                "ssl_error" => "TLS error".to_string(),
                "no_https" => "No HTTPS".to_string(),
                _ => "Error".to_string(),
            },
        }
    }

    fn days_text(&self, row: &Row) -> String {
        match row.cat {
            Cat::Expired => match row.days {
                Some(days) if days < 0 => format!("{} d ago", days.abs()),
                _ => "expired".to_string(),
            },
            Cat::Today => "today".to_string(),
            _ => match row.days {
                Some(days) if days >= 0 => format!("{days} d"),
                _ => "no date".to_string(),
            },
        }
    }

    fn days_detail(&self, row: &Row) -> String {
        match row.cat {
            Cat::Expired => match row.days {
                Some(days) if days < 0 => {
                    let ago = days.abs();
                    format!("Expired {ago} day{} ago", if ago == 1 { "" } else { "s" })
                }
                _ => "Expired".to_string(),
            },
            Cat::Today => "Expires today".to_string(),
            _ => match row.days {
                Some(1) => "1 day left".to_string(),
                Some(days) if days >= 0 => format!("{days} days left"),
                _ => "Not available".to_string(),
            },
        }
    }

    fn days_html(&self, row: &Row) -> String {
        if matches!(row.cat, Cat::Error | Cat::Invalid | Cat::Unknown) || row.days.is_none() {
            return "<span class=\"muted\">—</span>".to_string();
        }
        let days = row.days.unwrap_or(0);
        let percent = if row.cat == Cat::Expired {
            0.0
        } else {
            if days <= 0 { 3.0 } else { ((days as f64 / 90.0) * 100.0).clamp(4.0, 100.0) }
        };
        let tone = match row.cat {
            Cat::Today | Cat::Urgent => "days-hot",
            Cat::Warn => "days-warm",
            Cat::Expired => "days-bad",
            _ => "days-ok",
        };
        let text = self.days_text(row);
        format!(
            "<span class=\"sr-only\">{}</span><span class=\"days\" aria-hidden=\"true\"><span class=\"days-track\"><span class=\"days-fill {}\" style=\"width:{:.1}%\"></span></span><span class=\"days-value\">{}</span></span>",
            esc(&self.days_detail(row)),
            tone,
            percent,
            esc(&text)
        )
    }

    fn sort_label(&self) -> String {
        match (self.q.sort, self.q.dir) {
            (SortKey::Attention, SortDir::Asc) => "most urgent first".to_string(),
            (SortKey::Attention, SortDir::Desc) => "least urgent first".to_string(),
            (SortKey::Days, SortDir::Asc) => "soonest first".to_string(),
            (SortKey::Days, SortDir::Desc) => "furthest first".to_string(),
            (SortKey::Domain, SortDir::Asc) => "name A–Z".to_string(),
            (SortKey::Domain, SortDir::Desc) => "name Z–A".to_string(),
            (SortKey::Status, SortDir::Asc) => "status, worst first".to_string(),
            (SortKey::Status, SortDir::Desc) => "status, best first".to_string(),
            (SortKey::Checked, SortDir::Asc) => "oldest check first".to_string(),
            (SortKey::Checked, SortDir::Desc) => "newest check first".to_string(),
        }
    }
}

impl Row {
    fn not_after_title(&self) -> String {
        if self.not_after.is_empty() {
            self.expires_on.clone()
        } else {
            self.not_after.clone()
        }
    }
}

fn non_empty<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

fn raw_field(raw: &Value, key: &str) -> Option<String> {
    let value = raw.get(key)?;
    match value {
        Value::Null => None,
        Value::String(text) => {
            let text = clip(text.trim(), 600);
            if text.is_empty() || text.eq_ignore_ascii_case("n/a") {
                None
            } else {
                Some(text)
            }
        }
        Value::Bool(flag) => Some(if *flag { "Yes" } else { "No" }.to_string()),
        Value::Number(number) => Some(number.to_string()),
        Value::Array(items) => {
            let parts: Vec<String> = items
                .iter()
                .filter_map(scalar_text)
                .filter(|text| !text.is_empty())
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(clip(&parts.join(", "), 600))
            }
        }
        Value::Object(map) => {
            if map.is_empty() || map.len() > 8 {
                return None;
            }
            let parts: Vec<String> = map
                .iter()
                .filter_map(|(key, value)| scalar_text(value).map(|text| format!("{key}: {text}")))
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(clip(&parts.join("; "), 600))
            }
        }
    }
}

fn https_url(row: &Row) -> Option<String> {
    let port_ok = row.port.is_none() || row.port == Some(443);
    if !port_ok || row.domain.contains(':') {
        return None;
    }
    if row.domain.len() > 253 || !row.domain.contains('.') {
        return None;
    }
    let labels: Vec<&str> = row.domain.split('.').collect();
    if labels.iter().any(|label| {
        label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    }) {
        return None;
    }
    Some(format!("https://{}/", row.domain))
}

fn openssl_command(row: &Row) -> Option<String> {
    if row.port.is_some() && row.port != Some(443) {
        // Still useful: an explicit port is part of the endpoint.
    }
    let host = row.domain.split(':').next()?;
    if host.is_empty() || !host.contains('.') {
        return None;
    }
    if !host
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
    {
        return None;
    }
    let port = row.port.unwrap_or(443);
    Some(format!(
        "openssl s_client -connect {host}:{port} -servername {host} -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256"
    ))
}

fn share_text(part: usize, total: usize) -> String {
    if total == 0 || part == 0 {
        return "0%".to_string();
    }
    let percent = (part as f64 / total as f64) * 100.0;
    if percent < 1.0 {
        "<1%".to_string()
    } else {
        format!("{:.0}%", percent)
    }
}

fn stable_id(key: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in key.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("r-{hash:016x}")
}

// ── Static icons ─────────────────────────────────────────────────────────────

const CHECK_ICON: &str = "<svg viewBox=\"0 0 20 20\" width=\"16\" height=\"16\" aria-hidden=\"true\" focusable=\"false\"><path d=\"M3.5 10.5 8 15l8.5-10\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg>";
const CLOCK_ICON: &str = "<svg viewBox=\"0 0 20 20\" width=\"16\" height=\"16\" aria-hidden=\"true\" focusable=\"false\"><circle cx=\"10\" cy=\"10\" r=\"7\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.2\"/><path d=\"M10 5.8V10l3 1.8\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.2\" stroke-linecap=\"round\"/></svg>";
const ALERT_ICON: &str = "<svg viewBox=\"0 0 20 20\" width=\"16\" height=\"16\" aria-hidden=\"true\" focusable=\"false\"><path d=\"M10 3 17.5 16.5h-15L10 3Z\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.2\" stroke-linejoin=\"round\"/><path d=\"M10 8v3.6\" stroke=\"currentColor\" stroke-width=\"1.4\" stroke-linecap=\"round\"/><circle cx=\"10\" cy=\"14\" r=\".9\" fill=\"currentColor\"/></svg>";
const BAN_ICON: &str = "<svg viewBox=\"0 0 20 20\" width=\"16\" height=\"16\" aria-hidden=\"true\" focusable=\"false\"><circle cx=\"10\" cy=\"10\" r=\"7\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.2\"/><path d=\"M5 5l10 10\" stroke=\"currentColor\" stroke-width=\"1.2\"/></svg>";
const PLUG_ICON: &str = "<svg viewBox=\"0 0 20 20\" width=\"16\" height=\"16\" aria-hidden=\"true\" focusable=\"false\"><path d=\"M7.5 3v4M12.5 3v4M5.5 7h9v2.5a4.5 4.5 0 0 1-9 0V7ZM10 14v3\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.2\" stroke-linecap=\"round\"/></svg>";
const LAYERS_ICON: &str = "<svg viewBox=\"0 0 20 20\" width=\"16\" height=\"16\" aria-hidden=\"true\" focusable=\"false\"><path d=\"m10 2.8 7 3.8-7 3.8-7-3.8 7-3.8Z\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.2\" stroke-linejoin=\"round\"/><path d=\"m3 10 7 3.8 7-3.8M3 13.4l7 3.8 7-3.8\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.2\" stroke-linejoin=\"round\"/></svg>";
const SETUP_ICON: &str = "<div class=\"state-icon state-setup\" aria-hidden=\"true\"><svg viewBox=\"0 0 24 24\" width=\"22\" height=\"22\"><path d=\"M4 6.5h16M4 12h16M4 17.5h10\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.4\" stroke-linecap=\"round\"/></svg></div>";

// ── Tests ────────────────────────────────────────────────────────────────────
