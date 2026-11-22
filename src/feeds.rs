//! Public feeds: status summary, RFC 5545 calendar and SVG badges.
//!
//! Output is deterministic and allow-listed. Only a fixed schema is emitted:
//! raw checker error text, configuration, paths and credentials never reach a
//! feed. Categories mirror the server-rendered dashboard.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDate, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::results::{BADGES_DIR, CALENDAR_FILE, MANIFEST_FILE, STATUS_FILE};

pub const SCHEMA_VERSION: i64 = 1;

const SSL_VERDICTS: &[&str] = &["valid", "expired", "invalid"];
const SSL_UNREACHABLE: &[&str] = &["dns_error", "timeout", "no_https", "ssl_error", "error"];
const REGISTRATION_STATUSES: &[&str] = &["active", "valid", "warning", "warn", "urgent", "expired"];
const MAX_TEXT: usize = 200;
const MAX_LABEL: usize = 30;

const BADGE_STYLES: &[(&str, &str, &str)] = &[
    ("ok", "#2f855a", "ok"),
    ("warning", "#b7791f", "warning"),
    ("critical", "#c53030", "critical"),
    ("unknown", "#718096", "unknown"),
];

#[derive(Debug, Clone)]
pub struct FeedError {
    pub message: String,
    pub code: i32,
}

impl FeedError {
    fn new(message: impl Into<String>) -> Self {
        FeedError {
            message: message.into(),
            code: 1,
        }
    }

    fn unsafe_path(message: impl Into<String>) -> Self {
        FeedError {
            message: message.into(),
            code: 2,
        }
    }
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FeedError {}

#[derive(Debug, Clone)]
struct SslRow {
    domain: String,
    status: String,
    category: String,
    expires_on: Option<NaiveDate>,
    days_left: Option<i64>,
    provider: Option<String>,
}

#[derive(Debug, Clone)]
struct RegistrationRow {
    domain: String,
    status: String,
    category: String,
    expires_on: Option<NaiveDate>,
    days_left: Option<i64>,
    registrar: Option<String>,
}

// ── Input validation ─────────────────────────────────────────────────────────

fn status_token_re() -> &'static Regex {
    static STATUS: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    STATUS.get_or_init(|| Regex::new(r"^[a-z][a-z0-9_]{0,31}$").expect("static regex"))
}

fn dns_label_re() -> &'static Regex {
    static LABEL: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    LABEL.get_or_init(|| {
        Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").expect("static regex")
    })
}

fn badge_file_re() -> &'static Regex {
    static BADGE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    BADGE.get_or_init(|| {
        Regex::new(r"^badges/[a-z0-9-]{1,40}-[0-9a-f]{32}\.svg$").expect("static regex")
    })
}

pub fn reject_symlinked_path(source: &Path, rel: &str) -> Result<(), FeedError> {
    let mut current = source.to_path_buf();
    for part in rel.split('/') {
        current.push(part);
        if current.is_symlink() {
            return Err(FeedError::unsafe_path(format!(
                "input {rel:?} is a symlink; refusing to read it"
            )));
        }
    }
    Ok(())
}

pub fn parse_timestamp(value: &str, where_: &str) -> Result<DateTime<Utc>, FeedError> {
    let text = value.trim();
    if let Some(stripped) = text.strip_suffix(" UTC") {
        let stripped = stripped.replacen(' ', "T", 1);
        for format in ["%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"] {
            if let Ok(parsed) = NaiveDateTime::parse_from_str(&stripped, format) {
                return Ok(Utc.from_utc_datetime(&parsed));
            }
        }
        if let Ok(date) = NaiveDate::parse_from_str(&stripped, "%Y-%m-%d") {
            return Ok(Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0).unwrap()));
        }
    }
    if let Some(stripped) = text.strip_suffix('Z') {
        let stripped = stripped.replacen(' ', "T", 1);
        for format in ["%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"] {
            if let Ok(parsed) = NaiveDateTime::parse_from_str(&stripped, format) {
                return Ok(Utc.from_utc_datetime(&parsed));
            }
        }
    }
    if let Ok(parsed) = DateTime::parse_from_rfc3339(text) {
        return Ok(parsed.with_timezone(&Utc));
    }
    let iso_candidate = text.replacen(' ', "T", 1);
    if let Ok(parsed) = DateTime::parse_from_rfc3339(&iso_candidate) {
        return Ok(parsed.with_timezone(&Utc));
    }
    if let Ok(parsed) = NaiveDateTime::parse_from_str(&iso_candidate, "%Y-%m-%dT%H:%M:%S") {
        return Ok(Utc.from_utc_datetime(&parsed));
    }
    if let Ok(parsed) = NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S") {
        return Ok(Utc.from_utc_datetime(&parsed));
    }
    Err(FeedError::new(format!(
        "{where_}: unsupported timestamp {value:?}"
    )))
}

fn parse_port(value: &str, where_: &str) -> Result<u16, FeedError> {
    if value.is_empty() || !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(FeedError::new(format!("{where_}: port must be a number")));
    }
    let port: u32 = value
        .parse()
        .map_err(|_| FeedError::new(format!("{where_}: port must be a number")))?;
    if !(1..=65535).contains(&port) {
        return Err(FeedError::new(format!(
            "{where_}: port {port} is outside 1-65535"
        )));
    }
    Ok(port as u16)
}

fn split_host_port(text: &str, where_: &str) -> Result<(String, u16, bool), FeedError> {
    if let Some(rest) = text.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(FeedError::new(format!(
                "{where_}: unterminated IPv6 literal"
            )));
        };
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        let address: Ipv6Addr = host
            .parse()
            .map_err(|_| FeedError::new(format!("{where_}: invalid IPv6 literal")))?;
        let port = if tail.is_empty() {
            443
        } else if let Some(port) = tail.strip_prefix(':') {
            parse_port(port, where_)?
        } else {
            return Err(FeedError::new(format!(
                "{where_}: unexpected text after IPv6 literal"
            )));
        };
        return Ok((address.to_string(), port, true));
    }

    if text.matches(':').count() > 1 {
        return Err(FeedError::new(format!(
            "{where_}: IPv6 literals must be bracketed"
        )));
    }
    if let Some((host, port)) = text.rsplit_once(':') {
        return Ok((host.to_string(), parse_port(port, where_)?, false));
    }
    Ok((text.to_string(), 443, false))
}

/// Validate and canonicalise a host key used in output paths and keys.
pub fn canonical_domain(raw: Option<&Value>, where_: &str) -> Result<String, FeedError> {
    let raw = raw
        .and_then(Value::as_str)
        .ok_or_else(|| FeedError::new(format!("{where_}: domain must be a string")))?;
    let text = raw.trim();
    if text.is_empty() {
        return Err(FeedError::new(format!("{where_}: empty domain")));
    }
    if text
        .chars()
        .any(|ch| (ch as u32) < 0x20 || (ch as u32) == 0x7F)
    {
        return Err(FeedError::new(format!(
            "{where_}: domain contains a control character"
        )));
    }
    if text.chars().any(char::is_whitespace) {
        return Err(FeedError::new(format!(
            "{where_}: domain contains whitespace"
        )));
    }
    if text.contains("://")
        || text
            .chars()
            .any(|ch| matches!(ch, '/' | '\\' | '@' | '#' | '?'))
    {
        return Err(FeedError::new(format!(
            "{where_}: {raw:?} is not a host key"
        )));
    }

    let (host, port, is_ipv6) = split_host_port(text, where_)?;
    let host_part = if is_ipv6 {
        format!("[{host}]")
    } else if let Ok(address) = host.parse::<IpAddr>() {
        if !matches!(address, IpAddr::V4(_)) {
            return Err(FeedError::new(format!(
                "{where_}: IPv6 literals must be bracketed"
            )));
        }
        if let IpAddr::V4(v4) = address {
            v4.to_string()
        } else {
            unreachable!()
        }
    } else {
        let host = host.trim_end_matches('.').to_lowercase();
        if host.is_empty() || host.len() > 253 {
            return Err(FeedError::new(format!("{where_}: invalid host length")));
        }
        if host.split('.').any(|label| !dns_label_re().is_match(label)) {
            return Err(FeedError::new(format!(
                "{where_}: {raw:?} is not a valid host name"
            )));
        }
        host
    };
    Ok(if port == 443 {
        host_part
    } else {
        format!("{host_part}:{port}")
    })
}

fn clean_text(value: Option<&Value>, where_: &str) -> Result<Option<String>, FeedError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let text = value
        .as_str()
        .ok_or_else(|| FeedError::new(format!("{where_}: expected text")))?;
    let cleaned: String = text
        .chars()
        .map(|ch| {
            if (ch as u32) < 0x20 || (0x7F..=0x9F).contains(&(ch as u32)) {
                ' '
            } else {
                ch
            }
        })
        .collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.is_empty() {
        Ok(None)
    } else {
        Ok(Some(cleaned.chars().take(MAX_TEXT).collect()))
    }
}

pub fn parse_status(value: Option<&Value>, where_: &str) -> Result<String, FeedError> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| FeedError::new(format!("{where_}: status must be a string")))?;
    let status = text.trim().to_lowercase();
    if !status_token_re().is_match(&status) {
        return Err(FeedError::new(format!(
            "{where_}: invalid status {value:?}"
        )));
    }
    Ok(status)
}

fn parse_days(value: Option<&Value>, where_: &str) -> Result<Option<i64>, FeedError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_i64()
        .map(Some)
        .ok_or_else(|| FeedError::new(format!("{where_}: days_left must be an integer or null")))
}

fn parse_expiry(value: Option<&Value>, where_: &str) -> Result<Option<NaiveDate>, FeedError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let text = value
        .as_str()
        .ok_or_else(|| FeedError::new(format!("{where_}: expiry must be a date string or null")))?
        .trim();
    if text.is_empty()
        || matches!(
            text.to_uppercase().as_str(),
            "N/A" | "NA" | "UNKNOWN" | "NONE"
        )
    {
        return Ok(None);
    }
    if text.len() == 10 {
        if let Ok(date) = NaiveDate::parse_from_str(text, "%Y-%m-%d") {
            return Ok(Some(date));
        }
    }
    if let Ok(date) = NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        return Ok(Some(date));
    }
    if let Ok(parsed) = DateTime::parse_from_rfc3339(&text.replace('Z', "+00:00")) {
        return Ok(Some(parsed.date_naive()));
    }
    if let Ok(parsed) = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S") {
        return Ok(Some(parsed.date()));
    }
    Err(FeedError::new(format!("{where_}: invalid date {value:?}")))
}

// ── Classification (mirrors the dashboard) ───────────────────────────────────

pub fn ssl_category(status: &str, days: Option<i64>, is_expired: Option<bool>) -> String {
    if is_expired == Some(true) || status == "expired" {
        return "expired".into();
    }
    if status == "valid" {
        return match days {
            None => "valid".into(),
            Some(days) if days <= 0 => "today".into(),
            Some(days) if days <= 7 => "urgent".into(),
            Some(days) if days <= 30 => "warning".into(),
            Some(_) => "valid".into(),
        };
    }
    if status == "invalid" {
        return "invalid".into();
    }
    if SSL_UNREACHABLE.contains(&status) {
        return "error".into();
    }
    "unknown".into()
}

pub fn registration_category(status: &str, days: Option<i64>) -> String {
    if status == "expired" {
        return "expired".into();
    }
    if status == "active" || status == "valid" {
        return match days {
            None => "active".into(),
            Some(days) if days <= 0 => "expired".into(),
            Some(days) if days <= 7 => "urgent".into(),
            Some(days) if days <= 30 => "warning".into(),
            Some(_) => "active".into(),
        };
    }
    if status == "urgent" {
        return "urgent".into();
    }
    if status == "warning" || status == "warn" {
        return "warning".into();
    }
    "unknown".into()
}

pub fn registration_bucket(status: &str) -> &'static str {
    if !REGISTRATION_STATUSES.contains(&status) {
        return "unknown";
    }
    match status {
        "active" | "valid" => "active",
        "warning" | "warn" => "warning",
        "urgent" => "urgent",
        "expired" => "expired",
        _ => "unknown",
    }
}

/// A check that is not configured for this deployment is ignored; a check that
/// is configured but produced no row for this domain is a warning.
fn domain_status_scoped(
    certificate: Option<&SslRow>,
    registration: Option<&RegistrationRow>,
    certificate_checked: bool,
    registration_checked: bool,
) -> String {
    let mut categories: Vec<&str> = Vec::new();
    if let Some(certificate) = certificate {
        categories.push(certificate.category.as_str());
    }
    if let Some(registration) = registration {
        categories.push(registration.category.as_str());
    }
    if categories
        .iter()
        .any(|category| matches!(*category, "expired" | "today" | "invalid"))
    {
        return "critical".into();
    }
    if certificate_checked && certificate.is_none() {
        return "warning".into();
    }
    if registration_checked && registration.is_none() {
        return "warning".into();
    }
    if !certificate_checked && !registration_checked {
        return "unknown".into();
    }
    if categories.iter().all(|category| *category == "unknown") {
        return "unknown".into();
    }
    if categories
        .iter()
        .any(|category| !matches!(*category, "valid" | "active"))
    {
        return "warning".into();
    }
    "ok".into()
}

/// Aggregate one domain from already-classified check categories.
pub fn domain_status_from_categories(
    certificate: Option<&str>,
    registration: Option<&str>,
) -> String {
    let categories: Vec<&str> = [certificate, registration].into_iter().flatten().collect();
    if categories
        .iter()
        .any(|category| matches!(*category, "expired" | "today" | "invalid"))
    {
        return "critical".into();
    }
    if certificate.is_none() || registration.is_none() {
        return "warning".into();
    }
    if categories.iter().all(|category| *category == "unknown") {
        return "unknown".into();
    }
    if categories
        .iter()
        .any(|category| !matches!(*category, "valid" | "active"))
    {
        return "warning".into();
    }
    "ok".into()
}

pub fn overall_status(statuses: &[String]) -> String {
    if statuses.iter().any(|status| status == "critical") {
        return "critical".into();
    }
    if !statuses.is_empty() && statuses.iter().all(|status| status == "unknown") {
        return "unknown".into();
    }
    if statuses
        .iter()
        .any(|status| status == "warning" || status == "unknown")
    {
        return "warning".into();
    }
    "ok".into()
}

// ── Normalisation ────────────────────────────────────────────────────────────

fn normalise_ssl_row(row: &Value, where_: &str) -> Result<SslRow, FeedError> {
    if !row.is_object() {
        return Err(FeedError::new(format!("{where_}: expected an object")));
    }
    let domain = canonical_domain(row.get("domain"), &format!("{where_}: domain"))?;
    let status = parse_status(row.get("status"), &format!("{where_}: status"))?;
    let days = parse_days(row.get("days_left"), &format!("{where_}: days_left"))?;
    let is_expired = match row.get("is_expired") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(value)) => Some(*value),
        Some(_) => {
            return Err(FeedError::new(format!(
                "{where_}: is_expired must be a boolean or null"
            )))
        }
    };
    Ok(SslRow {
        category: ssl_category(&status, days, is_expired),
        expires_on: parse_expiry(row.get("expires_on"), &format!("{where_}: expires_on"))?,
        provider: clean_text(row.get("provider"), &format!("{where_}: provider"))?,
        domain,
        status,
        days_left: days,
    })
}

fn normalise_registration_row(row: &Value, where_: &str) -> Result<RegistrationRow, FeedError> {
    if !row.is_object() {
        return Err(FeedError::new(format!("{where_}: expected an object")));
    }
    let domain = canonical_domain(row.get("domain"), &format!("{where_}: domain"))?;
    let status = parse_status(row.get("status"), &format!("{where_}: status"))?;
    let days = parse_days(row.get("days_left"), &format!("{where_}: days_left"))?;
    Ok(RegistrationRow {
        category: registration_category(&status, days),
        expires_on: parse_expiry(row.get("expiry_date"), &format!("{where_}: expiry_date"))?,
        registrar: clean_text(row.get("registrar"), &format!("{where_}: registrar"))?,
        domain,
        status,
        days_left: days,
    })
}

fn index_rows<T>(
    rows: &[Value],
    label: &str,
    normaliser: fn(&Value, &str) -> Result<T, FeedError>,
) -> Result<BTreeMap<String, T>, FeedError>
where
    T: DomainRow,
{
    let mut indexed = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        let item = normaliser(row, &format!("{label} row {}", index + 1))?;
        let domain = item.domain().to_string();
        if indexed.contains_key(&domain) {
            return Err(FeedError::new(format!(
                "{label}: duplicate domain {domain:?}; refusing to guess"
            )));
        }
        indexed.insert(domain, item);
    }
    Ok(indexed)
}

trait DomainRow {
    fn domain(&self) -> &str;
}

impl DomainRow for SslRow {
    fn domain(&self) -> &str {
        &self.domain
    }
}

impl DomainRow for RegistrationRow {
    fn domain(&self) -> &str {
        &self.domain
    }
}

// ── Output helpers ───────────────────────────────────────────────────────────

pub fn xml_escape(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|ch| {
            if ((ch as u32) < 0x20 && !matches!(ch, '\t' | '\n' | '\r'))
                || (0x7F..=0x9F).contains(&(ch as u32))
            {
                ' '
            } else {
                ch
            }
        })
        .collect();
    cleaned
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[allow(clippy::collapsible_str_replace)]
pub fn ics_escape(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|ch| {
            if ((ch as u32) < 0x20 && !matches!(ch, '\t' | '\n' | '\r'))
                || (0x7F..=0x9F).contains(&(ch as u32))
            {
                ' '
            } else {
                ch
            }
        })
        .collect();
    cleaned
        .replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace("\r\n", "\\n")
        .replace('\n', "\\n")
        .replace('\r', "\\n")
}

pub fn fold_ics_line(line: &str) -> String {
    let mut folded: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut current_bytes = 0usize;
    for character in line.chars() {
        let width = character.len_utf8();
        if current_bytes + width > 75 {
            folded.push(current);
            current = format!(" {character}");
            current_bytes = 1 + width;
        } else {
            current.push(character);
            current_bytes += width;
        }
    }
    folded.push(current);
    folded.join("\r\n")
}

pub fn badge_filename(domain: &str) -> String {
    let slug = Regex::new(r"[^a-z0-9]+")
        .expect("static badge slug regex")
        .replace_all(&domain.to_lowercase(), "-")
        .to_string();
    let slug = slug.trim_matches('-');
    let slug: String = slug.chars().take(40).collect();
    let slug = slug.trim_matches('-');
    let slug = if slug.is_empty() { "host" } else { slug };
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    let digest = hasher.finalize();
    let digest: String = digest
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{slug}-{digest}.svg")
}
fn truncate(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    let prefix: String = value.chars().take(limit - 3).collect();
    format!("{prefix}...")
}

fn badge_style(status: &str) -> (&'static str, &'static str) {
    BADGE_STYLES
        .iter()
        .find(|(name, _, _)| *name == status)
        .map(|(_, color, label)| (*color, *label))
        .unwrap_or(("#718096", "unknown"))
}

fn badge_svg(
    domain: &str,
    status: &str,
    certificate: Option<&SslRow>,
    registration: Option<&RegistrationRow>,
) -> Vec<u8> {
    let (color, label) = badge_style(status);
    let visible = truncate(domain, MAX_LABEL);
    let left_width = (visible.chars().count() as f64 * 6.2).round() as i64 + 12;
    let right_width = (label.chars().count() as f64 * 6.2).round() as i64 + 12;
    let width = left_width + right_width;

    let mut details = Vec::new();
    if let Some(certificate) = certificate {
        let expiry = certificate
            .expires_on
            .map(|date| date.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "no date".into());
        details.push(format!(
            "certificate {}, expires {expiry}",
            certificate.status
        ));
    } else {
        details.push("certificate not checked".into());
    }
    if let Some(registration) = registration {
        let expiry = registration
            .expires_on
            .map(|date| date.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "no date".into());
        details.push(format!(
            "registration {}, expires {expiry}",
            registration.status
        ));
    } else {
        details.push("registration not checked".into());
    }
    let title = format!("{domain}: {}", details.join("; "));
    let aria = format!("{domain} status {status}");

    let mut svg = String::new();
    svg.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"20\" role=\"img\" aria-label=\"{}\">\n",
        xml_escape(&aria)
    ));
    svg.push_str(&format!("  <title>{}</title>\n", xml_escape(&title)));
    svg.push_str(&format!(
        "  <rect width=\"{width}\" height=\"20\" rx=\"3\" fill=\"#4a5568\"/>\n"
    ));
    svg.push_str(&format!(
        "  <rect x=\"{left_width}\" width=\"{right_width}\" height=\"20\" rx=\"3\" fill=\"{color}\"/>\n"
    ));
    svg.push_str(
        "  <g fill=\"#ffffff\" font-family=\"Verdana,DejaVu Sans,sans-serif\" font-size=\"11\" text-anchor=\"middle\">\n",
    );
    svg.push_str(&format!(
        "    <text x=\"{}\" y=\"14\">{}</text>\n",
        left_width / 2,
        xml_escape(&visible)
    ));
    svg.push_str(&format!(
        "    <text x=\"{}\" y=\"14\">{}</text>\n",
        left_width + right_width / 2,
        xml_escape(label)
    ));
    svg.push_str("  </g>\n</svg>\n");
    svg.into_bytes()
}

fn days_phrase(days: Option<i64>) -> String {
    match days {
        None => "no day count".into(),
        Some(days) if days < 0 => {
            let unit = if days == -1 { "day" } else { "days" };
            format!("expired {} {unit} ago", -days)
        }
        Some(0) => "expires today".into(),
        Some(days) => {
            let unit = if days == 1 { "day" } else { "days" };
            format!("{days} {unit} left")
        }
    }
}

fn calendar_event(
    kind: &str,
    domain: &str,
    expiry: NaiveDate,
    description: &str,
    dtstamp: DateTime<Utc>,
) -> Vec<String> {
    let uid_source = format!("{kind}|{domain}|{}", expiry.format("%Y-%m-%d"));
    let mut hasher = Sha256::new();
    hasher.update(uid_source.as_bytes());
    let digest: String = hasher
        .finalize()
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let uid = format!("{digest}@certiwatch.pages.dev");
    let next_day = expiry.succ_opt().unwrap_or(expiry);
    let summary = if kind == "certificate" {
        format!("SSL certificate expires: {domain}")
    } else {
        format!("Domain registration expires: {domain}")
    };
    let category = if kind == "certificate" {
        "SSL certificate"
    } else {
        "Domain registration"
    };
    vec![
        "BEGIN:VEVENT".into(),
        format!("UID:{uid}"),
        format!("DTSTAMP:{}", dtstamp.format("%Y%m%dT%H%M%SZ")),
        format!("DTSTART;VALUE=DATE:{}", expiry.format("%Y%m%d")),
        format!("DTEND;VALUE=DATE:{}", next_day.format("%Y%m%d")),
        format!("SUMMARY:{}", ics_escape(&summary)),
        format!("DESCRIPTION:{}", ics_escape(description)),
        format!("CATEGORIES:{}", ics_escape(category)),
        "TRANSP:TRANSPARENT".into(),
        "END:VEVENT".into(),
    ]
}

fn build_calendar(
    certificates: &BTreeMap<String, SslRow>,
    registrations: &BTreeMap<String, RegistrationRow>,
    dtstamp: DateTime<Utc>,
) -> Vec<u8> {
    let mut events: Vec<(NaiveDate, String, u8, Vec<String>)> = Vec::new();
    for (domain, row) in certificates {
        let Some(expiry) = row.expires_on else {
            continue;
        };
        let mut description = format!(
            "SSL certificate for {domain} expires {} ({}). Status: {}.",
            expiry.format("%Y-%m-%d"),
            days_phrase(row.days_left),
            row.status
        );
        if let Some(provider) = row.provider.as_deref() {
            description.push_str(&format!(" Issuer: {provider}."));
        }
        events.push((
            expiry,
            domain.clone(),
            0,
            calendar_event("certificate", domain, expiry, &description, dtstamp),
        ));
    }
    for (domain, row) in registrations {
        let Some(expiry) = row.expires_on else {
            continue;
        };
        let mut description = format!(
            "Domain registration for {domain} expires {} ({}). Status: {}.",
            expiry.format("%Y-%m-%d"),
            days_phrase(row.days_left),
            row.status
        );
        if let Some(registrar) = row.registrar.as_deref() {
            description.push_str(&format!(" Registrar: {registrar}."));
        }
        events.push((
            expiry,
            domain.clone(),
            1,
            calendar_event("registration", domain, expiry, &description, dtstamp),
        ));
    }
    events.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });

    let mut lines = vec![
        "BEGIN:VCALENDAR".to_string(),
        "VERSION:2.0".into(),
        "PRODID:-//CertiWatch//Public Expiry Feed//EN".into(),
        "CALSCALE:GREGORIAN".into(),
        "METHOD:PUBLISH".into(),
        "X-WR-CALNAME:CertiWatch certificate and domain expiries".into(),
        "X-WR-CALDESC:Certificate and registration expiry dates published by CertiWatch.".into(),
        "REFRESH-INTERVAL;VALUE=DURATION:PT1H".into(),
        "X-PUBLISHED-TTL:PT1H".into(),
    ];
    for (_, _, _, event_lines) in events {
        lines.extend(event_lines);
    }
    lines.push("END:VCALENDAR".into());

    let mut text = lines
        .iter()
        .map(|line| fold_ics_line(line))
        .collect::<Vec<_>>()
        .join("\r\n");
    text.push_str("\r\n");
    text.into_bytes()
}

// ── Model and outputs ────────────────────────────────────────────────────────

fn public_certificate(row: Option<&SslRow>) -> Value {
    let Some(row) = row else {
        return Value::Null;
    };
    let mut map = Map::new();
    map.insert("status".into(), json!(row.status));
    map.insert("category".into(), json!(row.category));
    map.insert(
        "expires_on".into(),
        json!(row
            .expires_on
            .map(|date| date.format("%Y-%m-%d").to_string())),
    );
    map.insert("days_left".into(), json!(row.days_left));
    map.insert("provider".into(), json!(row.provider));
    Value::Object(map)
}

fn public_registration(row: Option<&RegistrationRow>) -> Value {
    let Some(row) = row else {
        return Value::Null;
    };
    let mut map = Map::new();
    map.insert("status".into(), json!(row.status));
    map.insert("category".into(), json!(row.category));
    map.insert(
        "expires_on".into(),
        json!(row
            .expires_on
            .map(|date| date.format("%Y-%m-%d").to_string())),
    );
    map.insert("days_left".into(), json!(row.days_left));
    map.insert("registrar".into(), json!(row.registrar));
    Value::Object(map)
}

fn load_result(source: &Path, name: &str) -> Result<Value, FeedError> {
    reject_symlinked_path(source, name)?;
    let path = source.join(name);
    let metadata = fs::metadata(&path)
        .map_err(|_| FeedError::new(format!("required input missing or empty: {name}")))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(FeedError::new(format!(
            "required input missing or empty: {name}"
        )));
    }
    let text = fs::read_to_string(&path)
        .map_err(|exc| FeedError::new(format!("{name}: not valid JSON ({exc})")))?;
    let data: Value = serde_json::from_str(&text)
        .map_err(|exc| FeedError::new(format!("{name}: not valid JSON ({exc})")))?;
    if !data.is_object() {
        return Err(FeedError::new(format!(
            "{name}: expected a JSON object at the top level"
        )));
    }
    let generated_at = data
        .get("generated_at")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FeedError::new(format!("{name}: missing or empty 'generated_at'")))?;
    parse_timestamp(generated_at, &format!("{name}: generated_at"))?;
    data.get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| FeedError::new(format!("{name}: missing 'results' list")))?;
    Ok(data)
}

/// Build every feed file in memory. Paths are relative to the public root.
pub fn build_feeds(
    ssl_doc: &Value,
    domain_doc: &Value,
) -> Result<BTreeMap<String, Vec<u8>>, FeedError> {
    let ssl_generated = ssl_doc
        .get("generated_at")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| FeedError::new("ssl_results.json: missing or empty 'generated_at'"))?;
    let domain_generated = domain_doc
        .get("generated_at")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| FeedError::new("domain_results.json: missing or empty 'generated_at'"))?;
    let ssl_generated_at = parse_timestamp(ssl_generated, "ssl_results.json: generated_at")?;
    let domain_generated_at =
        parse_timestamp(domain_generated, "domain_results.json: generated_at")?;
    let ssl_results = ssl_doc
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| FeedError::new("ssl_results.json: missing 'results' list"))?;
    let domain_results = domain_doc
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| FeedError::new("domain_results.json: missing 'results' list"))?;
    if ssl_results.is_empty() && domain_results.is_empty() {
        return Err(FeedError::new(
            "refusing to publish empty feeds: at least one result file needs rows",
        ));
    }

    let certificates = index_rows(ssl_results, "ssl_results.json", normalise_ssl_row)?;
    let registrations = index_rows(
        domain_results,
        "domain_results.json",
        normalise_registration_row,
    )?;

    let generated_at = ssl_generated_at.max(domain_generated_at);
    let generated_iso = generated_at.to_rfc3339_opts(SecondsFormat::Secs, true);
    let domains: Vec<String> = certificates
        .keys()
        .chain(registrations.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut seen_files: BTreeMap<String, String> = BTreeMap::new();
    let mut entries = Vec::new();
    let mut badges: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut manifest_entries = Map::new();

    for domain in &domains {
        let certificate = certificates.get(domain);
        let registration = registrations.get(domain);
        let status = domain_status_scoped(
            certificate,
            registration,
            !certificates.is_empty(),
            !registrations.is_empty(),
        );
        let filename = badge_filename(domain);
        if let Some(existing) = seen_files.get(&filename) {
            if existing != domain {
                return Err(FeedError::new(format!(
                    "badge file name collision: {existing:?} and {domain:?}"
                )));
            }
        }
        seen_files.insert(filename.clone(), domain.clone());
        let path = format!("/{BADGES_DIR}/{filename}");
        let svg = badge_svg(domain, &status, certificate, registration);
        let digest = hex_sha256(&svg);
        let (color, _) = badge_style(&status);
        let mut manifest_entry = Map::new();
        manifest_entry.insert("path".into(), json!(path));
        manifest_entry.insert("status".into(), json!(status));
        manifest_entry.insert("color".into(), json!(color));
        manifest_entry.insert("sha256".into(), json!(digest));
        manifest_entries.insert(domain.clone(), Value::Object(manifest_entry));
        badges.insert(path.trim_start_matches('/').to_string(), svg);

        let mut entry = Map::new();
        entry.insert("domain".into(), json!(domain));
        entry.insert("status".into(), json!(status));
        entry.insert("badge".into(), json!(path));
        entry.insert("certificate".into(), public_certificate(certificate));
        entry.insert("registration".into(), public_registration(registration));
        entries.push(Value::Object(entry));
    }

    let mut certificate_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for row in certificates.values() {
        let bucket = if SSL_UNREACHABLE.contains(&row.status.as_str()) {
            "error"
        } else if SSL_VERDICTS.contains(&row.status.as_str()) {
            row.status.as_str()
        } else {
            "unknown"
        };
        *certificate_counts.entry(bucket).or_insert(0) += 1;
    }
    let mut registration_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for row in registrations.values() {
        *registration_counts
            .entry(registration_bucket(&row.status))
            .or_insert(0) += 1;
    }
    let mut domain_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for entry in &entries {
        *domain_counts
            .entry(entry["status"].as_str().unwrap_or("unknown"))
            .or_insert(0) += 1;
    }

    let mut checks = Map::new();
    let mut certificate_check = Map::new();
    certificate_check.insert(
        "generated_at".into(),
        json!(ssl_generated_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
    );
    certificate_check.insert("rows".into(), json!(certificates.len()));
    checks.insert("certificates".into(), Value::Object(certificate_check));
    let mut registration_check = Map::new();
    registration_check.insert(
        "generated_at".into(),
        json!(domain_generated_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
    );
    registration_check.insert("rows".into(), json!(registrations.len()));
    checks.insert("registrations".into(), Value::Object(registration_check));

    let mut links = Map::new();
    links.insert("calendar".into(), json!(format!("/{CALENDAR_FILE}")));
    links.insert("badges".into(), json!(format!("/{MANIFEST_FILE}")));

    let mut domain_summary = Map::new();
    domain_summary.insert("total".into(), json!(entries.len()));
    for key in ["ok", "warning", "critical", "unknown"] {
        domain_summary.insert(
            key.into(),
            json!(domain_counts.get(key).copied().unwrap_or(0)),
        );
    }
    let mut certificate_summary = Map::new();
    certificate_summary.insert("total".into(), json!(certificates.len()));
    for key in ["valid", "expired", "invalid", "error", "unknown"] {
        certificate_summary.insert(
            key.into(),
            json!(certificate_counts.get(key).copied().unwrap_or(0)),
        );
    }
    let mut registration_summary = Map::new();
    registration_summary.insert("total".into(), json!(registrations.len()));
    for key in ["active", "warning", "urgent", "expired", "unknown"] {
        registration_summary.insert(
            key.into(),
            json!(registration_counts.get(key).copied().unwrap_or(0)),
        );
    }
    let mut summary = Map::new();
    summary.insert("domains".into(), Value::Object(domain_summary));
    summary.insert("certificates".into(), Value::Object(certificate_summary));
    summary.insert("registrations".into(), Value::Object(registration_summary));

    let statuses: Vec<String> = entries
        .iter()
        .map(|entry| entry["status"].as_str().unwrap_or("unknown").to_string())
        .collect();
    let mut status_doc = Map::new();
    status_doc.insert("schema_version".into(), json!(SCHEMA_VERSION));
    status_doc.insert("generated_at".into(), json!(generated_iso));
    status_doc.insert("overall_status".into(), json!(overall_status(&statuses)));
    status_doc.insert("checks".into(), Value::Object(checks));
    status_doc.insert("links".into(), Value::Object(links));
    status_doc.insert("summary".into(), Value::Object(summary));
    status_doc.insert("domains".into(), Value::Array(entries));

    let mut manifest = Map::new();
    manifest.insert("schema_version".into(), json!(SCHEMA_VERSION));
    manifest.insert("generated_at".into(), json!(generated_iso));
    manifest.insert("badges".into(), Value::Object(manifest_entries));

    let mut files = BTreeMap::new();
    files.insert(
        STATUS_FILE.to_string(),
        pretty_bytes(&Value::Object(status_doc)),
    );
    files.insert(
        CALENDAR_FILE.to_string(),
        build_calendar(&certificates, &registrations, generated_at),
    );
    files.insert(
        MANIFEST_FILE.to_string(),
        pretty_bytes(&Value::Object(manifest)),
    );
    files.extend(badges);
    Ok(files)
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn pretty_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap_or_else(|_| b"{}".to_vec());
    bytes.push(b'\n');
    bytes
}

// ── Bundle builder (CLI / offline verification) ──────────────────────────────

pub const BADGE_FILE_PATTERN: &str = r"^badges/[a-z0-9-]{1,40}-[0-9a-f]{32}\.svg$";

fn check_out_path(source: &Path, out: &Path) -> Result<(), FeedError> {
    let source = source
        .canonicalize()
        .map_err(|exc| FeedError::new(exc.to_string()))?;
    let out = if out.exists() {
        out.canonicalize()
            .map_err(|exc| FeedError::new(exc.to_string()))?
    } else {
        let parent = out.parent().unwrap_or_else(|| Path::new("."));
        parent
            .canonicalize()
            .map_err(|exc| FeedError::new(exc.to_string()))?
            .join(out.file_name().unwrap_or_default())
    };
    if out == source {
        return Err(FeedError::unsafe_path(format!(
            "refusing to use the source tree as output: {}",
            out.display()
        )));
    }
    if source.starts_with(&out) {
        return Err(FeedError::unsafe_path(format!(
            "refusing to replace a parent of the source tree: {}",
            out.display()
        )));
    }
    Ok(())
}

fn check_existing_bundle(out: &Path) -> Result<(), FeedError> {
    if !out.exists() {
        return Ok(());
    }
    if out.is_symlink() || !out.is_dir() {
        return Err(FeedError::unsafe_path(format!(
            "refusing to replace output path {}: not a plain directory",
            out.display()
        )));
    }
    let mut names = BTreeSet::new();
    for entry in walk(out)? {
        let rel = entry
            .strip_prefix(out)
            .unwrap_or(&entry)
            .to_string_lossy()
            .replace('\\', "/");
        if entry.is_symlink() {
            return Err(FeedError::unsafe_path(format!(
                "refusing to replace {}: found symlink {rel:?}",
                out.display()
            )));
        }
        if entry.is_dir() {
            if rel != BADGES_DIR {
                return Err(FeedError::unsafe_path(format!(
                    "refusing to replace {}: found directory {rel:?}",
                    out.display()
                )));
            }
            continue;
        }
        if !entry.is_file() {
            return Err(FeedError::unsafe_path(format!(
                "refusing to replace {}: found {rel:?}",
                out.display()
            )));
        }
        if rel == STATUS_FILE
            || rel == CALENDAR_FILE
            || rel == MANIFEST_FILE
            || badge_file_re().is_match(&rel)
        {
            names.insert(rel);
            continue;
        }
        return Err(FeedError::unsafe_path(format!(
            "refusing to replace {}: found {rel:?}",
            out.display()
        )));
    }
    if !names.is_empty() && !names.contains(MANIFEST_FILE) {
        return Err(FeedError::unsafe_path(format!(
            "refusing to replace {}: it has no {MANIFEST_FILE}",
            out.display()
        )));
    }
    Ok(())
}

fn walk(root: &Path) -> Result<Vec<PathBuf>, FeedError> {
    let mut entries = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current).map_err(|exc| FeedError::new(exc.to_string()))? {
            let entry = entry.map_err(|exc| FeedError::new(exc.to_string()))?;
            let path = entry.path();
            if path.is_dir() && !path.is_symlink() {
                stack.push(path.clone());
            }
            entries.push(path);
        }
    }
    entries.sort();
    Ok(entries)
}

/// Build a feed bundle directory from a source tree holding both results.
pub fn build_bundle(source: &Path, out: &Path) -> Result<Vec<String>, FeedError> {
    let ssl = load_result(source, "ssl_results.json")?;
    let domain = load_result(source, "domain_results.json")?;
    let files = build_feeds(&ssl, &domain)?;
    check_out_path(source, out)?;
    check_existing_bundle(out)?;

    let parent = out.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|exc| FeedError::new(exc.to_string()))?;
    let staging = parent.join(format!(
        ".{}.staging-{}",
        out.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging).map_err(|exc| FeedError::new(exc.to_string()))?;

    for (rel, bytes) in &files {
        let target = staging.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|exc| FeedError::new(exc.to_string()))?;
        }
        fs::write(&target, bytes).map_err(|exc| FeedError::new(exc.to_string()))?;
    }

    if out.exists() {
        let backup = parent.join(format!(
            ".{}.previous-{}",
            out.file_name().unwrap_or_default().to_string_lossy(),
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&backup);
        fs::rename(out, &backup).map_err(|exc| FeedError::new(exc.to_string()))?;
        if let Err(error) = fs::rename(&staging, out) {
            let _ = fs::rename(&backup, out);
            let _ = fs::remove_dir_all(&staging);
            return Err(FeedError::new(error.to_string()));
        }
        let _ = fs::remove_dir_all(&backup);
    } else {
        fs::rename(&staging, out).map_err(|exc| FeedError::new(exc.to_string()))?;
    }
    Ok(files.keys().cloned().collect())
}
