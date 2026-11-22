//! Domain registration expiry checks: RDAP, WHOIS and the .lk registry API.
//!
//! The lookup order mirrors the legacy checker: the generic RDAP gateway,
//! then the IANA bootstrap service, then WHOIS over port 43. `.lk` names use
//! `register.domains.lk` with an adaptive, shared request limiter.
//!
//! Network access is behind [`RegistrationClient`], so tests and recorded
//! replay never touch the network.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use serde_json::{json, Value};
use url::Url;

use crate::config::Target;
use crate::dns::{diagnose_dns, Resolver};
use crate::results::{base_domain_result, dns_not_checked, JsonMap};

use ureq::config::Config as UreqConfig;
use ureq::http::Uri;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver as UreqResolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

pub const RDAP_HEADERS: &[(&str, &str)] = &[
    ("User-Agent", "Mozilla/5.0 (DomainExpiryChecker/1.0)"),
    (
        "Accept",
        "application/rdap+json, application/json;q=0.9, */*;q=0.8",
    ),
];

pub const LK_BASE_URL: &str = "https://register.domains.lk";
pub const LK_SEARCH_URL: &str = "https://register.domains.lk/domains-search";
pub const LK_API_URL: &str = "https://register.domains.lk/proxy/domains/single-search";

const WHOIS_EXPIRY_PATTERNS: &[&str] = &[
    r"Registry Expiry Date:\s*(.+)",
    r"Registrar Registration Expiration Date:\s*(.+)",
    r"Expiry Date:\s*(.+)",
    r"Expiration Date:\s*(.+)",
    r"paid-till:\s*(.+)",
    r"renewal date:\s*(.+)",
    r"expire-date:\s*(.+)",
    r"domain_datebilleduntil:\s*(.+)",
    r"Record expires on\s*(.+)",
    r"Expires On:\s*(.+)",
];

const WHOIS_REGISTRAR_PATTERNS: &[&str] = &[
    r"Registrar:\s*(.+)",
    r"Sponsoring Registrar:\s*(.+)",
    r"registrar-name:\s*(.+)",
    r"Registrar Name:\s*(.+)",
];

const REGISTRAR_ALIASES: &[(&str, &str)] = &[
    ("godaddy.com, llc", "GoDaddy"),
    ("godaddy", "GoDaddy"),
    ("go daddy llc", "GoDaddy"),
    ("csl computer service langenbach gmbh", "GoDaddy"),
    ("cscsl computer service langenbach", "GoDaddy"),
    ("joker.com", "GoDaddy"),
    ("nameaction", "GoDaddy"),
    ("wild west domains", "GoDaddy"),
    ("namecheap, inc.", "Namecheap"),
    ("namecheap", "Namecheap"),
    ("cloudflare, inc.", "Cloudflare"),
    ("cloudflare", "Cloudflare"),
    ("name.com, inc.", "Name.com"),
    ("name.com", "Name.com"),
    ("network solutions", "Network Solutions"),
    ("web commerce communications", "Domainnameshop"),
    ("enom", "eNom"),
];

#[derive(Debug, Clone)]
pub struct RegistrationOptions {
    pub timeout: Duration,
    pub request_delay: Duration,
    pub lk_delay: Duration,
    pub lk_max_delay: Duration,
    pub lk_max_retries: u32,
}

impl Default for RegistrationOptions {
    fn default() -> Self {
        RegistrationOptions {
            timeout: Duration::from_secs(20),
            request_delay: Duration::from_millis(350),
            lk_delay: Duration::from_millis(800),
            lk_max_delay: Duration::from_secs(5),
            lk_max_retries: 3,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ClientError {
    Status(u16, Option<f64>),
    Timeout,
    Connect(String),
    InvalidJson(String),
    Other(String),
}

/// The three network shapes a registration check needs.
pub trait RegistrationClient {
    fn get_json(&self, url: &str, headers: &[(&str, &str)]) -> Result<Value, ClientError>;
    fn get_text(&self, url: &str, headers: &[(&str, &str)]) -> Result<String, ClientError>;
    fn whois(&self, server: &str, query: &str) -> Result<String, ClientError>;
}

// ── Pure helpers ─────────────────────────────────────────────────────────────

pub fn normalize_domain(value: &str) -> String {
    let mut domain = value.trim().to_lowercase();
    for prefix in ["https://", "http://"] {
        if let Some(rest) = domain.strip_prefix(prefix) {
            domain = rest.to_string();
        }
    }
    let domain = domain
        .split('/')
        .next()
        .unwrap_or("")
        .trim_matches([' ', '.']);
    domain.strip_prefix("www.").unwrap_or(domain).to_string()
}

pub fn days_to_status(days_left: Option<i64>) -> &'static str {
    match days_left {
        None => "unknown",
        Some(days) if days <= 0 => "expired",
        Some(days) if days <= 7 => "urgent",
        Some(days) if days <= 30 => "warning",
        Some(_) => "active",
    }
}

pub fn normalize_registrar(raw: &str) -> String {
    if raw.is_empty() || raw == "N/A" {
        return raw.to_string();
    }
    let lower = raw.to_lowercase();
    for (pattern, canonical) in REGISTRAR_ALIASES {
        if lower.contains(pattern) {
            return (*canonical).to_string();
        }
    }
    raw.to_string()
}

fn ordinal_re() -> &'static Regex {
    static ORDINAL: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    ORDINAL.get_or_init(|| {
        Regex::new(r"^[A-Za-z]+,\s+(\d{1,2})(?:st|nd|rd|th)\s+([A-Za-z]+),\s+(\d{4})$")
            .expect("static ordinal pattern")
    })
}

/// Parse the many date shapes WHOIS and RDAP return.
pub fn parse_date(value: &str) -> Option<NaiveDateTime> {
    let mut text = value.trim().to_string();
    if text.is_empty() {
        return None;
    }
    for suffix in [" UTC", " GMT"] {
        if text.to_uppercase().ends_with(suffix) {
            text.truncate(text.len() - suffix.len());
        }
    }
    let text = text.trim_matches([' ', '.']).to_string();
    if text.is_empty() {
        return None;
    }

    if let Some(captures) = ordinal_re().captures(&text) {
        let day: u32 = captures.get(1)?.as_str().parse().ok()?;
        let month_text = captures.get(2)?.as_str();
        let year: i32 = captures.get(3)?.as_str().parse().ok()?;
        let month = month_number(month_text)?;
        return NaiveDate::from_ymd_opt(year, month, day)
            .and_then(|date| date.and_hms_opt(0, 0, 0));
    }

    const FORMATS: &[&str] = &[
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%Y.%m.%d",
        "%d-%m-%Y",
        "%d/%m/%Y",
        "%d.%m.%Y",
        "%d-%b-%Y",
        "%d-%B-%Y",
        "%b %d %Y",
        "%B %d %Y",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y.%m.%d %H:%M:%S",
        "%d-%b-%Y %H:%M:%S",
        "%d-%B-%Y %H:%M:%S",
    ];
    for format in FORMATS {
        if format.contains("%H") {
            if let Ok(value) = NaiveDateTime::parse_from_str(&text, format) {
                return Some(value);
            }
        } else if let Ok(date) = NaiveDate::parse_from_str(&text, format) {
            return date.and_hms_opt(0, 0, 0);
        }
    }

    // ISO-8601 with an offset; Python normalises it to UTC and drops the zone.
    if let Ok(value) = DateTime::parse_from_rfc3339(&text) {
        return Some(value.with_timezone(&Utc).naive_utc());
    }
    if let Ok(value) = NaiveDateTime::parse_from_str(&text, "%Y-%m-%dT%H:%M:%S") {
        return Some(value);
    }
    NaiveDate::parse_from_str(&text, "%Y-%m-%d")
        .ok()
        .and_then(|date| date.and_hms_opt(0, 0, 0))
}

fn month_number(name: &str) -> Option<u32> {
    const MONTHS: [&str; 12] = [
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
    ];
    let lower = name.to_lowercase();
    if let Some(index) = MONTHS.iter().position(|month| *month == lower) {
        return Some(index as u32 + 1);
    }
    MONTHS
        .iter()
        .position(|month| month.starts_with(&lower) && lower.len() >= 3)
        .map(|index| index as u32 + 1)
}

pub fn extract_registrar(rdap: &Value) -> String {
    let Some(entities) = rdap.get("entities").and_then(Value::as_array) else {
        return "N/A".into();
    };
    for entity in entities {
        let Some(entity) = entity.as_object() else {
            continue;
        };
        let roles = entity
            .get("roles")
            .and_then(Value::as_array)
            .map(|roles| {
                roles
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_lowercase)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !roles.iter().any(|role| role == "registrar") {
            continue;
        }
        let Some(vcard) = entity.get("vcardArray").and_then(Value::as_array) else {
            continue;
        };
        if vcard.len() < 2 {
            continue;
        }
        let Some(fields) = vcard[1].as_array() else {
            continue;
        };
        for field in fields {
            let Some(field) = field.as_array() else {
                continue;
            };
            if field.len() < 4 {
                continue;
            }
            let key = field[0].as_str().unwrap_or("").to_lowercase();
            let value = field[3].as_str().unwrap_or("").trim();
            if (key == "fn" || key == "org") && !value.is_empty() {
                return value.to_string();
            }
        }
    }
    "N/A".into()
}

pub fn extract_expiry_from_rdap(rdap: &Value) -> Option<NaiveDateTime> {
    let mut best: Option<NaiveDateTime> = None;
    if let Some(events) = rdap.get("events").and_then(Value::as_array) {
        for event in events {
            let Some(event) = event.as_object() else {
                continue;
            };
            let action = event
                .get("eventAction")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            if !action.contains("expir") {
                continue;
            }
            let Some(parsed) =
                parse_date(event.get("eventDate").and_then(Value::as_str).unwrap_or(""))
            else {
                continue;
            };
            if best.is_none() || parsed > best.unwrap() {
                best = Some(parsed);
            }
        }
    }
    if best.is_some() {
        return best;
    }
    for key in ["expirationDate", "expiryDate", "expires"] {
        if let Some(value) = rdap.get(key).and_then(Value::as_str) {
            if let Some(parsed) = parse_date(value) {
                return Some(parsed);
            }
        }
    }
    None
}

pub fn parse_registrar_from_whois(text: &str) -> String {
    for pattern in WHOIS_REGISTRAR_PATTERNS {
        let regex = Regex::new(&format!("(?i){pattern}")).expect("static whois pattern");
        if let Some(captures) = regex.captures(text) {
            let value = captures.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            if !value.is_empty() {
                return value.to_string();
            }
        }
    }
    "N/A".into()
}

pub fn parse_expiry_from_whois(text: &str) -> Option<String> {
    let mut candidates = Vec::new();
    for pattern in WHOIS_EXPIRY_PATTERNS {
        let regex = Regex::new(&format!("(?i){pattern}")).expect("static whois pattern");
        for captures in regex.captures_iter(text) {
            let raw = captures.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            let raw = raw.split(" (").next().unwrap_or("").trim();
            if let Some(parsed) = parse_date(raw) {
                candidates.push(parsed);
            }
        }
    }
    candidates
        .into_iter()
        .max()
        .map(|value| value.format("%Y-%m-%d").to_string())
}

// ── Lookup flow ──────────────────────────────────────────────────────────────

fn rdap_error(error: &ClientError) -> String {
    match error {
        ClientError::Timeout => "RDAP timeout".into(),
        ClientError::Status(code, _) => format!("RDAP HTTP error: {code}"),
        ClientError::Connect(reason) => format!("RDAP connection error: {reason}"),
        ClientError::InvalidJson(_) => "RDAP returned invalid JSON".into(),
        ClientError::Other(_) => "RDAP returned invalid JSON".into(),
    }
}

fn percentile_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn lookup_global_domain_rdap(
    client: &dyn RegistrationClient,
    domain: &str,
    base_url: &str,
) -> (String, String, Option<String>) {
    let base = format!("{}/", base_url.trim_end_matches('/'));
    let url = format!("{base}domain/{}", percentile_encode(domain));
    let payload = match client.get_json(&url, RDAP_HEADERS) {
        Ok(payload) => payload,
        Err(error) => return ("N/A".into(), rdap_error(&error), None),
    };
    let registrar = extract_registrar(&payload);
    let Some(expiry) = extract_expiry_from_rdap(&payload) else {
        return (registrar, "Expiration date not found in RDAP".into(), None);
    };
    (
        registrar,
        String::new(),
        Some(expiry.format("%Y-%m-%d").to_string()),
    )
}

fn get_rdap_base_url(client: &dyn RegistrationClient, domain: &str) -> Option<String> {
    let tld = domain.rsplit('.').next().unwrap_or("").to_lowercase();
    let payload = client
        .get_json("https://data.iana.org/rdap/dns.json", RDAP_HEADERS)
        .ok()?;
    let services = payload.get("services").and_then(Value::as_array)?;
    for service in services {
        let Some(service) = service.as_array() else {
            continue;
        };
        if service.len() < 2 {
            continue;
        }
        let (Some(tlds), Some(urls)) = (service[0].as_array(), service[1].as_array()) else {
            continue;
        };
        if !tlds
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.to_lowercase() == tld)
        {
            continue;
        }
        for item in urls {
            if let Some(url) = item.as_str() {
                if let Ok(parsed) = validate_registration_url(url) {
                    return Some(parsed.to_string());
                }
            }
        }
    }
    None
}

fn get_whois_server(client: &dyn RegistrationClient, domain: &str) -> Option<String> {
    let tld = domain.rsplit('.').next().unwrap_or("").to_lowercase();
    let response = client.whois("whois.iana.org", &tld).ok()?;
    for line in response.lines() {
        if line.to_lowercase().starts_with("whois:") {
            let server = line
                .split_once(':')
                .map(|(_, rest)| rest.trim())
                .unwrap_or("");
            // The referral is untrusted input: accept only a hostname or IP
            // literal. The WHOIS client resolves and checks it again before
            // dialling, so a public name that rebinds is still filtered.
            if let Some(server) = whois_host(server) {
                return Some(server);
            }
        }
    }
    None
}

fn lookup_global_domain_whois(
    client: &dyn RegistrationClient,
    domain: &str,
) -> (String, String, Option<String>) {
    let Some(server) = get_whois_server(client, domain) else {
        return ("N/A".into(), "WHOIS server not found".into(), None);
    };
    let response = match client.whois(&server, domain) {
        Ok(response) if !response.trim().is_empty() => response,
        _ => return ("N/A".into(), format!("WHOIS query failed ({server})"), None),
    };
    let lowered = response.to_lowercase();
    if lowered.contains("no match")
        || lowered.contains("not found")
        || lowered.contains("available")
    {
        return (
            "N/A".into(),
            "Domain appears unregistered in WHOIS".into(),
            None,
        );
    }
    let registrar = parse_registrar_from_whois(&response);
    let Some(expiry) = parse_expiry_from_whois(&response) else {
        return (registrar, "Expiry not found in WHOIS".into(), None);
    };
    (registrar, String::new(), Some(expiry))
}

fn lookup_global_domain(
    client: &dyn RegistrationClient,
    domain: &str,
) -> (String, String, Option<String>) {
    let (mut registrar, mut error, expiry) =
        lookup_global_domain_rdap(client, domain, "https://rdap.org/");
    if expiry.is_some() {
        return (registrar, String::new(), expiry);
    }

    if let Some(base) = get_rdap_base_url(client, domain) {
        let (registrar2, error2, expiry2) = lookup_global_domain_rdap(client, domain, &base);
        if expiry2.is_some() {
            return (registrar2, String::new(), expiry2);
        }
        if registrar2 != "N/A" {
            registrar = registrar2;
        }
        if !error2.is_empty() && error.is_empty() {
            error = error2;
        }
    }

    let (registrar3, error3, expiry3) = lookup_global_domain_whois(client, domain);
    if expiry3.is_some() {
        return (registrar3, String::new(), expiry3);
    }
    if registrar3 != "N/A" {
        registrar = registrar3;
    }
    let combined = [error, error3]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    (
        registrar,
        if combined.is_empty() {
            "No expiry in RDAP/WHOIS".into()
        } else {
            combined
        },
        None,
    )
}

struct LkLimiter {
    minimum: Duration,
    delay: Duration,
    maximum: Duration,
    last: Instant,
}

/// Thread-safe spacing with additive back-off and gradual recovery.
pub struct AdaptiveLimiter {
    state: Mutex<LkLimiter>,
}

impl AdaptiveLimiter {
    pub fn new(initial: Duration, maximum: Duration) -> Self {
        let maximum = maximum.max(initial);
        AdaptiveLimiter {
            state: Mutex::new(LkLimiter {
                minimum: initial,
                delay: initial,
                maximum,
                last: Instant::now() - initial,
            }),
        }
    }

    pub fn current_delay(&self) -> Duration {
        self.state
            .lock()
            .map(|state| state.delay)
            .unwrap_or_default()
    }

    pub fn wait(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return,
        };
        if state.minimum.is_zero() && state.delay.is_zero() {
            return;
        }
        let elapsed = state.last.elapsed();
        if state.delay > elapsed {
            std::thread::sleep(state.delay - elapsed);
        }
        state.last = Instant::now();
    }

    pub fn note_success(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.delay = state.minimum.max(state.delay.mul_f64(0.9));
        }
    }

    pub fn note_throttled(&self, retry_after: Option<Duration>) {
        if let Ok(mut state) = self.state.lock() {
            let doubled = state.delay.mul_f64(2.0);
            let wanted = doubled.max(retry_after.unwrap_or_default());
            state.delay = state.minimum.max(state.maximum.min(wanted));
        }
    }
}

fn retry_after_seconds(value: Option<&str>) -> Option<Duration> {
    const MAX_RETRY_AFTER_SECONDS: f64 = 86_400.0;
    let seconds = value?.trim().parse::<f64>().ok()?;
    if !seconds.is_finite() || seconds <= 0.0 {
        return None;
    }
    Some(Duration::from_secs_f64(
        seconds.min(MAX_RETRY_AFTER_SECONDS),
    ))
}

fn get_lk_expiry(
    client: &dyn RegistrationClient,
    limiter: &AdaptiveLimiter,
    domain: &str,
    options: &RegistrationOptions,
) -> String {
    let lookup = normalize_domain(domain);
    if lookup.is_empty() {
        return "[ERROR] Invalid domain".into();
    }
    let url = format!("{LK_API_URL}?keyword={}", percentile_encode(&lookup));
    const HEADERS: &[(&str, &str)] = &[
        (
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        ),
        ("Referer", LK_SEARCH_URL),
        ("Accept", "application/json, text/plain, */*"),
    ];

    let mut payload: Option<Value> = None;
    let mut attempt = 0u32;
    while attempt <= options.lk_max_retries {
        limiter.wait();
        match client.get_json(&url, HEADERS) {
            Ok(value) => {
                limiter.note_success();
                payload = Some(value);
                break;
            }
            Err(ClientError::Status(code, retry_after))
                if (code == 429 || code == 503) && attempt < options.lk_max_retries =>
            {
                let wait = retry_after
                    .map(Duration::from_secs_f64)
                    .unwrap_or_else(|| Duration::from_secs(1u64 << attempt.min(3)));
                limiter.note_throttled(Some(wait.max(options.lk_delay)));
                attempt += 1;
                continue;
            }
            Err(ClientError::Status(code, _)) => {
                return format!("[ERROR] LK API HTTP error: {code}")
            }
            Err(ClientError::Connect(reason)) => {
                if attempt < options.lk_max_retries {
                    std::thread::sleep(Duration::from_secs(1u64 << attempt.min(3)));
                    attempt += 1;
                    continue;
                }
                return format!("[ERROR] LK API connection error: {reason}");
            }
            Err(ClientError::Timeout) => {
                if attempt < options.lk_max_retries {
                    std::thread::sleep(Duration::from_secs(1u64 << attempt.min(3)));
                    attempt += 1;
                    continue;
                }
                return "[ERROR] LK API request failed after retries".into();
            }
            Err(ClientError::InvalidJson(_)) => {
                return "[ERROR] LK API returned invalid JSON".into()
            }
            Err(ClientError::Other(_)) => return "[ERROR] LK API returned invalid JSON".into(),
        }
    }

    let Some(payload) = payload else {
        return "[ERROR] LK API request failed after retries".into();
    };
    let availability = payload
        .get("result")
        .and_then(|result| result.get("domainAvailability"))
        .cloned()
        .unwrap_or(Value::Null);
    let Some(availability) = availability.as_object() else {
        return "[INFO] Domain information not available from LK API.".into();
    };
    if availability.is_empty() {
        return "[INFO] Domain information not available from LK API.".into();
    }
    if availability.get("isAvailable").and_then(Value::as_bool) == Some(true) {
        return "[INFO] Domain is NOT registered (available for registration).".into();
    }
    if let Some(expiry) = availability
        .get("domainInfo")
        .and_then(|info| info.get("expireDate"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return expiry.to_string();
    }
    if let Some(message) = availability
        .get("message")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return format!("[INFO] {message}");
    }
    "[INFO] Domain is registered, but expiry date is not exposed by API.".into()
}

fn check_registration(
    domain: &str,
    client: &dyn RegistrationClient,
    limiter: &AdaptiveLimiter,
    options: &RegistrationOptions,
) -> JsonMap {
    let mut result = base_domain_result(domain);
    let now = Utc::now().naive_utc();

    let (expiry_value, lk) = if domain.to_lowercase().ends_with(".lk") {
        result.insert("registrar".into(), json!("domains.lk"));
        (get_lk_expiry(client, limiter, domain, options), true)
    } else {
        let (registrar, error, expiry) = lookup_global_domain(client, domain);
        result.insert("registrar".into(), json!(normalize_registrar(&registrar)));
        if expiry.is_none() && !error.is_empty() {
            result.insert("status".into(), json!("unknown"));
        }
        (expiry.unwrap_or_default(), false)
    };

    if lk && (expiry_value.starts_with("[ERROR]") || expiry_value.starts_with("[INFO]")) {
        return result;
    }
    let Some(expiry) = parse_date(&expiry_value) else {
        return result;
    };
    let days_left = (expiry - now).num_seconds().div_euclid(86_400);
    result.insert(
        "expiry_date".into(),
        json!(expiry.format("%Y-%m-%d").to_string()),
    );
    result.insert("days_left".into(), json!(days_left));
    result.insert("status".into(), json!(days_to_status(Some(days_left))));
    result
}

fn attach_dns(result: &mut JsonMap, target: Option<&Target>, resolver: &dyn Resolver) {
    let Some(target) = target else {
        return;
    };
    let dns_name = target.dns_name_value();
    result.insert("dns_name".into(), json!(dns_name));
    if !target.check_dns {
        result.insert(
            "dns".into(),
            Value::Object(dns_not_checked(Some(&dns_name))),
        );
        return;
    }
    let diagnostics = diagnose_dns(&dns_name, resolver);
    result.insert("dns".into(), Value::Object(diagnostics));
}

/// Check registration expiry, optionally adding configured DNS diagnostics.
pub fn check_domain(
    domain: &str,
    target: Option<&Target>,
    client: &dyn RegistrationClient,
    limiter: &AdaptiveLimiter,
    options: &RegistrationOptions,
    resolver: &dyn Resolver,
) -> JsonMap {
    let mut result = check_registration(domain, client, limiter, options);
    // DNS diagnostics never change the registration verdict.
    attach_dns(&mut result, target, resolver);
    if let Some(target) = target {
        for (key, value) in target.public_metadata() {
            result.insert(key, value);
        }
    }
    result
}

// ── Production client ────────────────────────────────────────────────────────

/// A conservative public-unicast check for addresses this process may connect
/// to for registration data. Loopback, private, link-local, shared, reserved,
/// documentation, multicast and transition ranges are all refused.
pub fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(*v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_public_ipv4(mapped);
            }
            is_public_ipv6(*v6)
        }
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && matches!(c, 0 | 2))
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && matches!(b, 18 | 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_ipv6(ip: std::net::Ipv6Addr) -> bool {
    let segments = ip.segments();
    let global_unicast = segments[0] & 0xe000 == 0x2000;
    let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let teredo = segments[0] == 0x2001 && segments[1] == 0;
    let orchid = segments[0] == 0x2001 && matches!(segments[1] & 0xfff0, 0x0010 | 0x0020);
    let benchmarking = segments[0] == 0x2001 && segments[1] == 0x0002;
    let six_to_four = segments[0] == 0x2002;
    let new_documentation = segments[0] & 0xfff0 == 0x3ff0;
    global_unicast
        && !documentation
        && !teredo
        && !orchid
        && !benchmarking
        && !six_to_four
        && !new_documentation
}

/// Resolve a host to only public unicast addresses. Literal IPs are checked
/// directly; DNS answers are filtered before the caller dials any of them.
pub fn resolve_public_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("registration host is empty".into());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_public_ip(&ip) {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        return Err(format!(
            "registration host {host} is not a public unicast address"
        ));
    }
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("cannot resolve {host}: {error}"))?;
    let addresses: Vec<SocketAddr> = resolved.filter(|addr| is_public_ip(&addr.ip())).collect();
    if addresses.is_empty() {
        return Err(format!(
            "registration host {host} resolves only to non-public addresses"
        ));
    }
    Ok(addresses)
}

/// A ureq resolver that pins every connection to a vetted public address, so
/// a redirect or DNS answer cannot steer the request at a local service.
#[derive(Debug, Default, Clone, Copy)]
pub struct PublicResolver;

impl UreqResolver for PublicResolver {
    fn resolve(
        &self,
        uri: &Uri,
        _config: &UreqConfig,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let scheme = uri.scheme_str().unwrap_or("");
        if scheme != "https" {
            return Err(ureq::Error::BadUri(
                "registration egress requires https".into(),
            ));
        }
        let Some(authority) = uri.authority() else {
            return Err(ureq::Error::BadUri("registration URL has no host".into()));
        };
        let port = authority.port_u16().unwrap_or(443);
        let addresses = resolve_public_host(authority.host(), port)
            .map_err(|message| ureq::Error::Io(std::io::Error::other(message)))?;
        let mut result = self.empty();
        for address in addresses.into_iter().take(16) {
            result.push(address);
        }
        if result.is_empty() {
            return Err(ureq::Error::HostNotFound);
        }
        Ok(result)
    }
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Validate one registration URL: HTTPS only, a real host, and no embedded
/// credentials. Each redirect target passes through this before it is fetched.
pub fn validate_registration_url(value: &str) -> Result<Url, ClientError> {
    let url = Url::parse(value)
        .map_err(|error| ClientError::Other(format!("invalid registration URL: {error}")))?;
    if url.scheme() != "https" {
        return Err(ClientError::Other(
            "registration egress requires https".into(),
        ));
    }
    if url.host_str().is_none() || url.host_str() == Some("") {
        return Err(ClientError::Other("registration URL has no host".into()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ClientError::Other(
            "registration URL must not contain credentials".into(),
        ));
    }
    Ok(url)
}

/// Parse the IANA referral into a host or IP literal. Ports other than the
/// WHOIS port are refused so a referral cannot turn into a port probe.
fn whois_host(server: &str) -> Option<String> {
    let mut text = server.trim();
    if text.is_empty() || text.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return None;
    }
    if let Some(rest) = text.strip_prefix("whois://") {
        text = rest;
    }
    let text = text.split('/').next()?.trim_end_matches('.');
    let bracketed = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'));
    let text = bracketed.unwrap_or(text);
    if text.parse::<IpAddr>().is_ok() {
        return Some(text.to_string());
    }
    if text.contains(':') {
        let (host, port) = text.rsplit_once(':')?;
        if port != "43" || host.is_empty() {
            return None;
        }
        return Some(host.to_string());
    }
    if text.len() > 253 || !text.contains('.') {
        return None;
    }
    let labels: Vec<&str> = text.split('.').collect();
    let valid = labels
        .iter()
        .all(|label| !label.is_empty() && label.len() <= 63)
        && labels.iter().any(|label| label.len() >= 2)
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'));
    valid.then(|| text.to_string())
}

const MAX_REGISTRATION_REDIRECTS: usize = 3;

pub struct NetworkClient {
    agent: ureq::Agent,
    throttle: Mutex<Instant>,
    request_delay: Duration,
    timeout: Duration,
}

impl NetworkClient {
    pub fn new(request_delay: Duration, timeout: Duration) -> Self {
        // Redirects are followed by hand so every hop is revalidated as HTTPS
        // and re-resolved through PublicResolver at connection time.
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .max_redirects(0)
            .http_status_as_error(false)
            // Environment proxies would move the connection away from
            // PublicResolver and bypass the public-address policy. Registration
            // egress is direct by design.
            .proxy(None)
            .build();
        NetworkClient {
            agent: ureq::Agent::with_parts(config, DefaultConnector::default(), PublicResolver),
            throttle: Mutex::new(Instant::now() - request_delay),
            request_delay,
            timeout,
        }
    }

    fn throttle(&self) {
        if self.request_delay.is_zero() {
            return;
        }
        if let Ok(mut last) = self.throttle.lock() {
            let elapsed = last.elapsed();
            if self.request_delay > elapsed {
                std::thread::sleep(self.request_delay - elapsed);
            }
            *last = Instant::now();
        }
    }

    fn send_once(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<(u16, Option<String>, Option<String>, String), ClientError> {
        let url = validate_registration_url(url)?;
        self.throttle();
        let response = match method {
            "GET" => {
                let mut request = self.agent.get(url.as_str());
                for (key, value) in headers {
                    request = request.header(*key, *value);
                }
                request.call()
            }
            "POST" => {
                let mut request = self.agent.post(url.as_str());
                for (key, value) in headers {
                    request = request.header(*key, *value);
                }
                request.send(body.unwrap_or_default())
            }
            other => return Err(ClientError::Other(format!("unsupported method {other}"))),
        };
        let mut response = match response {
            Ok(response) => response,
            Err(ureq::Error::Timeout(_)) => return Err(ClientError::Timeout),
            Err(ureq::Error::HostNotFound) => {
                return Err(ClientError::Connect("name or service not known".into()))
            }
            Err(ureq::Error::Io(error)) => return Err(ClientError::Connect(error.to_string())),
            Err(error) => return Err(ClientError::Other(error.to_string())),
        };
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|error| ClientError::Other(error.to_string()))?;
        Ok((status, retry_after, location, text))
    }

    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<(u16, Option<String>, String), ClientError> {
        let mut current = validate_registration_url(url)?.to_string();
        let mut redirects = 0usize;
        loop {
            let (status, retry_after, location, text) =
                self.send_once(method, &current, headers, body)?;
            if method != "GET" || !is_redirect(status) {
                return Ok((status, retry_after, text));
            }
            if redirects >= MAX_REGISTRATION_REDIRECTS {
                return Err(ClientError::Other(
                    "registration lookup exceeded the redirect limit".into(),
                ));
            }
            let Some(location) = location else {
                return Err(ClientError::Other(
                    "registration redirect had no Location header".into(),
                ));
            };
            let base = Url::parse(&current)
                .map_err(|error| ClientError::Other(format!("invalid redirect base: {error}")))?;
            let next = base
                .join(&location)
                .map_err(|error| ClientError::Other(format!("invalid redirect target: {error}")))?;
            current = validate_registration_url(next.as_str())?.to_string();
            redirects += 1;
        }
    }

    fn get_json_value(&self, url: &str, headers: &[(&str, &str)]) -> Result<Value, ClientError> {
        let (status, retry_after, text) = self.request("GET", url, headers, None)?;
        if !(200..300).contains(&status) {
            let seconds =
                retry_after_seconds(retry_after.as_deref()).map(|value| value.as_secs_f64());
            return Err(ClientError::Status(status, seconds));
        }
        serde_json::from_str(&text).map_err(|error| ClientError::InvalidJson(error.to_string()))
    }
}

impl RegistrationClient for NetworkClient {
    fn get_json(&self, url: &str, headers: &[(&str, &str)]) -> Result<Value, ClientError> {
        self.get_json_value(url, headers)
    }

    fn get_text(&self, url: &str, headers: &[(&str, &str)]) -> Result<String, ClientError> {
        let (status, retry_after, text) = self.request("GET", url, headers, None)?;
        if !(200..300).contains(&status) {
            let seconds =
                retry_after_seconds(retry_after.as_deref()).map(|value| value.as_secs_f64());
            return Err(ClientError::Status(status, seconds));
        }
        Ok(text)
    }

    fn whois(&self, server: &str, query: &str) -> Result<String, ClientError> {
        self.throttle();
        let server = whois_host(server)
            .ok_or_else(|| ClientError::Connect("WHOIS server name is invalid".into()))?;
        let addresses = resolve_public_host(&server, 43).map_err(ClientError::Connect)?;
        let mut last_error = String::from("WHOIS server has no address");
        for address in addresses {
            let mut stream = match TcpStream::connect_timeout(&address, self.timeout) {
                Ok(stream) => stream,
                Err(error) => {
                    last_error = error.to_string();
                    continue;
                }
            };
            stream
                .set_read_timeout(Some(self.timeout))
                .map_err(|error| ClientError::Connect(error.to_string()))?;
            stream
                .set_write_timeout(Some(self.timeout))
                .map_err(|error| ClientError::Connect(error.to_string()))?;
            if let Err(error) = stream.write_all(format!("{query}\r\n").as_bytes()) {
                last_error = error.to_string();
                continue;
            }
            let mut chunks = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(size) => {
                        chunks.extend_from_slice(&buffer[..size]);
                        if chunks.len() > 1024 * 1024 {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        return Err(ClientError::Timeout)
                    }
                    Err(error) => {
                        last_error = error.to_string();
                        break;
                    }
                }
            }
            if !chunks.is_empty() {
                return Ok(String::from_utf8_lossy(&chunks).to_string());
            }
        }
        Err(ClientError::Connect(last_error))
    }
}

/// Production entry point: a network client plus one shared .lk limiter.
pub struct RegistrationService {
    pub client: NetworkClient,
    pub limiter: AdaptiveLimiter,
    pub options: RegistrationOptions,
}

impl RegistrationService {
    pub fn new(options: RegistrationOptions) -> Self {
        RegistrationService {
            client: NetworkClient::new(options.request_delay, options.timeout),
            limiter: AdaptiveLimiter::new(options.lk_delay, options.lk_max_delay),
            options,
        }
    }

    pub fn check(&self, domain: &str, target: Option<&Target>, resolver: &dyn Resolver) -> JsonMap {
        check_domain(
            domain,
            target,
            &self.client,
            &self.limiter,
            &self.options,
            resolver,
        )
    }
}

/// A map from domain to row, used by the HTTP layer for shallow health data.
pub fn status_counts(rows: &[Value]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for row in rows {
        let status = row
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        *counts.entry(status).or_insert(0) += 1;
    }
    counts
}

/// Parse a `generated_at` value used by the checkers.
pub fn parse_generated_at(value: &str) -> Option<NaiveDateTime> {
    parse_date(value).or_else(|| {
        DateTime::parse_from_str(value, "%Y-%m-%d %H:%M UTC")
            .ok()
            .map(|value| value.with_timezone(&Utc).naive_utc())
    })
}

#[allow(dead_code)]
fn utc_from_naive(value: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&value)
}
