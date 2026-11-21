//! Unified CertiWatch configuration.
//!
//! `certiwatch.toml` is the only target configuration. It is parsed, validated
//! with the same rules as `schema/certiwatch.schema.json`, and normalised into
//! [`Target`] values. Missing, unreadable or invalid configuration is always an
//! error; nothing falls back to the retired `ssl.conf` / `domains.conf` files.
//!
//! Privacy rule: `owner` and `notes` are carried on [`Target`] for local use,
//! but [`Target::public_metadata`] exposes only `tags` and `group`.

use std::collections::BTreeSet;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde_json::{json, Map, Value};

pub const CONFIG_FILE: &str = "certiwatch.toml";
pub const DEFAULT_SSL_PORT: u16 = 443;
pub const DEFAULT_THRESHOLDS: [i64; 4] = [30, 14, 7, 1];
pub const DEFAULT_HISTORY_LIMIT: u32 = 365;
pub const DEFAULT_CHECK_DNS: bool = true;
pub const DEFAULT_CHECK_HSTS: bool = true;
pub const DEFAULT_CHECK_LEGACY_TLS: bool = false;
pub const SUPPORTED_VERSION: i64 = 1;

#[derive(Debug, Clone)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(value: std::io::Error) -> Self {
        ConfigError(value.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    Direct,
    StartTls,
}

impl TlsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            TlsMode::Direct => "direct",
            TlsMode::StartTls => "starttls",
        }
    }
}

impl FromStr for TlsMode {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "direct" => Ok(TlsMode::Direct),
            "starttls" => Ok(TlsMode::StartTls),
            other => Err(ConfigError(format!(
                "tls_mode must be one of direct, starttls: {other:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartTlsProtocol {
    Smtp,
    Imap,
    Pop3,
}

impl StartTlsProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            StartTlsProtocol::Smtp => "smtp",
            StartTlsProtocol::Imap => "imap",
            StartTlsProtocol::Pop3 => "pop3",
        }
    }
}

impl FromStr for StartTlsProtocol {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "smtp" => Ok(StartTlsProtocol::Smtp),
            "imap" => Ok(StartTlsProtocol::Imap),
            "pop3" => Ok(StartTlsProtocol::Pop3),
            other => Err(ConfigError(format!(
                "starttls_protocol must be one of smtp, imap, pop3: {other:?}"
            ))),
        }
    }
}

/// One monitored endpoint or registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub ssl: bool,
    pub registration: bool,
    pub tags: Vec<String>,
    pub group: Option<String>,
    pub owner: Option<String>,
    pub notes: Option<String>,
    pub tls_mode: TlsMode,
    pub starttls_protocol: Option<StartTlsProtocol>,
    pub https: Option<bool>,
    pub dns_name: Option<String>,
    pub check_dns: bool,
    pub check_hsts: bool,
    pub check_legacy_tls: bool,
}

impl Target {
    /// A directly constructed target is inert, matching the legacy default.
    pub fn new(host: impl Into<String>, port: u16, ssl: bool, registration: bool) -> Self {
        Target {
            host: host.into(),
            port,
            ssl,
            registration,
            tags: Vec::new(),
            group: None,
            owner: None,
            notes: None,
            tls_mode: TlsMode::Direct,
            starttls_protocol: None,
            https: None,
            dns_name: None,
            check_dns: false,
            check_hsts: false,
            check_legacy_tls: false,
        }
    }

    pub fn ssl_endpoint(&self) -> Option<String> {
        self.ssl.then(|| format_endpoint(&self.host, self.port))
    }

    pub fn registration_domain(&self) -> String {
        registration_domain(&self.host)
    }

    pub fn dns_name_value(&self) -> String {
        let value = self
            .dns_name
            .clone()
            .unwrap_or_else(|| self.registration_domain());
        value.trim().trim_end_matches('.').to_lowercase()
    }

    pub fn is_https(&self) -> bool {
        match self.https {
            Some(value) => value,
            None => self.tls_mode == TlsMode::Direct && self.port == DEFAULT_SSL_PORT,
        }
    }

    /// Only the metadata a public result file may carry.
    pub fn public_metadata(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("tags".into(), json!(self.tags));
        map.insert("group".into(), json!(self.group));
        map
    }

    /// Endpoint facts that are public but are not privacy metadata.
    pub fn connection_metadata(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("tls_mode".into(), json!(self.tls_mode.as_str()));
        map.insert(
            "starttls_protocol".into(),
            json!(self.starttls_protocol.map(|value| value.as_str())),
        );
        map.insert("https".into(), json!(self.is_https()));
        map.insert("dns_name".into(), json!(self.dns_name_value()));
        map
    }

    /// Local-only metadata. Never pass this to a public writer.
    pub fn private_metadata(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("owner".into(), json!(self.owner));
        map.insert("notes".into(), json!(self.notes));
        map
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub version: i64,
    pub thresholds: [i64; 4],
    pub ssl_port: u16,
    pub history_limit: u32,
    pub targets: Vec<Target>,
    pub alerts_discord: bool,
    pub source: String,
    pub path: Option<PathBuf>,
    pub check_dns: bool,
    pub check_hsts: bool,
    pub check_legacy_tls: bool,
}

impl Config {
    pub fn ssl_targets(&self) -> Vec<&Target> {
        self.targets.iter().filter(|target| target.ssl).collect()
    }

    pub fn registration_targets(&self) -> Vec<&Target> {
        self.targets
            .iter()
            .filter(|target| target.registration)
            .collect()
    }

    pub fn ssl_endpoints(&self) -> Vec<(String, &Target)> {
        self.ssl_targets()
            .into_iter()
            .filter_map(|target| target.ssl_endpoint().map(|endpoint| (endpoint, target)))
            .collect()
    }

    pub fn registration_rows(&self) -> Vec<(String, &Target)> {
        self.registration_targets()
            .into_iter()
            .map(|target| (target.registration_domain(), target))
            .collect()
    }
}

// ── Endpoint handling ────────────────────────────────────────────────────────

/// Parse `host`, `host:port` or a URL into `(host, port)`.
pub fn parse_endpoint(raw: &str) -> Option<(String, u16)> {
    split_endpoint(raw).map(|(host, port, _)| (host, port))
}

/// Return `(host, port, port_was_explicit)` or `None` when invalid.
///
/// The rules mirror `urllib.parse.urlsplit` as used by the legacy checkers:
/// a scheme is optional, a path is ignored, userinfo is rejected, hosts are
/// lowercased and a trailing dot is removed.
pub fn split_endpoint(raw: &str) -> Option<(String, u16, bool)> {
    let text = raw.trim();
    if text.is_empty() || text.chars().any(char::is_whitespace) {
        return None;
    }
    // "//host" is not a valid input: the legacy code prefixes another "//"
    // and urlparse then finds an empty host.
    if text.starts_with("//") {
        return None;
    }

    let rest = if has_scheme(text) {
        let index = text.find("://")?;
        &text[index + 3..]
    } else {
        text
    };

    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }

    let (host_raw, port_raw) = if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped.find(']')?;
        let host = &stripped[..end];
        let tail = &stripped[end + 1..];
        let port = if tail.is_empty() {
            None
        } else {
            Some(tail.strip_prefix(':')?)
        };
        (host.to_string(), port)
    } else {
        let mut parts = authority.rsplitn(2, ':');
        let last = parts.next().unwrap_or("");
        match parts.next() {
            Some(host) => (host.to_string(), Some(last)),
            None => (last.to_string(), None),
        }
    };

    if host_raw.is_empty() {
        return None;
    }
    if host_raw.contains(':') && host_raw.parse::<std::net::Ipv6Addr>().is_err() {
        // A colon in a host is only valid inside a bracketed IPv6 literal.
        return None;
    }

    let host = host_raw.trim().to_lowercase();
    let host = host.trim_end_matches('.').to_string();
    if host.is_empty() {
        return None;
    }

    let (port, explicit) = match port_raw {
        None => (DEFAULT_SSL_PORT, false),
        Some("") => (DEFAULT_SSL_PORT, false),
        Some(value) => {
            if !value.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            let port: u32 = value.parse().ok()?;
            if port == 0 || port > u16::MAX as u32 {
                return None;
            }
            (port as u16, true)
        }
    };
    Some((host, port, explicit))
}

fn has_scheme(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    let mut index = 1;
    while index < bytes.len() {
        let ch = bytes[index];
        if ch == b':' {
            return text[index..].starts_with("://");
        }
        if !(ch.is_ascii_alphanumeric() || matches!(ch, b'+' | b'.' | b'-')) {
            return false;
        }
        index += 1;
    }
    false
}

/// Canonical target: bare host on 443, otherwise `host:port`.
pub fn format_endpoint(host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == DEFAULT_SSL_PORT {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn is_ip(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

/// Accept an IP literal or a valid multi-label DNS hostname.
pub fn is_valid_host(host: &str) -> bool {
    if is_ip(host) {
        return true;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    if labels.iter().any(|label| label.is_empty()) {
        return false;
    }
    if labels.last().map(|label| label.len() < 2).unwrap_or(true) {
        return false;
    }
    labels.iter().all(|label| valid_label(label))
}

fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    if !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit() {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn registration_domain(host: &str) -> String {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    host.strip_prefix("www.").unwrap_or(&host).to_string()
}

fn normalise_dns_name(value: &str) -> Option<String> {
    let text = value.trim();
    if text.is_empty() || text.chars().any(char::is_whitespace) {
        return None;
    }
    let (host, _port, explicit) = split_endpoint(text)?;
    if explicit || is_ip(&host) || !is_valid_host(&host) {
        return None;
    }
    Some(host)
}

// ── Threshold bands ──────────────────────────────────────────────────────────

const BAND_LABELS: [&str; 4] = ["notice", "warning", "urgent", "critical"];

/// Map remaining days to a stable alert band.
pub fn band_for_days(days_left: Option<i64>, thresholds: &[i64]) -> String {
    let Some(days) = days_left else {
        return "unknown".to_string();
    };
    if days < 0 {
        return "expired".to_string();
    }
    if thresholds.len() != BAND_LABELS.len() {
        return "unknown".to_string();
    }
    for (threshold, label) in thresholds.iter().rev().zip(BAND_LABELS.iter().rev()) {
        if days <= *threshold {
            return (*label).to_string();
        }
    }
    "ok".to_string()
}

// ── Loading ──────────────────────────────────────────────────────────────────

/// Load and validate the sole `certiwatch.toml`.
///
/// With no path: use `./certiwatch.toml`. A missing, unreadable or invalid file
/// is an error; there is no legacy fallback.
pub fn load_config(path: Option<&Path>) -> Result<Config, ConfigError> {
    if let Some(path) = path {
        if !path.exists() {
            return Err(ConfigError(format!(
                "configuration file not found: {}",
                path.display()
            )));
        }
        return load_toml(path);
    }

    let default = Path::new(CONFIG_FILE);
    if default.exists() {
        return load_toml(default);
    }
    Err(ConfigError(format!(
        "configuration file not found: {CONFIG_FILE}"
    )))
}

fn load_toml(path: &Path) -> Result<Config, ConfigError> {
    let text = fs::read_to_string(path).map_err(|exc| {
        ConfigError(format!(
            "{}: cannot read configuration: {exc}",
            path.display()
        ))
    })?;
    let document: toml::Table = toml::from_str(&text)
        .map_err(|exc| ConfigError(format!("{}: invalid TOML: {exc}", path.display())))?;
    let document = toml::Value::Table(document);
    validate_document(&document, path)?;
    normalise_document(&document, path)
}

fn table<'a>(
    value: &'a toml::Value,
    where_: &str,
    path: &Path,
) -> Result<&'a toml::Table, ConfigError> {
    value
        .as_table()
        .ok_or_else(|| ConfigError(format!("{}: {where_} must be a TOML table", path.display())))
}

fn reject_unknown(
    table: &toml::Table,
    allowed: &[&str],
    where_: &str,
    path: &Path,
) -> Result<(), ConfigError> {
    let unknown: Vec<&str> = table
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .map(String::as_str)
        .collect();
    if let Some(key) = unknown.first() {
        return Err(ConfigError(format!(
            "{}: {where_}: unknown key {key:?} (unknown keys are rejected)",
            path.display()
        )));
    }
    Ok(())
}

fn require_integer(value: &toml::Value, where_: &str, path: &Path) -> Result<i64, ConfigError> {
    value
        .as_integer()
        .ok_or_else(|| ConfigError(format!("{}: {where_}: expected an integer", path.display())))
}

fn require_string(value: &toml::Value, where_: &str, path: &Path) -> Result<String, ConfigError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| ConfigError(format!("{}: {where_}: expected a string", path.display())))
}

fn require_bool(value: &toml::Value, where_: &str, path: &Path) -> Result<bool, ConfigError> {
    value
        .as_bool()
        .ok_or_else(|| ConfigError(format!("{}: {where_}: expected a boolean", path.display())))
}

fn validate_document(document: &toml::Value, path: &Path) -> Result<(), ConfigError> {
    let document = table(document, "the top level", path)?;
    reject_unknown(
        document,
        &["version", "defaults", "alerts", "targets"],
        "$",
        path,
    )?;

    let version = document
        .get("version")
        .ok_or_else(|| ConfigError(format!("{}: $: version is required", path.display())))?;
    let version = require_integer(version, "$.version", path)?;
    if version != SUPPORTED_VERSION {
        return Err(ConfigError(format!(
            "{}: $.version: must be exactly {SUPPORTED_VERSION}",
            path.display()
        )));
    }

    if let Some(defaults) = document.get("defaults") {
        let defaults = table(defaults, "$.defaults", path)?;
        reject_unknown(
            defaults,
            &[
                "ssl_port",
                "thresholds",
                "history_limit",
                "check_dns",
                "check_hsts",
                "check_legacy_tls",
            ],
            "$.defaults",
            path,
        )?;
        if let Some(value) = defaults.get("ssl_port") {
            let port = require_integer(value, "$.defaults.ssl_port", path)?;
            if !(1..=65535).contains(&port) {
                return Err(ConfigError(format!(
                    "{}: $.defaults.ssl_port: must be between 1 and 65535",
                    path.display()
                )));
            }
        }
        if let Some(value) = defaults.get("history_limit") {
            let limit = require_integer(value, "$.defaults.history_limit", path)?;
            if !(1..=3650).contains(&limit) {
                return Err(ConfigError(format!(
                    "{}: $.defaults.history_limit: must be between 1 and 3650",
                    path.display()
                )));
            }
        }
        if let Some(value) = defaults.get("thresholds") {
            let list = value.as_array().ok_or_else(|| {
                ConfigError(format!(
                    "{}: $.defaults.thresholds: expected an array",
                    path.display()
                ))
            })?;
            if list.len() != 4 {
                return Err(ConfigError(format!(
                    "{}: $.defaults.thresholds: must contain exactly 4 items",
                    path.display()
                )));
            }
            for item in list {
                let number = require_integer(item, "$.defaults.thresholds", path)?;
                if number < 0 {
                    return Err(ConfigError(format!(
                        "{}: $.defaults.thresholds: cannot be negative",
                        path.display()
                    )));
                }
            }
        }
        for key in ["check_dns", "check_hsts", "check_legacy_tls"] {
            if let Some(value) = defaults.get(key) {
                require_bool(value, &format!("$.defaults.{key}"), path)?;
            }
        }
    }

    if let Some(alerts) = document.get("alerts") {
        let alerts = table(alerts, "$.alerts", path)?;
        reject_unknown(alerts, &["discord"], "$.alerts", path)?;
        if let Some(value) = alerts.get("discord") {
            require_bool(value, "$.alerts.discord", path)?;
        }
    }

    let targets = document
        .get("targets")
        .ok_or_else(|| ConfigError(format!("{}: $: targets is required", path.display())))?;
    let targets = targets
        .as_array()
        .ok_or_else(|| ConfigError(format!("{}: $.targets: expected an array", path.display())))?;
    if targets.is_empty() {
        return Err(ConfigError(format!(
            "{}: $.targets: must contain at least one item",
            path.display()
        )));
    }
    for (index, item) in targets.iter().enumerate() {
        let where_ = format!("$.targets[{index}]");
        let item = table(item, &where_, path)?;
        reject_unknown(
            item,
            &[
                "domain",
                "ssl",
                "registration",
                "ssl_port",
                "tls_mode",
                "starttls_protocol",
                "https",
                "dns_name",
                "check_dns",
                "check_hsts",
                "check_legacy_tls",
                "tags",
                "group",
                "owner",
                "notes",
            ],
            &where_,
            path,
        )?;
        let domain = item.get("domain").ok_or_else(|| {
            ConfigError(format!("{}: {where_}: domain is required", path.display()))
        })?;
        let domain = require_string(domain, &format!("{where_}.domain"), path)?;
        if domain.is_empty() {
            return Err(ConfigError(format!(
                "{}: {where_}.domain: must not be empty",
                path.display()
            )));
        }
        for key in [
            "ssl",
            "registration",
            "https",
            "check_dns",
            "check_hsts",
            "check_legacy_tls",
        ] {
            if let Some(value) = item.get(key) {
                require_bool(value, &format!("{where_}.{key}"), path)?;
            }
        }
        if let Some(value) = item.get("ssl_port") {
            let port = require_integer(value, &format!("{where_}.ssl_port"), path)?;
            if !(1..=65535).contains(&port) {
                return Err(ConfigError(format!(
                    "{}: {where_}.ssl_port: must be between 1 and 65535",
                    path.display()
                )));
            }
        }
        if let Some(value) = item.get("tls_mode") {
            let mode = require_string(value, &format!("{where_}.tls_mode"), path)?;
            if mode != "direct" && mode != "starttls" {
                return Err(ConfigError(format!(
                    "{}: {where_}.tls_mode: must be one of direct, starttls",
                    path.display()
                )));
            }
        }
        if let Some(value) = item.get("starttls_protocol") {
            let protocol = require_string(value, &format!("{where_}.starttls_protocol"), path)?;
            if !["smtp", "imap", "pop3"].contains(&protocol.as_str()) {
                return Err(ConfigError(format!(
                    "{}: {where_}.starttls_protocol: must be one of smtp, imap, pop3",
                    path.display()
                )));
            }
        }
        if let Some(value) = item.get("dns_name") {
            let name = require_string(value, &format!("{where_}.dns_name"), path)?;
            if name.is_empty() {
                return Err(ConfigError(format!(
                    "{}: {where_}.dns_name: must not be empty",
                    path.display()
                )));
            }
        }
        for key in ["group", "owner", "notes"] {
            if let Some(value) = item.get(key) {
                let text = require_string(value, &format!("{where_}.{key}"), path)?;
                if text.is_empty() {
                    return Err(ConfigError(format!(
                        "{}: {where_}.{key}: must not be empty",
                        path.display()
                    )));
                }
            }
        }
        if let Some(value) = item.get("tags") {
            let tags = value.as_array().ok_or_else(|| {
                ConfigError(format!(
                    "{}: {where_}.tags: expected an array",
                    path.display()
                ))
            })?;
            let mut seen = BTreeSet::new();
            for tag in tags {
                let text = require_string(tag, &format!("{where_}.tags"), path)?;
                if text.is_empty() {
                    return Err(ConfigError(format!(
                        "{}: {where_}.tags: must not contain an empty string",
                        path.display()
                    )));
                }
                if !seen.insert(text.clone()) {
                    return Err(ConfigError(format!(
                        "{}: {where_}.tags: items must be unique ({text:?})",
                        path.display()
                    )));
                }
            }
        }

        // JSON Schema anyOf: registration == true, or ssl is not false.
        let ssl_disabled = item.get("ssl").and_then(toml::Value::as_bool) == Some(false);
        let registration_enabled =
            item.get("registration").and_then(toml::Value::as_bool) == Some(true);
        if ssl_disabled && !registration_enabled {
            return Err(ConfigError(format!(
                "{}: {where_}: enable ssl, registration, or both",
                path.display()
            )));
        }
    }
    Ok(())
}

fn normalise_document(document: &toml::Value, path: &Path) -> Result<Config, ConfigError> {
    let document = document.as_table().expect("validated table");
    let defaults = document
        .get("defaults")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();

    let thresholds = match defaults.get("thresholds").and_then(toml::Value::as_array) {
        Some(values) => {
            let mut result = [0i64; 4];
            for (index, value) in values.iter().enumerate() {
                result[index] = value.as_integer().unwrap_or(0);
            }
            validate_thresholds(&result, path)?
        }
        None => DEFAULT_THRESHOLDS,
    };
    let ssl_port = defaults
        .get("ssl_port")
        .and_then(toml::Value::as_integer)
        .map(|value| value as u16)
        .unwrap_or(DEFAULT_SSL_PORT);
    let history_limit = defaults
        .get("history_limit")
        .and_then(toml::Value::as_integer)
        .map(|value| value as u32)
        .unwrap_or(DEFAULT_HISTORY_LIMIT);
    let check_dns = defaults
        .get("check_dns")
        .and_then(toml::Value::as_bool)
        .unwrap_or(DEFAULT_CHECK_DNS);
    let check_hsts = defaults
        .get("check_hsts")
        .and_then(toml::Value::as_bool)
        .unwrap_or(DEFAULT_CHECK_HSTS);
    let check_legacy_tls = defaults
        .get("check_legacy_tls")
        .and_then(toml::Value::as_bool)
        .unwrap_or(DEFAULT_CHECK_LEGACY_TLS);
    let discord = document
        .get("alerts")
        .and_then(toml::Value::as_table)
        .and_then(|alerts| alerts.get("discord"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);

    let raw_targets = document
        .get("targets")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut targets: Vec<Target> = Vec::new();
    let mut ssl_seen: BTreeSet<String> = BTreeSet::new();
    let mut registration_seen: BTreeSet<String> = BTreeSet::new();

    for (index, item) in raw_targets.iter().enumerate() {
        let target = normalise_target(
            item,
            index,
            ssl_port,
            path,
            check_dns,
            check_hsts,
            check_legacy_tls,
        )?;
        if target.ssl {
            if let Some(endpoint) = target.ssl_endpoint() {
                if !ssl_seen.insert(endpoint.clone()) {
                    return Err(ConfigError(format!(
                        "{}: duplicate SSL endpoint {endpoint:?} (targets[{index}])",
                        path.display()
                    )));
                }
            }
        }
        if target.registration {
            let domain = target.registration_domain();
            if !registration_seen.insert(domain.clone()) {
                return Err(ConfigError(format!(
                    "{}: duplicate registration domain {domain:?} (targets[{index}])",
                    path.display()
                )));
            }
        }
        targets.push(target);
    }

    Ok(Config {
        version: SUPPORTED_VERSION,
        thresholds,
        ssl_port,
        history_limit,
        targets,
        alerts_discord: discord,
        source: "toml".into(),
        path: Some(path.to_path_buf()),
        check_dns,
        check_hsts,
        check_legacy_tls,
    })
}

fn validate_thresholds(values: &[i64; 4], path: &Path) -> Result<[i64; 4], ConfigError> {
    for value in values {
        if *value < 0 {
            return Err(ConfigError(format!(
                "{}: thresholds cannot be negative",
                path.display()
            )));
        }
    }
    for index in 0..values.len() - 1 {
        if values[index] <= values[index + 1] {
            return Err(ConfigError(format!(
                "{}: thresholds must be strictly descending",
                path.display()
            )));
        }
    }
    Ok(*values)
}

fn normalise_target(
    item: &toml::Value,
    index: usize,
    default_port: u16,
    path: &Path,
    default_check_dns: bool,
    default_check_hsts: bool,
    default_check_legacy_tls: bool,
) -> Result<Target, ConfigError> {
    let where_ = format!("{}: targets[{index}]", path.display());
    let item = item.as_table().expect("validated table");
    let raw_domain = item
        .get("domain")
        .and_then(toml::Value::as_str)
        .unwrap_or_default();

    let (host, explicit_port, port_was_explicit) = split_endpoint(raw_domain)
        .ok_or_else(|| ConfigError(format!("{where_}: invalid domain {raw_domain:?}")))?;

    let ssl_enabled = item
        .get("ssl")
        .and_then(toml::Value::as_bool)
        .unwrap_or(true);
    let registration = item
        .get("registration")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    if !ssl_enabled && !registration {
        return Err(ConfigError(format!(
            "{where_}: enable ssl, registration, or both"
        )));
    }

    let port = match item.get("ssl_port") {
        Some(value) => {
            let ssl_port = value.as_integer().unwrap_or_default() as u16;
            if !ssl_enabled {
                return Err(ConfigError(format!(
                    "{where_}: ssl_port is only valid when ssl is enabled"
                )));
            }
            if port_was_explicit && ssl_port != explicit_port {
                return Err(ConfigError(format!(
                    "{where_}: ssl_port {ssl_port} conflicts with the port in domain"
                )));
            }
            ssl_port
        }
        None => {
            if port_was_explicit {
                if !ssl_enabled {
                    return Err(ConfigError(format!(
                        "{where_}: a port is only valid when ssl is enabled"
                    )));
                }
                explicit_port
            } else {
                default_port
            }
        }
    };

    if !is_valid_host(&host) {
        return Err(ConfigError(format!("{where_}: invalid host {host:?}")));
    }
    if registration && is_ip(&host) {
        return Err(ConfigError(format!(
            "{where_}: registration checks require a domain, not an IP"
        )));
    }

    let tags: Vec<String> = item
        .get("tags")
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .map(|value| value.trim().to_string())
                .collect()
        })
        .unwrap_or_default();
    if tags.iter().any(String::is_empty) {
        return Err(ConfigError(format!("{where_}: tags cannot be empty")));
    }

    let group = optional_text(item.get("group"));
    let owner = optional_text(item.get("owner"));
    let notes = optional_text(item.get("notes"));

    let tls_mode = TlsMode::from_str(
        item.get("tls_mode")
            .and_then(toml::Value::as_str)
            .unwrap_or("direct")
            .trim()
            .to_lowercase()
            .as_str(),
    )
    .map_err(|_| {
        ConfigError(format!(
            "{where_}: tls_mode must be one of direct, starttls"
        ))
    })?;
    if !ssl_enabled && tls_mode != TlsMode::Direct {
        return Err(ConfigError(format!(
            "{where_}: tls_mode is only valid when ssl is enabled"
        )));
    }

    let starttls_protocol = match item.get("starttls_protocol").and_then(toml::Value::as_str) {
        Some(value) => {
            let protocol = StartTlsProtocol::from_str(value.trim().to_lowercase().as_str())
                .map_err(|_| {
                    ConfigError(format!(
                        "{where_}: starttls_protocol must be one of smtp, imap, pop3"
                    ))
                })?;
            if tls_mode != TlsMode::StartTls {
                return Err(ConfigError(format!(
                    "{where_}: starttls_protocol is only valid when tls_mode = 'starttls'"
                )));
            }
            Some(protocol)
        }
        None => {
            if tls_mode == TlsMode::StartTls {
                Some(StartTlsProtocol::Smtp)
            } else {
                None
            }
        }
    };

    let https = item.get("https").and_then(toml::Value::as_bool);
    if https == Some(true) && tls_mode != TlsMode::Direct {
        return Err(ConfigError(format!(
            "{where_}: https cannot be combined with STARTTLS"
        )));
    }

    let dns_name = match item.get("dns_name").and_then(toml::Value::as_str) {
        Some(value) => {
            let name = normalise_dns_name(value).ok_or_else(|| {
                ConfigError(format!(
                    "{where_}: dns_name must be a domain name without a port or IP"
                ))
            })?;
            Some(name)
        }
        None => None,
    };

    let check_dns = item
        .get("check_dns")
        .and_then(toml::Value::as_bool)
        .unwrap_or(default_check_dns);
    let check_hsts = item
        .get("check_hsts")
        .and_then(toml::Value::as_bool)
        .unwrap_or(default_check_hsts);
    let check_legacy_tls = item
        .get("check_legacy_tls")
        .and_then(toml::Value::as_bool)
        .unwrap_or(default_check_legacy_tls);

    Ok(Target {
        host,
        port,
        ssl: ssl_enabled,
        registration,
        tags,
        group,
        owner,
        notes,
        tls_mode,
        starttls_protocol,
        https,
        dns_name,
        check_dns,
        check_hsts,
        check_legacy_tls,
    })
}

fn optional_text(value: Option<&toml::Value>) -> Option<String> {
    let text = value?.as_str()?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}
