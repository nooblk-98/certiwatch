//! Result documents shared by the checkers, the monitor and the feeds.
//!
//! Rows are ordered JSON objects (`serde_json` with `preserve_order`), because
//! the public result files are a compatibility contract: existing dashboards,
//! feed builders and recorded legacy behaviour read the exact field names and
//! presence rules. Field order also keeps diffs and byte comparisons stable.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Map, Value};

pub type JsonMap = Map<String, Value>;

pub const SSL_OUTPUT_FILE: &str = "ssl_results.json";
pub const DOMAIN_OUTPUT_FILE: &str = "domain_results.json";
pub const HISTORY_FILE: &str = "history.json";
pub const STATUS_FILE: &str = "status.json";
pub const CALENDAR_FILE: &str = "expiries.ics";
pub const BADGES_DIR: &str = "badges";
pub const MANIFEST_FILE: &str = "badges/manifest.json";
pub const ALERT_STATE_FILE: &str = "alert_state.json";

pub const REVOCATION_NOTE: &str = "OCSP/CRL revocation verification is not implemented; this checker does not claim a revocation result.";
pub const DNS_LIMITS: &str = "Records are what this machine's resolver returned for the configured dns_name. NS/CAA absence means NOERROR/NODATA or NXDOMAIN, not an unqueried name. DNSSEC is 'validated' only when the resolver sets the AD bit; 'present' means DNSKEY data was returned without local validation. CAA is queried at this name; a policy at an ancestor can still apply, and CAA is not a certificate-issuance guarantee by itself.";

pub fn now_checked_at(now: DateTime<Utc>) -> String {
    now.format("%Y-%m-%d %H:%M UTC").to_string()
}

pub fn iso_z(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn insert(map: &mut JsonMap, key: &str, value: Value) {
    map.insert(key.to_string(), value);
}

/// The full SSL row with every field present, before a probe is attached.
pub fn base_ssl_result(domain: &str, host: &str, port: u16, now: DateTime<Utc>) -> JsonMap {
    let mut map = JsonMap::new();
    insert(&mut map, "domain", json!(domain));
    insert(&mut map, "host", json!(host));
    insert(&mut map, "port", json!(port));
    insert(&mut map, "status", json!("error"));
    insert(&mut map, "provider", json!("N/A"));
    insert(&mut map, "issued_on", json!("N/A"));
    insert(&mut map, "expires_on", json!("N/A"));
    insert(&mut map, "days_left", Value::Null);
    insert(&mut map, "is_expired", Value::Null);
    insert(&mut map, "error", Value::Null);
    insert(&mut map, "checked_at", json!(now_checked_at(now)));
    insert(&mut map, "resolved_via", Value::Null);
    insert(&mut map, "fallback", Value::Null);
    insert(&mut map, "trusted_chain", Value::Null);
    insert(&mut map, "chain_error", Value::Null);
    insert(&mut map, "hostname_matches", Value::Null);
    insert(&mut map, "common_name", Value::Null);
    insert(&mut map, "wildcard", json!(false));
    insert(&mut map, "san", json!([]));
    insert(&mut map, "san_count", json!(0));
    insert(&mut map, "key_type", Value::Null);
    insert(&mut map, "key_size", Value::Null);
    insert(&mut map, "key_curve", Value::Null);
    insert(&mut map, "key_strength", Value::Null);
    insert(&mut map, "not_before", Value::Null);
    insert(&mut map, "not_after", Value::Null);
    insert(&mut map, "fingerprint_sha256", Value::Null);
    insert(&mut map, "serial_number", Value::Null);
    insert(&mut map, "tls_version", Value::Null);
    insert(&mut map, "cipher", Value::Null);
    insert(&mut map, "tls_mode", json!("direct"));
    insert(&mut map, "starttls_protocol", Value::Null);
    insert(&mut map, "https", json!(port == 443));
    insert(&mut map, "chain", json!([]));
    insert(&mut map, "chain_length", json!(0));
    insert(&mut map, "chain_source", Value::Null);
    insert(&mut map, "dns_name", Value::Null);
    insert(&mut map, "dns", Value::Object(dns_not_checked(None)));
    insert(&mut map, "hsts", Value::Object(hsts_not_applicable()));
    insert(
        &mut map,
        "legacy_tls",
        Value::Object(legacy_tls_not_checked()),
    );
    insert(&mut map, "revocation_checked", json!(false));
    insert(&mut map, "revocation_status", json!("not_checked"));
    insert(&mut map, "revocation_supported", json!(false));
    insert(&mut map, "revocation", Value::Object(revocation_map()));
    map
}

/// The registration row before diagnostics are attached.
pub fn base_domain_result(domain: &str) -> JsonMap {
    let mut map = JsonMap::new();
    insert(&mut map, "domain", json!(domain));
    insert(&mut map, "registrar", json!("N/A"));
    insert(&mut map, "purchase_date", json!("N/A"));
    insert(&mut map, "expiry_date", json!("N/A"));
    insert(&mut map, "days_left", Value::Null);
    insert(&mut map, "status", json!("unknown"));
    map
}

pub fn revocation_map() -> JsonMap {
    let mut map = JsonMap::new();
    insert(&mut map, "checked", json!(false));
    insert(&mut map, "supported", json!(false));
    insert(&mut map, "status", json!("not_checked"));
    insert(&mut map, "method", Value::Null);
    insert(&mut map, "error", Value::Null);
    insert(&mut map, "note", json!(REVOCATION_NOTE));
    map
}

pub fn hsts_not_applicable() -> JsonMap {
    let mut map = JsonMap::new();
    insert(&mut map, "applicable", json!(false));
    insert(&mut map, "checked", json!(false));
    insert(&mut map, "present", Value::Null);
    insert(&mut map, "valid", Value::Null);
    insert(&mut map, "enabled", Value::Null);
    insert(&mut map, "status", json!("not_checked"));
    insert(&mut map, "max_age", Value::Null);
    insert(&mut map, "include_subdomains", Value::Null);
    insert(&mut map, "preload", Value::Null);
    insert(&mut map, "error", Value::Null);
    map
}

pub fn hsts_disabled() -> JsonMap {
    let mut map = hsts_not_applicable();
    insert(&mut map, "applicable", json!(true));
    map
}

pub fn hsts_indeterminate(error: &str) -> JsonMap {
    let mut map = hsts_not_applicable();
    insert(&mut map, "applicable", json!(true));
    insert(&mut map, "checked", json!(true));
    insert(&mut map, "status", json!("indeterminate"));
    insert(&mut map, "error", json!(error));
    map
}

pub fn legacy_tls_not_checked() -> JsonMap {
    let mut map = JsonMap::new();
    insert(&mut map, "checked", json!(false));
    insert(&mut map, "tls10", json!("not_checked"));
    insert(&mut map, "tls11", json!("not_checked"));
    map
}

pub fn dns_record_not_checked() -> Value {
    json!({"status": "not_checked", "records": [], "error": null})
}

pub fn dnssec_not_checked() -> Value {
    json!({
        "status": "not_checked",
        "validated": false,
        "records": [],
        "signature_count": 0,
        "error": null
    })
}

pub fn dns_not_checked(name: Option<&str>) -> JsonMap {
    let mut map = JsonMap::new();
    insert(&mut map, "checked", json!(false));
    insert(&mut map, "name", json!(name));
    insert(&mut map, "ns", dns_record_not_checked());
    insert(&mut map, "caa", dns_record_not_checked());
    insert(&mut map, "dnssec", dnssec_not_checked());
    insert(&mut map, "error", Value::Null);
    map
}

/// A diagnostics failure that must not look like an authoritative absence.
pub fn dns_failed(name: Option<&str>, error: &str) -> JsonMap {
    let mut map = dns_not_checked(name);
    insert(&mut map, "checked", json!(false));
    insert(&mut map, "error", json!(error));
    for record in ["ns", "caa", "dnssec"] {
        if let Some(entry) = map.get_mut(record).and_then(Value::as_object_mut) {
            insert(entry, "status", json!("unknown"));
            insert(entry, "error", json!(error));
        }
    }
    map
}

// ── Output documents ─────────────────────────────────────────────────────────

pub fn build_ssl_output(entry_count: usize, mut results: Vec<Value>) -> Value {
    results.sort_by_key(ssl_sort_key);
    let valid = results
        .iter()
        .filter(|row| row.get("status").and_then(Value::as_str) == Some("valid"))
        .count();
    let expired = results
        .iter()
        .filter(|row| row.get("status").and_then(Value::as_str) == Some("expired"))
        .count();
    let mut map = JsonMap::new();
    insert(&mut map, "generated_at", json!(now_checked_at(Utc::now())));
    insert(&mut map, "total_domains", json!(entry_count));
    insert(&mut map, "valid", json!(valid));
    insert(&mut map, "expired", json!(expired));
    insert(&mut map, "errors", json!(results.len() - valid - expired));
    insert(&mut map, "results", Value::Array(results));
    Value::Object(map)
}

pub fn ssl_sort_key(row: &Value) -> (u8, i64) {
    let rank = match row.get("status").and_then(Value::as_str) {
        Some("dns_error") => 0,
        Some("timeout") => 1,
        Some("expired") => 2,
        Some("ssl_error") | Some("no_https") | Some("error") => 3,
        Some("invalid") => 4,
        Some("valid") => 5,
        _ => 3,
    };
    let days = row.get("days_left").and_then(Value::as_i64).unwrap_or(9999);
    (rank, days)
}

pub fn build_domain_output(mut results: Vec<Value>) -> Value {
    results.sort_by_key(domain_sort_key);
    let count = |status: &str| {
        results
            .iter()
            .filter(|row| row.get("status").and_then(Value::as_str) == Some(status))
            .count()
    };
    let mut map = JsonMap::new();
    insert(&mut map, "generated_at", json!(now_checked_at(Utc::now())));
    insert(&mut map, "total_domains", json!(results.len()));
    insert(&mut map, "active", json!(count("active")));
    insert(&mut map, "warning", json!(count("warning")));
    insert(&mut map, "urgent", json!(count("urgent")));
    insert(&mut map, "expired", json!(count("expired")));
    insert(&mut map, "results", Value::Array(results));
    Value::Object(map)
}

pub fn domain_sort_key(row: &Value) -> (u8, i64, String) {
    let status = row
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let rank = match status {
        "unknown" => 0,
        "expired" => 1,
        "urgent" => 2,
        "warning" => 3,
        "active" => 4,
        _ => 4,
    };
    let days = row
        .get("days_left")
        .and_then(Value::as_i64)
        .unwrap_or(99_999);
    let domain = row
        .get("domain")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    (rank, days, domain)
}

// ── Atomic files ─────────────────────────────────────────────────────────────

/// A JSON document as written to disk: pretty, UTF-8, trailing newline.
pub fn json_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap_or_else(|_| b"{}".to_vec());
    bytes.push(b'\n');
    bytes
}

/// Write bytes via a sibling temporary file and rename.
///
/// A crash or a full disk never leaves a half-written file for the dashboard
/// or the feed builder to read, and the previous file survives a failed write.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(directory)?;
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let unique = format!(".{}.{}.{}.tmp", name, std::process::id(), monotonic_nanos());
    let temporary: PathBuf = directory.join(unique);
    let result = (|| -> std::io::Result<()> {
        let mut handle = fs::File::create(&temporary)?;
        handle.write_all(bytes)?;
        handle.flush()?;
        handle.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn write_json_atomic(path: &Path, value: &Value) -> std::io::Result<()> {
    write_atomic(path, &json_bytes(value))
}

fn monotonic_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

pub fn read_json(path: &Path) -> Result<Value, String> {
    let text =
        fs::read_to_string(path).map_err(|exc| format!("cannot read {}: {exc}", path.display()))?;
    serde_json::from_str(&text).map_err(|exc| format!("{}: not valid JSON: {exc}", path.display()))
}
