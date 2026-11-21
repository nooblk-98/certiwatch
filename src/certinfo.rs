//! Certificate parsing and the pure TLS judgement helpers.
//!
//! These functions are deliberately separable from the network: certificate
//! metadata, hostname matching, key strength, issuer labelling and status
//! derivation can be tested and replayed without a socket.

use std::net::IpAddr;
use std::sync::OnceLock;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::Id;
use openssl::x509::{X509Ref, X509};
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::results::{iso_z, JsonMap};

const CA_RULES: &[(&str, &str)] = &[
    (r"let'?s\s*encrypt|letsencrypt", "Let's Encrypt"),
    (r"cloudflare", "Cloudflare SSL"),
    (r"sectigo|comodo", "Sectigo / Comodo"),
    (r"digicert", "DigiCert"),
    (r"geotrust", "GeoTrust"),
    (r"globalsign", "GlobalSign"),
    (r"go\s*daddy|godaddy", "GoDaddy"),
    (r"rapidssl", "RapidSSL"),
    (r"thawte", "Thawte"),
    (r"\bamazon\b|\baws\b", "Amazon / AWS"),
    (r"google trust services|\bgts\b", "Google Trust Services"),
    (r"zerossl", "ZeroSSL"),
    (r"ssl\.com", "SSL.com"),
    (r"12ssl|twelve\s*ssl", "12SSL"),
    (r"entrust", "Entrust"),
    (r"buypass", "Buypass"),
    (r"identrust", "IdenTrust"),
    (r"microsoft", "Microsoft"),
];

fn ca_rules() -> &'static Vec<(Regex, &'static str)> {
    static RULES: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    RULES.get_or_init(|| {
        CA_RULES
            .iter()
            .map(|(pattern, label)| {
                (
                    Regex::new(&format!("(?i){pattern}")).expect("static provider pattern"),
                    *label,
                )
            })
            .collect()
    })
}

#[derive(Debug, Clone)]
pub struct CertificateMetadata {
    pub issued_on: String,
    pub expires_on: String,
    pub days_left: i64,
    pub is_expired: bool,
    pub provider: String,
    pub not_before: String,
    pub not_after: String,
    pub common_name: Option<String>,
    pub san: Vec<String>,
    pub san_count: usize,
    pub wildcard: bool,
    pub hostname_matches: bool,
    pub key_type: Option<String>,
    pub key_size: Option<u32>,
    pub key_curve: Option<String>,
    pub key_strength: String,
    pub fingerprint_sha256: String,
    pub serial_number: String,
}

impl CertificateMetadata {
    pub fn into_map(self) -> JsonMap {
        let mut map = JsonMap::new();
        map.insert("issued_on".into(), json!(self.issued_on));
        map.insert("expires_on".into(), json!(self.expires_on));
        map.insert("days_left".into(), json!(self.days_left));
        map.insert("is_expired".into(), json!(self.is_expired));
        map.insert("provider".into(), json!(self.provider));
        map.insert("not_before".into(), json!(self.not_before));
        map.insert("not_after".into(), json!(self.not_after));
        map.insert("common_name".into(), json!(self.common_name));
        map.insert("san".into(), json!(self.san));
        map.insert("san_count".into(), json!(self.san_count));
        map.insert("wildcard".into(), json!(self.wildcard));
        map.insert("hostname_matches".into(), json!(self.hostname_matches));
        map.insert("key_type".into(), json!(self.key_type));
        map.insert("key_size".into(), json!(self.key_size));
        map.insert("key_curve".into(), json!(self.key_curve));
        map.insert("key_strength".into(), json!(self.key_strength));
        map.insert("fingerprint_sha256".into(), json!(self.fingerprint_sha256));
        map.insert("serial_number".into(), json!(self.serial_number));
        map
    }
}

/// Detect the certificate authority label from issuer organization/common name.
pub fn detect_provider(organization: Option<&str>, common_name: Option<&str>) -> String {
    let combined = format!(
        "{} {}",
        organization.unwrap_or_default(),
        common_name.unwrap_or_default()
    );
    for (pattern, label) in ca_rules() {
        if pattern.is_match(&combined) {
            return (*label).to_string();
        }
    }
    if let Some(org) = organization.filter(|value| !value.is_empty()) {
        return org.to_string();
    }
    if let Some(cn) = common_name.filter(|value| !value.is_empty()) {
        return cn.to_string();
    }
    "Unknown".to_string()
}

/// Classify a leaf key without pretending a borderline key is safe.
pub fn classify_key_strength(key_type: Option<&str>, key_size: Option<i64>) -> String {
    match key_type {
        Some("RSA") => match key_size {
            None => "unknown".into(),
            Some(size) if size < 2048 => "weak".into(),
            Some(size) if size < 3072 => "acceptable".into(),
            Some(_) => "strong".into(),
        },
        Some("ECDSA") => match key_size {
            None => "unknown".into(),
            Some(size) if size < 256 => "weak".into(),
            Some(size) if size < 384 => "acceptable".into(),
            Some(_) => "strong".into(),
        },
        Some("Ed25519") | Some("Ed448") => "strong".into(),
        Some("DSA") => "weak".into(),
        _ => "unknown".into(),
    }
}

/// RFC 6125-style wildcard match: a wildcard covers exactly one leftmost label.
pub fn dnsname_match(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_lowercase();
    let host = host.trim_end_matches('.').to_lowercase();
    if pattern == host {
        return true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let suffix_labels: Vec<&str> = suffix.split('.').collect();
    if suffix_labels.len() < 2 || suffix_labels.iter().any(|label| label.is_empty()) {
        return false;
    }
    let Some(prefix) = host.strip_suffix(&format!(".{suffix}")) else {
        return false;
    };
    !prefix.is_empty() && !prefix.contains('.')
}

/// Check a host or IP literal against SAN entries only; the CN is ignored.
pub fn hostname_matches(host: &str, dns_names: &[String], ip_addresses: &[String]) -> bool {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    if let Ok(wanted) = host.parse::<IpAddr>() {
        return ip_addresses
            .iter()
            .filter_map(|candidate| candidate.parse::<IpAddr>().ok())
            .any(|candidate| candidate == wanted);
    }
    dns_names
        .iter()
        .any(|pattern| dnsname_match(pattern, &host))
}

fn name_field(cert: &X509Ref, nid: Nid) -> Option<String> {
    let name = cert.subject_name();
    let entry = name.entries_by_nid(nid).next()?;
    entry.data().to_string().ok()
}

fn issuer_field(cert: &X509Ref, nid: Nid) -> Option<String> {
    let name = cert.issuer_name();
    let entry = name.entries_by_nid(nid).next()?;
    entry.data().to_string().ok()
}

/// Parse the OpenSSL ASN.1 time text (`Nov 21 12:00:00 2026 GMT`).
fn parse_asn1_time(text: &str) -> Option<DateTime<Utc>> {
    let trimmed = text.trim();
    let naive = NaiveDateTime::parse_from_str(trimmed, "%b %e %H:%M:%S %Y GMT")
        .or_else(|_| NaiveDateTime::parse_from_str(trimmed, "%b %d %H:%M:%S %Y GMT"))
        .ok()?;
    Some(Utc.from_utc_datetime(&naive))
}

fn subject_alt_names(cert: &X509Ref) -> (Vec<String>, Vec<String>) {
    let mut dns_names = Vec::new();
    let mut ip_addresses = Vec::new();
    if let Some(names) = cert.subject_alt_names() {
        for name in names.iter() {
            if let Some(dns) = name.dnsname() {
                dns_names.push(dns.to_string());
            } else if let Some(bytes) = name.ipaddress() {
                match bytes.len() {
                    4 => {
                        let octets: [u8; 4] = bytes.try_into().expect("4 bytes");
                        ip_addresses.push(std::net::Ipv4Addr::from(octets).to_string());
                    }
                    16 => {
                        let octets: [u8; 16] = bytes.try_into().expect("16 bytes");
                        ip_addresses.push(std::net::Ipv6Addr::from(octets).to_string());
                    }
                    _ => {}
                }
            }
        }
    }
    (dns_names, ip_addresses)
}

fn key_metadata(cert: &X509Ref) -> (Option<String>, Option<u32>, Option<String>) {
    let Ok(key) = cert.public_key() else {
        return (None, None, None);
    };
    let id = key.id();
    let key_type = match id {
        Id::RSA | Id::RSA_PSS => "RSA",
        Id::EC => "ECDSA",
        Id::ED25519 => "Ed25519",
        Id::ED448 => "Ed448",
        Id::DSA => "DSA",
        _ => return (None, None, None),
    };
    let size = if matches!(key_type, "Ed25519" | "Ed448") {
        None
    } else {
        Some(key.bits())
    };
    let curve = if key_type == "ECDSA" {
        key.ec_key()
            .ok()
            .and_then(|ec| ec.group().curve_name())
            .map(curve_label)
    } else {
        None
    };
    (Some(key_type.to_string()), size, curve)
}

fn curve_label(nid: Nid) -> String {
    match nid {
        Nid::X9_62_PRIME256V1 => "secp256r1".into(),
        Nid::SECP384R1 => "secp384r1".into(),
        Nid::SECP521R1 => "secp521r1".into(),
        Nid::SECP256K1 => "secp256k1".into(),
        other => other.short_name().unwrap_or("unknown").to_string(),
    }
}

fn fingerprint(cert: &X509Ref) -> Option<String> {
    let digest = cert.digest(MessageDigest::sha256()).ok()?;
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Some(hex)
}

fn serial_number(cert: &X509Ref) -> Option<String> {
    let bn = cert.serial_number().to_bn().ok()?;
    let text = bn.to_hex_str().ok()?;
    Some(text.to_string().to_uppercase())
}

/// Return the JSON fields that describe one leaf certificate.
pub fn certificate_metadata(
    cert: &X509Ref,
    host: &str,
    now: DateTime<Utc>,
) -> Result<CertificateMetadata, String> {
    let organization = issuer_field(cert, Nid::ORGANIZATIONNAME);
    let issuer_cn = issuer_field(cert, Nid::COMMONNAME);
    let subject_cn = name_field(cert, Nid::COMMONNAME);
    let (dns_names, ip_addresses) = subject_alt_names(cert);

    let not_before = parse_asn1_time(&cert.not_before().to_string())
        .ok_or_else(|| "certificate notBefore is not readable".to_string())?;
    let not_after = parse_asn1_time(&cert.not_after().to_string())
        .ok_or_else(|| "certificate notAfter is not readable".to_string())?;

    // Python's timedelta.days floors towards negative infinity; chrono's
    // num_days truncates towards zero for negative durations.
    let days_left = (not_after - now).num_seconds().div_euclid(86_400);
    let is_expired = now >= not_after;

    let (key_type, key_size, key_curve) = key_metadata(cert);
    let mut san: Vec<String> = dns_names.to_vec();
    san.extend(ip_addresses.iter().cloned());
    let san_count = san.len();
    let mut wildcard = dns_names.iter().any(|name| name.starts_with("*."));
    if !wildcard {
        if let Some(cn) = subject_cn.as_deref() {
            wildcard = cn.starts_with("*.");
        }
    }

    Ok(CertificateMetadata {
        issued_on: not_before.format("%Y-%m-%d").to_string(),
        expires_on: not_after.format("%Y-%m-%d").to_string(),
        days_left,
        is_expired,
        provider: detect_provider(organization.as_deref(), issuer_cn.as_deref()),
        not_before: iso_z(not_before),
        not_after: iso_z(not_after),
        common_name: subject_cn,
        san,
        san_count,
        wildcard,
        hostname_matches: hostname_matches(host, &dns_names, &ip_addresses),
        key_type: key_type.clone(),
        key_size,
        key_curve,
        key_strength: classify_key_strength(key_type.as_deref(), key_size.map(i64::from)),
        fingerprint_sha256: fingerprint(cert).unwrap_or_default(),
        serial_number: serial_number(cert).unwrap_or_default(),
    })
}

pub fn parse_der(der: &[u8]) -> Result<X509, String> {
    X509::from_der(der).map_err(|exc| exc.to_string())
}

fn is_ca(der: &[u8]) -> bool {
    // OpenSSL's safe API does not decode BasicConstraints; the parser is used
    // for this one field only.
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        return false;
    };
    for extension in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::BasicConstraints(constraints) =
            extension.parsed_extension()
        {
            return constraints.ca;
        }
    }
    false
}

/// Parse a DER chain into compact JSON rows. Unparseable entries are skipped.
pub fn chain_summary(chain_der: &[Vec<u8>]) -> (Vec<Value>, bool) {
    let mut rows = Vec::new();
    let mut complete = true;
    for der in chain_der {
        let Ok(cert) = parse_der(der) else {
            complete = false;
            continue;
        };
        let subject = name_field(&cert, Nid::COMMONNAME)
            .or_else(|| name_field(&cert, Nid::ORGANIZATIONNAME))
            .unwrap_or_else(|| "Unknown".to_string());
        let issuer = issuer_field(&cert, Nid::COMMONNAME)
            .or_else(|| issuer_field(&cert, Nid::ORGANIZATIONNAME))
            .unwrap_or_else(|| "Unknown".to_string());
        let not_before = parse_asn1_time(&cert.not_before().to_string())
            .map(iso_z)
            .unwrap_or_default();
        let not_after = parse_asn1_time(&cert.not_after().to_string())
            .map(iso_z)
            .unwrap_or_default();
        let mut map = Map::new();
        map.insert("subject".into(), json!(subject));
        map.insert("issuer".into(), json!(issuer));
        map.insert("not_before".into(), json!(not_before));
        map.insert("not_after".into(), json!(not_after));
        map.insert("is_ca".into(), json!(is_ca(der)));
        rows.push(Value::Object(map));
    }
    (rows, complete)
}

pub fn self_signed(chain: &[Value]) -> bool {
    chain.len() == 1
        && chain[0].get("subject") == chain[0].get("issuer")
        && chain[0]
            .get("subject")
            .and_then(Value::as_str)
            .map(|value| !value.is_empty())
            .unwrap_or(false)
}

pub fn trim_text(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        value.to_string()
    } else {
        let mut text: String = value.chars().take(limit.saturating_sub(1)).collect();
        text.push('…');
        text
    }
}

/// Map probe facts to the legacy `(status, error)` pair.
pub fn derive_status(
    days_left: Option<i64>,
    is_expired: bool,
    trusted_chain: bool,
    host_matches: Option<bool>,
    verification_error: Option<&str>,
    self_signed: bool,
) -> (String, Option<String>) {
    if days_left.is_none() {
        return (
            "invalid".into(),
            Some("Certificate has no readable expiry date".into()),
        );
    }
    if is_expired {
        return ("expired".into(), Some("Certificate has expired".into()));
    }
    if host_matches == Some(false) {
        return ("invalid".into(), Some("Hostname mismatch".into()));
    }
    if !trusted_chain {
        if self_signed {
            return ("invalid".into(), Some("Self-signed certificate".into()));
        }
        if let Some(error) = verification_error {
            return (
                "invalid".into(),
                Some(format!(
                    "Certificate verification failed: {}",
                    trim_text(error, 180)
                )),
            );
        }
        return (
            "invalid".into(),
            Some("Certificate chain is not trusted".into()),
        );
    }
    ("valid".into(), None)
}
