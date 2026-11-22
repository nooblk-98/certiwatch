//! TLS probing: direct and STARTTLS handshakes, HSTS, legacy versions and
//! the legacy `check_ssl` result assembly.
//!
//! The probe intentionally separates *trust* from *name*: the chain probe
//! validates against the configured trust store with hostname checking off,
//! and the leaf's SANs are matched separately. That is what lets the checker
//! report an expired or mismatched certificate instead of only "handshake
//! failed".

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::Utc;
use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslStream, SslVerifyMode, SslVersion};
use serde_json::{json, Value};

use crate::certinfo::{
    certificate_metadata, chain_summary, derive_status, parse_der, self_signed, trim_text,
};
use crate::config::{format_endpoint, parse_endpoint, Target, TlsMode};
use crate::dns::{diagnose_dns, Resolver};
use crate::results::{
    base_ssl_result, dns_not_checked, hsts_disabled, hsts_indeterminate, hsts_not_applicable,
    legacy_tls_not_checked, JsonMap,
};

pub const DEFAULT_TIMEOUT_SECONDS: f64 = 15.0;

pub type HeaderFetcher<'a> = dyn Fn(&str, u16) -> Result<Vec<(String, String)>, String> + 'a;

#[derive(Debug, Clone)]
pub struct TlsOptions {
    pub timeout: Duration,
    pub ca_file: Option<PathBuf>,
}

impl Default for TlsOptions {
    fn default() -> Self {
        TlsOptions {
            timeout: Duration::from_secs_f64(DEFAULT_TIMEOUT_SECONDS),
            ca_file: std::env::var("SSL_CA_FILE")
                .ok()
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
        }
    }
}

#[derive(Debug)]
pub enum ProbeError {
    Dns(String),
    Timeout,
    Refused,
    Tls(String),
    Io(String),
}

pub struct TlsProbe {
    pub der: Vec<u8>,
    pub tls_version: Option<String>,
    pub cipher: Option<String>,
    pub trusted: bool,
    pub verification_error: Option<String>,
    pub chain_der: Vec<Vec<u8>>,
    pub chain_source: String,
    pub tls_mode: TlsMode,
    pub starttls_protocol: Option<String>,
}

// ── Connection helpers ───────────────────────────────────────────────────────

fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, ProbeError> {
    let addresses: Vec<std::net::SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|exc| ProbeError::Dns(format!("DNS error: {exc}")))?
        .collect();
    if addresses.is_empty() {
        return Err(ProbeError::Dns(format!("DNS error: no address for {host}")));
    }
    let deadline = Instant::now() + timeout;
    let mut last: Option<std::io::Error> = None;
    let mut saw_timeout = false;
    for address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            saw_timeout = true;
            break;
        }
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|exc| ProbeError::Io(exc.to_string()))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|exc| ProbeError::Io(exc.to_string()))?;
                return Ok(stream);
            }
            Err(error) => {
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) {
                    saw_timeout = true;
                }
                last = Some(error);
            }
        }
    }
    if saw_timeout {
        return Err(ProbeError::Timeout);
    }
    match last {
        Some(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            Err(ProbeError::Refused)
        }
        Some(error) => Err(ProbeError::Io(error.to_string())),
        None => Err(ProbeError::Timeout),
    }
}

fn is_timeout_error(message: &str) -> bool {
    let lower = message.to_lowercase();
    lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("would block")
        || lower.contains("resource temporarily unavailable")
}

fn verification_is_failed(stream: &SslStream<TcpStream>) -> bool {
    stream.ssl().verify_result() != openssl::x509::X509VerifyResult::OK
}

fn build_connector(verify: bool, opts: &TlsOptions) -> Result<SslConnector, ProbeError> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|exc| ProbeError::Tls(exc.to_string()))?;
    if verify {
        builder
            .set_default_verify_paths()
            .map_err(|exc| ProbeError::Tls(exc.to_string()))?;
        if let Some(ca_file) = opts.ca_file.as_ref() {
            builder
                .set_ca_file(ca_file)
                .map_err(|exc| ProbeError::Tls(exc.to_string()))?;
        }
        builder.set_verify(SslVerifyMode::PEER);
    } else {
        builder.set_verify(SslVerifyMode::NONE);
    }
    // Hostname checks are evaluated from SANs separately; a CN-only
    // certificate must not be rescued by OpenSSL's legacy CN fallback.
    builder.set_options(SslOptions::NO_COMPRESSION);
    Ok(builder.build())
}

fn starttls(
    stream: &mut TcpStream,
    protocol: Option<&str>,
    timeout: Duration,
) -> Result<(), ProbeError> {
    let protocol = protocol.unwrap_or("smtp").trim().to_lowercase();
    let mut budget = StartTlsBudget::new(timeout);
    match protocol.as_str() {
        "smtp" => budget.smtp(stream)?,
        "imap" => budget.imap(stream)?,
        "pop3" => budget.pop3(stream)?,
        other => {
            return Err(ProbeError::Tls(format!(
                "unsupported STARTTLS protocol: {other}"
            )))
        }
    }
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|exc| ProbeError::Io(exc.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|exc| ProbeError::Io(exc.to_string()))?;
    Ok(())
}

fn handshake(
    host: &str,
    port: u16,
    verify: bool,
    tls_mode: TlsMode,
    starttls_protocol: Option<&str>,
    opts: &TlsOptions,
) -> Result<TlsProbe, ProbeError> {
    let mut stream = connect(host, port, opts.timeout)?;
    if tls_mode == TlsMode::StartTls {
        starttls(&mut stream, starttls_protocol, opts.timeout)?;
    }
    let connector = build_connector(verify, opts)?;
    let configuration = connector
        .configure()
        .map_err(|exc| ProbeError::Tls(exc.to_string()))?;
    let ssl = configuration
        .verify_hostname(false)
        .into_ssl(host)
        .map_err(|exc| ProbeError::Tls(exc.to_string()))?;
    let mut stream = SslStream::new(ssl, stream).map_err(|exc| ProbeError::Tls(exc.to_string()))?;
    if let Err(error) = stream.connect() {
        if is_timeout_error(&error.to_string()) {
            return Err(ProbeError::Timeout);
        }
        let message = if verification_is_failed(&stream) {
            format!("{} ({})", stream.ssl().verify_result(), error)
        } else {
            error.to_string()
        };
        return Err(ProbeError::Tls(message));
    }

    let der = stream
        .ssl()
        .peer_certificate()
        .ok_or_else(|| ProbeError::Tls("server did not present a certificate".into()))?
        .to_der()
        .map_err(|exc| ProbeError::Tls(exc.to_string()))?;
    let tls_version = Some(stream.ssl().version_str().to_string());
    let cipher = stream
        .ssl()
        .current_cipher()
        .map(|cipher| cipher.name().to_string());
    let mut chain_der = Vec::new();
    if let Some(chain) = stream.ssl().peer_cert_chain() {
        for cert in chain.iter() {
            if let Ok(bytes) = cert.to_der() {
                chain_der.push(bytes);
            }
        }
    }
    if chain_der.is_empty() {
        chain_der.push(der.clone());
    }
    let chain_source = if verify { "verified" } else { "unverified" }.to_string();
    Ok(TlsProbe {
        der,
        tls_version,
        cipher,
        trusted: verify,
        verification_error: None,
        chain_der,
        chain_source,
        tls_mode,
        starttls_protocol: (tls_mode == TlsMode::StartTls)
            .then(|| starttls_protocol.unwrap_or("smtp").to_string()),
    })
}

fn probe_with_fallback(
    host: &str,
    port: u16,
    tls_mode: TlsMode,
    starttls_protocol: Option<&str>,
    opts: &TlsOptions,
) -> Result<TlsProbe, ProbeError> {
    match handshake(host, port, true, tls_mode, starttls_protocol, opts) {
        Ok(probe) => Ok(probe),
        Err(ProbeError::Tls(message)) => {
            // Only a chain failure is recoverable: read the certificate
            // without verification so dates, names and keys stay reportable.
            let mut probe = handshake(host, port, false, tls_mode, starttls_protocol, opts)
                .map_err(|_| ProbeError::Tls(message.clone()))?;
            probe.trusted = false;
            probe.verification_error = Some(strip_openssl_prefix(&message));
            Ok(probe)
        }
        Err(other) => Err(other),
    }
}

fn strip_openssl_prefix(message: &str) -> String {
    message.trim().to_string()
}

pub fn probe_endpoint(host: &str, port: u16, opts: &TlsOptions) -> Result<TlsProbe, ProbeError> {
    probe_with_fallback(host, port, TlsMode::Direct, None, opts)
}

pub fn probe_starttls(
    host: &str,
    port: u16,
    protocol: Option<&str>,
    opts: &TlsOptions,
) -> Result<TlsProbe, ProbeError> {
    probe_with_fallback(host, port, TlsMode::StartTls, protocol, opts)
}

// ── STARTTLS plaintext budget ────────────────────────────────────────────────

const STARTTLS_MAX_TOTAL_BYTES: usize = 64 * 1024;
const STARTTLS_MAX_TOTAL_LINES: usize = 128;
const STARTTLS_MAX_LINE_BYTES: usize = 4096;

pub struct StartTlsBudget {
    deadline: Instant,
    bytes_read: usize,
    bytes_written: usize,
    lines_read: usize,
    lines_written: usize,
    max_bytes: usize,
    max_lines: usize,
    max_line_bytes: usize,
}

impl StartTlsBudget {
    pub fn new(timeout: Duration) -> Self {
        StartTlsBudget {
            deadline: Instant::now() + timeout,
            bytes_read: 0,
            bytes_written: 0,
            lines_read: 0,
            lines_written: 0,
            max_bytes: STARTTLS_MAX_TOTAL_BYTES,
            max_lines: STARTTLS_MAX_TOTAL_LINES,
            max_line_bytes: STARTTLS_MAX_LINE_BYTES,
        }
    }

    fn remaining(&self) -> Result<Duration, ProbeError> {
        let now = Instant::now();
        if now >= self.deadline {
            return Err(ProbeError::Timeout);
        }
        Ok(self.deadline - now)
    }

    fn set_timeout(&self, stream: &TcpStream) -> Result<(), ProbeError> {
        stream
            .set_read_timeout(Some(self.remaining()?))
            .map_err(|exc| ProbeError::Io(exc.to_string()))?;
        stream
            .set_write_timeout(Some(self.remaining()?))
            .map_err(|exc| ProbeError::Io(exc.to_string()))
    }

    fn consume(
        &mut self,
        read: usize,
        written: usize,
        read_lines: usize,
        written_lines: usize,
    ) -> Result<(), ProbeError> {
        self.bytes_read += read;
        self.bytes_written += written;
        self.lines_read += read_lines;
        self.lines_written += written_lines;
        if self.bytes_read + self.bytes_written > self.max_bytes {
            return Err(ProbeError::Tls(
                "STARTTLS aggregate byte cap exceeded".into(),
            ));
        }
        if self.lines_read + self.lines_written > self.max_lines {
            return Err(ProbeError::Tls(
                "STARTTLS aggregate line cap exceeded".into(),
            ));
        }
        Ok(())
    }

    pub fn read_line(&mut self, stream: &mut TcpStream) -> Result<String, ProbeError> {
        let mut data = Vec::new();
        while data.len() < self.max_line_bytes {
            self.set_timeout(stream)?;
            let mut byte = [0u8; 1];
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {}
                Err(exc) if is_timeout_error(&exc.to_string()) => return Err(ProbeError::Timeout),
                Err(exc) => return Err(ProbeError::Io(exc.to_string())),
            }
            self.remaining()?;
            self.consume(1, 0, 0, 0)?;
            data.push(byte[0]);
            if data.ends_with(b"\n") {
                self.consume(0, 0, 1, 0)?;
                return Ok(String::from_utf8_lossy(&data)
                    .trim_end_matches(['\r', '\n'])
                    .to_string());
            }
        }
        if data.ends_with(b"\n") {
            self.consume(0, 0, 1, 0)?;
            return Ok(String::from_utf8_lossy(&data)
                .trim_end_matches(['\r', '\n'])
                .to_string());
        }
        if data.len() >= self.max_line_bytes {
            return Err(ProbeError::Tls("STARTTLS line length cap exceeded".into()));
        }
        if !data.is_empty() {
            self.consume(0, 0, 1, 0)?;
        }
        Ok(String::from_utf8_lossy(&data)
            .trim_end_matches(['\r', '\n'])
            .to_string())
    }

    pub fn write(&mut self, stream: &mut TcpStream, data: &[u8]) -> Result<(), ProbeError> {
        self.remaining()?;
        if data.len() > self.max_line_bytes {
            return Err(ProbeError::Tls("STARTTLS line length cap exceeded".into()));
        }
        let newlines = data.iter().filter(|byte| **byte == b'\n').count();
        self.consume(0, data.len(), 0, newlines)?;
        self.set_timeout(stream)?;
        stream
            .write_all(data)
            .map_err(|exc| ProbeError::Io(exc.to_string()))?;
        self.remaining()?;
        Ok(())
    }

    fn require(prefixes: &[&str], line: &str, protocol: &str) -> Result<(), ProbeError> {
        let upper = line.to_uppercase();
        if prefixes
            .iter()
            .any(|prefix| upper.starts_with(&prefix.to_uppercase()))
        {
            Ok(())
        } else {
            let shown: String = line.chars().take(120).collect();
            let shown = if shown.is_empty() {
                "no response".to_string()
            } else {
                shown
            };
            Err(ProbeError::Tls(format!(
                "{} did not accept STARTTLS: {shown}",
                protocol.to_uppercase()
            )))
        }
    }

    fn smtp(&mut self, stream: &mut TcpStream) -> Result<(), ProbeError> {
        let greeting = self.read_line(stream)?;
        Self::require(&["220"], &greeting, "smtp")?;
        self.write(stream, b"EHLO certiwatch.local\r\n")?;
        let mut advertised = false;
        loop {
            let line = self.read_line(stream)?;
            if line.is_empty() {
                return Err(ProbeError::Tls(
                    "SMTP closed the connection during EHLO".into(),
                ));
            }
            if line.to_uppercase().contains("STARTTLS") {
                advertised = true;
            }
            let bytes = line.as_bytes();
            if bytes.len() >= 4 && bytes[3] == b' ' {
                break;
            }
        }
        if !advertised {
            return Err(ProbeError::Tls(
                "SMTP server does not advertise STARTTLS".into(),
            ));
        }
        self.write(stream, b"STARTTLS\r\n")?;
        let reply = self.read_line(stream)?;
        Self::require(&["220"], &reply, "smtp")
    }

    fn imap(&mut self, stream: &mut TcpStream) -> Result<(), ProbeError> {
        let greeting = self.read_line(stream)?;
        let upper = greeting.to_uppercase();
        if !(upper.starts_with("* OK") || upper.starts_with("* PREAUTH")) {
            let shown: String = greeting.chars().take(120).collect();
            return Err(ProbeError::Tls(format!(
                "IMAP greeting rejected STARTTLS: {shown}"
            )));
        }
        self.write(stream, b"a001 STARTTLS\r\n")?;
        loop {
            let line = self.read_line(stream)?;
            if line.is_empty() {
                return Err(ProbeError::Tls(
                    "IMAP closed the connection during STARTTLS".into(),
                ));
            }
            if line.to_uppercase().starts_with("A001 ") {
                return Self::require(&["a001 OK"], &line, "imap");
            }
        }
    }

    fn pop3(&mut self, stream: &mut TcpStream) -> Result<(), ProbeError> {
        let greeting = self.read_line(stream)?;
        Self::require(&["+OK"], &greeting, "pop3")?;
        self.write(stream, b"STLS\r\n")?;
        let reply = self.read_line(stream)?;
        Self::require(&["+OK"], &reply, "pop3")
    }
}

// ── HSTS ─────────────────────────────────────────────────────────────────────

/// Classify a Strict-Transport-Security header without over-claiming.
pub fn classify_hsts(headers: &[(String, String)]) -> JsonMap {
    let value = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("strict-transport-security"))
        .map(|(_, value)| value.clone());

    let Some(value) = value else {
        let mut map = JsonMap::new();
        map.insert("present".into(), json!(false));
        map.insert("valid".into(), json!(false));
        map.insert("enabled".into(), json!(false));
        map.insert("status".into(), json!("absent"));
        map.insert("max_age".into(), Value::Null);
        map.insert("include_subdomains".into(), json!(false));
        map.insert("preload".into(), json!(false));
        map.insert("error".into(), Value::Null);
        return map;
    };

    let mut max_age: Option<i64> = None;
    let mut include_subdomains = false;
    let mut preload = false;
    let mut error: Option<String> = None;

    for directive in value
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (name, raw_value) = match directive.split_once('=') {
            Some((name, value)) => (
                name.trim().to_lowercase(),
                value.trim().trim_matches('"').to_string(),
            ),
            None => (directive.trim().to_lowercase(), String::new()),
        };
        match name.as_str() {
            "max-age" => match raw_value.parse::<i64>() {
                Ok(parsed) => {
                    if parsed < 0 {
                        error = Some("max-age cannot be negative".into());
                    }
                    max_age = Some(parsed);
                }
                Err(_) => error = Some("max-age is not an integer".into()),
            },
            "includesubdomains" => include_subdomains = true,
            "preload" => preload = true,
            _ => {}
        }
    }

    if max_age.is_none() && error.is_none() {
        error = Some("max-age directive is missing".into());
    }
    let valid = max_age.is_some_and(|value| value >= 0);
    let enabled = valid && max_age.unwrap_or_default() > 0;
    let status = if !valid {
        "invalid"
    } else if !enabled {
        "disabled"
    } else {
        "present"
    };

    let mut map = JsonMap::new();
    map.insert("present".into(), json!(true));
    map.insert("valid".into(), json!(valid));
    map.insert("enabled".into(), json!(enabled));
    map.insert("status".into(), json!(status));
    map.insert("max_age".into(), json!(max_age));
    map.insert("include_subdomains".into(), json!(include_subdomains));
    map.insert("preload".into(), json!(preload));
    map.insert("error".into(), json!(error));
    map
}

fn fetch_https_headers(
    host: &str,
    port: u16,
    opts: &TlsOptions,
) -> Result<Vec<(String, String)>, String> {
    let stream = connect(host, port, opts.timeout).map_err(|exc| format!("{exc:?}"))?;
    let mut builder =
        SslConnector::builder(SslMethod::tls_client()).map_err(|exc| exc.to_string())?;
    builder
        .set_default_verify_paths()
        .map_err(|exc| exc.to_string())?;
    if let Some(ca_file) = opts.ca_file.as_ref() {
        builder
            .set_ca_file(ca_file)
            .map_err(|exc| exc.to_string())?;
    }
    builder.set_verify(SslVerifyMode::PEER);
    let connector = builder.build();
    let ssl = connector
        .configure()
        .map_err(|exc| exc.to_string())?
        .verify_hostname(true)
        .into_ssl(host)
        .map_err(|exc| exc.to_string())?;
    let mut stream = SslStream::new(ssl, stream).map_err(|exc| exc.to_string())?;
    stream.connect().map_err(|exc| exc.to_string())?;

    let host_header = format_endpoint(host, port);
    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: CertiWatch/1.0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|exc| exc.to_string())?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).map_err(|exc| exc.to_string())?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") || buffer.len() > 64 * 1024 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buffer);
    let mut headers = Vec::new();
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.push((key.trim().to_lowercase(), value.trim().to_string()));
        }
    }
    Ok(headers)
}

/// Read HSTS only for an HTTPS origin; a non-HTTPS endpoint is inapplicable.
pub fn check_hsts<'a>(
    host: &str,
    port: u16,
    applicable: bool,
    opts: &TlsOptions,
    fetcher: Option<&HeaderFetcher<'a>>,
) -> JsonMap {
    if !applicable {
        return hsts_not_applicable();
    }
    let result = match fetcher {
        Some(fetcher) => fetcher(host, port),
        None => fetch_https_headers(host, port, opts),
    };
    match result {
        Ok(headers) => {
            let mut classification = classify_hsts(&headers);
            classification.insert("applicable".into(), json!(true));
            classification.insert("checked".into(), json!(true));
            classification
        }
        Err(error) => {
            let text = trim_text(&error, 180);
            hsts_indeterminate(if text.is_empty() {
                "HTTPS connection could not be authenticated"
            } else {
                &text
            })
        }
    }
}

// ── Legacy TLS ───────────────────────────────────────────────────────────────

fn classify_legacy_error(message: &str) -> &'static str {
    let text = message.to_lowercase();
    for marker in [
        "no protocols available",
        "unsupported protocol",
        "unknown protocol",
        "no ciphers available",
        "no cipher match",
    ] {
        if text.contains(marker) {
            return "local_unsupported";
        }
    }
    "not_supported"
}

enum LegacyFailure {
    Io,
    Tls(String),
    Local,
}

fn legacy_handshake(
    host: &str,
    port: u16,
    version: &str,
    tls_mode: TlsMode,
    protocol: Option<&str>,
    opts: &TlsOptions,
) -> Result<(), LegacyFailure> {
    let mut stream = connect(host, port, opts.timeout).map_err(|exc| match exc {
        ProbeError::Tls(message) => LegacyFailure::Tls(message),
        other => {
            let _ = other;
            LegacyFailure::Io
        }
    })?;
    if tls_mode == TlsMode::StartTls {
        starttls(&mut stream, protocol, opts.timeout).map_err(|exc| match exc {
            ProbeError::Tls(message) => LegacyFailure::Tls(message),
            other => {
                let _ = other;
                LegacyFailure::Io
            }
        })?;
    }
    let mut builder =
        SslConnector::builder(SslMethod::tls_client()).map_err(|_| LegacyFailure::Local)?;
    builder.set_verify(SslVerifyMode::NONE);
    let selected = match version {
        "tls10" => SslVersion::TLS1,
        "tls11" => SslVersion::TLS1_1,
        _ => return Err(LegacyFailure::Local),
    };
    builder
        .set_min_proto_version(Some(selected))
        .map_err(|_| LegacyFailure::Local)?;
    builder
        .set_max_proto_version(Some(selected))
        .map_err(|_| LegacyFailure::Local)?;
    let connector = builder.build();
    let ssl = connector
        .configure()
        .map_err(|_| LegacyFailure::Local)?
        .verify_hostname(false)
        .into_ssl(host)
        .map_err(|_| LegacyFailure::Local)?;
    let mut stream = SslStream::new(ssl, stream).map_err(|_| LegacyFailure::Local)?;
    stream.connect().map_err(|exc| {
        let message = exc.to_string();
        if is_timeout_error(&message) {
            LegacyFailure::Io
        } else {
            LegacyFailure::Tls(message)
        }
    })?;
    Ok(())
}

pub fn probe_legacy_version(
    host: &str,
    port: u16,
    version: &str,
    tls_mode: TlsMode,
    protocol: Option<&str>,
    opts: &TlsOptions,
) -> String {
    if version != "tls10" && version != "tls11" {
        return "local_unsupported".into();
    }
    match legacy_handshake(host, port, version, tls_mode, protocol, opts) {
        Ok(()) => "supported".into(),
        Err(LegacyFailure::Io) => "unknown".into(),
        Err(LegacyFailure::Local) => "local_unsupported".into(),
        Err(LegacyFailure::Tls(message)) => classify_legacy_error(&message).to_string(),
    }
}

pub fn check_legacy_tls(
    host: &str,
    port: u16,
    tls_mode: TlsMode,
    protocol: Option<&str>,
    opts: &TlsOptions,
) -> JsonMap {
    let mut map = JsonMap::new();
    map.insert("checked".into(), json!(true));
    map.insert(
        "tls10".into(),
        json!(probe_legacy_version(
            host, port, "tls10", tls_mode, protocol, opts
        )),
    );
    map.insert(
        "tls11".into(),
        json!(probe_legacy_version(
            host, port, "tls11", tls_mode, protocol, opts
        )),
    );
    map.insert(
        "note".into(),
        json!("local_unsupported means this machine's OpenSSL/Python cannot try the protocol; it is not evidence about the server. not_supported and supported are remote outcomes."),
    );
    map
}

// ── Result assembly ──────────────────────────────────────────────────────────

fn apply_probe(result: &mut JsonMap, probe: &TlsProbe, match_host: &str) -> Result<(), String> {
    let cert = parse_der(&probe.der)?;
    let metadata = certificate_metadata(&cert, match_host, Utc::now())?;
    for (key, value) in metadata.into_map() {
        result.insert(key, value);
    }

    let chain_der = if probe.chain_der.is_empty() {
        vec![probe.der.clone()]
    } else {
        probe.chain_der.clone()
    };
    let (chain, complete) = chain_summary(&chain_der);
    let chain_length = chain.len();
    result.insert("chain".into(), Value::Array(chain.clone()));
    result.insert("chain_length".into(), json!(chain_length));
    result.insert("chain_source".into(), json!(probe.chain_source));
    if !complete {
        result.insert(
            "chain_error".into(),
            json!("Some certificates in the chain could not be parsed"),
        );
    }
    if let Some(error) = probe.verification_error.as_deref() {
        result.insert("chain_error".into(), json!(trim_text(error, 240)));
    }
    result.insert("trusted_chain".into(), json!(probe.trusted));
    result.insert("tls_version".into(), json!(probe.tls_version));
    result.insert("cipher".into(), json!(probe.cipher));

    let is_self_signed = self_signed(&chain);
    let days_left = result.get("days_left").and_then(Value::as_i64);
    let is_expired = result
        .get("is_expired")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let host_matches = result.get("hostname_matches").and_then(Value::as_bool);
    let (status, error) = derive_status(
        days_left,
        is_expired,
        probe.trusted,
        host_matches,
        probe.verification_error.as_deref(),
        is_self_signed,
    );
    result.insert("status".into(), json!(status));
    result.insert("error".into(), json!(error));
    Ok(())
}

fn check_target(
    host: &str,
    port: u16,
    result: &mut JsonMap,
    tls_mode: TlsMode,
    starttls_protocol: Option<&str>,
    opts: &TlsOptions,
) -> Result<(), ProbeError> {
    let probe = if tls_mode == TlsMode::StartTls {
        probe_starttls(host, port, starttls_protocol, opts)?
    } else {
        probe_endpoint(host, port, opts)?
    };
    apply_probe(result, &probe, host).map_err(ProbeError::Tls)
}

fn attach_www_fallback(result: &mut JsonMap, host: &str, port: u16, opts: &TlsOptions) {
    if port != 443 || host.starts_with("www.") {
        return;
    }
    let fallback_host = format!("www.{host}");
    let fallback_domain = format_endpoint(&fallback_host, port);
    let mut fallback = base_ssl_result(&fallback_domain, &fallback_host, port, Utc::now());
    if check_target(
        &fallback_host,
        port,
        &mut fallback,
        TlsMode::Direct,
        None,
        opts,
    )
    .is_err()
    {
        return;
    }
    fallback.insert("resolved_via".into(), json!(fallback_domain));
    result.insert("fallback".into(), Value::Object(fallback));
}

fn apply_configured_diagnostics(
    result: &mut JsonMap,
    host: &str,
    port: u16,
    target: Option<&Target>,
    opts: &TlsOptions,
    resolver: &dyn Resolver,
) {
    let Some(target) = target else {
        result.insert("https".into(), json!(port == 443));
        return;
    };
    for (key, value) in target.connection_metadata() {
        result.insert(key, value);
    }
    let dns_name = target.dns_name_value();
    result.insert("dns_name".into(), json!(dns_name));

    if target.check_dns {
        let diagnostics = diagnose_dns(&dns_name, resolver);
        result.insert("dns".into(), Value::Object(diagnostics));
    } else {
        result.insert(
            "dns".into(),
            Value::Object(dns_not_checked(Some(&dns_name))),
        );
    }

    if target.is_https() {
        if target.check_hsts {
            let hsts = check_hsts(host, port, true, opts, None);
            result.insert("hsts".into(), Value::Object(hsts));
        } else {
            result.insert("hsts".into(), Value::Object(hsts_disabled()));
        }
    } else {
        result.insert("hsts".into(), Value::Object(hsts_not_applicable()));
    }

    if target.check_legacy_tls {
        let legacy = check_legacy_tls(
            host,
            port,
            target.tls_mode,
            target.starttls_protocol.map(|value| value.as_str()),
            opts,
        );
        result.insert("legacy_tls".into(), Value::Object(legacy));
    } else {
        result.insert("legacy_tls".into(), Value::Object(legacy_tls_not_checked()));
    }
}

/// Check the TLS endpoint named by `domain` (`host` or `host:port`).
pub fn check_ssl(
    domain: &str,
    target: Option<&Target>,
    opts: &TlsOptions,
    resolver: &dyn Resolver,
) -> JsonMap {
    let Some((host, port)) = parse_endpoint(domain) else {
        let clean = if domain.trim().is_empty() {
            "empty entry".to_string()
        } else {
            domain.trim().to_string()
        };
        let mut result = base_ssl_result(&clean, &clean, 443, Utc::now());
        result.insert("status".into(), json!("error"));
        result.insert("error".into(), json!("Invalid host or port"));
        return result;
    };

    let canonical = format_endpoint(&host, port);
    let mut result = base_ssl_result(&canonical, &host, port, Utc::now());
    let tls_mode = target
        .map(|value| value.tls_mode)
        .unwrap_or(TlsMode::Direct);
    let starttls_protocol = target
        .and_then(|value| value.starttls_protocol)
        .map(|value| value.as_str());
    if let Some(target) = target {
        for (key, value) in target.connection_metadata() {
            result.insert(key, value);
        }
        result.insert("dns_name".into(), json!(target.dns_name_value()));
    }

    match check_target(&host, port, &mut result, tls_mode, starttls_protocol, opts) {
        Ok(()) => {}
        Err(ProbeError::Tls(first)) => {
            // Transient handshake failures are common: retry once.
            match check_target(&host, port, &mut result, tls_mode, starttls_protocol, opts) {
                Ok(()) => {}
                Err(_) => {
                    result.insert("status".into(), json!("ssl_error"));
                    result.insert(
                        "error".into(),
                        json!(format!("SSL error: {}", trim_text(&first, 120))),
                    );
                }
            }
        }
        Err(ProbeError::Timeout) => {
            result.insert("status".into(), json!("timeout"));
            result.insert("error".into(), json!("Connection timed out"));
            if tls_mode == TlsMode::Direct {
                attach_www_fallback(&mut result, &host, port, opts);
            }
        }
        Err(ProbeError::Dns(message)) => {
            result.insert("status".into(), json!("dns_error"));
            result.insert(
                "error".into(),
                json!(format!("DNS error: {}", trim_text(&message, 120))),
            );
            if tls_mode == TlsMode::Direct {
                attach_www_fallback(&mut result, &host, port, opts);
            }
        }
        Err(ProbeError::Refused) => {
            result.insert("status".into(), json!("no_https"));
            result.insert("error".into(), json!(format!("Port {port} refused")));
        }
        Err(ProbeError::Io(message)) => {
            result.insert("status".into(), json!("error"));
            result.insert("error".into(), json!(trim_text(&message, 120)));
        }
    }

    apply_configured_diagnostics(&mut result, &host, port, target, opts, resolver);
    if let Some(target) = target {
        for (key, value) in target.public_metadata() {
            result.insert(key, value);
        }
    }
    result
}
