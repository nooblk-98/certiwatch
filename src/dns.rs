//! Defensive DNS diagnostics for configured targets.
//!
//! Three questions stay separate: data is `present`, an authoritative
//! `absent` answer, or `unknown` when the lookup failed. DNSSEC is
//! `validated` only when the resolver sets the AD bit; returned DNSKEY
//! material alone is `present`.
//!
//! The resolver is a trait so tests (and deterministic recordings) never make
//! DNS traffic. [`SystemResolver`] talks to the nameservers in
//! `/etc/resolv.conf` with the DO bit set.

use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use regex::Regex;
use serde_json::{json, Value};

use crate::results::{dns_failed, JsonMap, DNS_LIMITS};

pub const STATUS_PRESENT: &str = "present";
pub const STATUS_ABSENT: &str = "absent";
pub const STATUS_UNKNOWN: &str = "unknown";
pub const STATUS_VALIDATED: &str = "validated";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    Ns(String),
    Caa {
        flags: u8,
        tag: String,
        value: String,
    },
    Dnskey(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupAnswer {
    pub ad: bool,
    pub records: Vec<RecordData>,
    pub rrsig_count: usize,
}

/// Absence carries an optional explanation: NODATA has none, NXDOMAIN does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupFailure {
    Absent(Option<String>),
    Unknown(String),
}

pub trait Resolver {
    fn lookup(&self, name: &str, record_type: RecordType) -> Result<LookupAnswer, LookupFailure>;
}

fn label_re() -> &'static Regex {
    static LABEL: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    LABEL.get_or_init(|| Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("static regex"))
}

pub fn normalise_name(name: &str) -> Option<String> {
    let text = name.trim().trim_end_matches('.').to_lowercase();
    let labels: Vec<&str> = text.split('.').collect();
    if labels.len() < 2 || labels.last().map(|label| label.len()).unwrap_or(0) < 2 {
        return None;
    }
    if labels.iter().any(|label| !label_re().is_match(label)) {
        return None;
    }
    Some(text)
}

fn record_map(status: &str, records: Vec<Value>, error: Option<&str>) -> Value {
    json!({"status": status, "records": records, "error": error})
}

fn dnssec_map(
    status: &str,
    validated: bool,
    records: Vec<Value>,
    signature_count: usize,
    error: Option<&str>,
    include_limits: bool,
) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("status".into(), json!(status));
    map.insert("validated".into(), json!(validated));
    map.insert("records".into(), json!(records));
    map.insert("signature_count".into(), json!(signature_count));
    map.insert("error".into(), json!(error));
    if include_limits {
        map.insert("limits".into(), json!(DNS_LIMITS));
    }
    Value::Object(map)
}

fn unavailable(name: &str, error: &str) -> JsonMap {
    let mut map = JsonMap::new();
    map.insert("checked".into(), json!(false));
    map.insert("name".into(), json!(name));
    map.insert(
        "ns".into(),
        record_map(STATUS_UNKNOWN, Vec::new(), Some(error)),
    );
    map.insert(
        "caa".into(),
        record_map(STATUS_UNKNOWN, Vec::new(), Some(error)),
    );
    map.insert(
        "dnssec".into(),
        dnssec_map(STATUS_UNKNOWN, false, Vec::new(), 0, Some(error), true),
    );
    map.insert("error".into(), json!(error));
    map
}

/// Return NS, CAA and DNSSEC diagnostics for `name`.
pub fn diagnose_dns(name: &str, resolver: &dyn Resolver) -> JsonMap {
    let Some(normalised) = normalise_name(name) else {
        return unavailable(name.trim(), "invalid DNS name");
    };

    let ns = match resolver.lookup(&normalised, RecordType::NS) {
        Ok(answer) => {
            let mut records: Vec<String> = answer
                .records
                .iter()
                .filter_map(|record| match record {
                    RecordData::Ns(value) => Some(value.trim().to_string()),
                    _ => None,
                })
                .filter(|value| !value.is_empty())
                .collect();
            records.sort();
            records.dedup();
            if records.is_empty() {
                record_map(STATUS_ABSENT, Vec::new(), None)
            } else {
                record_map(
                    STATUS_PRESENT,
                    records.into_iter().map(Value::String).collect(),
                    None,
                )
            }
        }
        Err(LookupFailure::Absent(error)) => {
            record_map(STATUS_ABSENT, Vec::new(), error.as_deref())
        }
        Err(LookupFailure::Unknown(error)) => record_map(STATUS_UNKNOWN, Vec::new(), Some(&error)),
    };

    let caa = match resolver.lookup(&normalised, RecordType::CAA) {
        Ok(answer) => {
            let mut rows: Vec<(String, String, u8)> = answer
                .records
                .iter()
                .filter_map(|record| match record {
                    RecordData::Caa { flags, tag, value } => {
                        Some((tag.clone(), value.clone(), *flags))
                    }
                    _ => None,
                })
                .collect();
            rows.sort();
            if rows.is_empty() {
                record_map(STATUS_ABSENT, Vec::new(), None)
            } else {
                let values: Vec<Value> = rows
                    .into_iter()
                    .map(|(tag, value, flags)| json!({"flags": flags, "tag": tag, "value": value}))
                    .collect();
                record_map(STATUS_PRESENT, values, None)
            }
        }
        Err(LookupFailure::Absent(error)) => {
            record_map(STATUS_ABSENT, Vec::new(), error.as_deref())
        }
        Err(LookupFailure::Unknown(error)) => record_map(STATUS_UNKNOWN, Vec::new(), Some(&error)),
    };

    let dnssec = match resolver.lookup(&normalised, RecordType::DNSKEY) {
        Ok(answer) => {
            let records: Vec<Value> = answer
                .records
                .iter()
                .filter_map(|record| match record {
                    RecordData::Dnskey(value) if !value.trim().is_empty() => {
                        Some(Value::String(value.trim().to_string()))
                    }
                    _ => None,
                })
                .collect();
            if records.is_empty() {
                dnssec_map(
                    STATUS_ABSENT,
                    false,
                    Vec::new(),
                    answer.rrsig_count,
                    None,
                    true,
                )
            } else if answer.ad {
                dnssec_map(
                    STATUS_VALIDATED,
                    true,
                    records,
                    answer.rrsig_count,
                    None,
                    true,
                )
            } else {
                dnssec_map(
                    STATUS_PRESENT,
                    false,
                    records,
                    answer.rrsig_count,
                    None,
                    true,
                )
            }
        }
        Err(LookupFailure::Absent(error)) => {
            dnssec_map(STATUS_ABSENT, false, Vec::new(), 0, error.as_deref(), true)
        }
        Err(LookupFailure::Unknown(error)) => {
            dnssec_map(STATUS_UNKNOWN, false, Vec::new(), 0, Some(&error), true)
        }
    };

    let mut map = JsonMap::new();
    map.insert("checked".into(), json!(true));
    map.insert("name".into(), json!(normalised));
    map.insert("ns".into(), ns);
    map.insert("caa".into(), caa);
    map.insert("dnssec".into(), dnssec);
    map.insert("limits".into(), json!(DNS_LIMITS));
    map.insert("error".into(), Value::Null);
    map
}

/// Diagnostics that could not run at all; every record is `unknown`.
pub fn failed(name: Option<&str>, error: &str) -> JsonMap {
    dns_failed(name, error)
}

// ── System resolver ──────────────────────────────────────────────────────────

pub struct SystemResolver {
    nameservers: Vec<SocketAddr>,
    timeout: Duration,
}

impl SystemResolver {
    pub fn new(timeout: Duration) -> Self {
        SystemResolver {
            nameservers: system_nameservers(),
            timeout,
        }
    }

    pub fn with_nameservers(nameservers: Vec<SocketAddr>, timeout: Duration) -> Self {
        SystemResolver {
            nameservers,
            timeout,
        }
    }

    fn exchange(&self, query: &Message) -> Result<Message, LookupFailure> {
        let encoded = query
            .to_bytes()
            .map_err(|exc| LookupFailure::Unknown(format!("could not encode DNS query: {exc}")))?;
        let mut last_error = String::from("no resolver configured");
        for nameserver in &self.nameservers {
            match self.exchange_udp(nameserver, query, &encoded) {
                Ok(message) => {
                    if message.metadata.truncation {
                        match self.exchange_tcp(nameserver, query, &encoded) {
                            Ok(message) => return Ok(message),
                            Err(error) => last_error = error,
                        }
                    } else {
                        return Ok(message);
                    }
                }
                Err(error) => last_error = error,
            }
        }
        Err(LookupFailure::Unknown(last_error))
    }

    fn exchange_udp(
        &self,
        nameserver: &SocketAddr,
        query: &Message,
        encoded: &[u8],
    ) -> Result<Message, String> {
        let bind = if nameserver.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).map_err(|exc| exc.to_string())?;
        socket
            .set_write_timeout(Some(self.timeout))
            .map_err(|exc| exc.to_string())?;
        socket.connect(nameserver).map_err(|exc| exc.to_string())?;
        socket.send(encoded).map_err(|exc| exc.to_string())?;

        // A connected UDP socket filters the source address, but an attacker on
        // the path can still inject a packet. Ignore every reply that does not
        // echo this exact query until the read deadline expires.
        let deadline = Instant::now() + self.timeout;
        let mut buffer = [0u8; 4096];
        let mut rejected = 0usize;
        loop {
            if rejected > 64 {
                return Err("DNS response validation failed: too many mismatched replies".into());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err("DNS response validation failed: no matching UDP reply".into());
            }
            socket
                .set_read_timeout(Some(deadline - now))
                .map_err(|exc| exc.to_string())?;
            let size = match socket.recv(&mut buffer) {
                Ok(size) => size,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err("DNS response validation failed: no matching UDP reply".into())
                }
                Err(error) => return Err(error.to_string()),
            };
            let response = match Message::from_bytes(&buffer[..size]) {
                Ok(response) => response,
                Err(_) => continue,
            };
            if validate_response(query, &response).is_ok() {
                return Ok(response);
            }
            rejected += 1;
        }
    }

    fn exchange_tcp(
        &self,
        nameserver: &SocketAddr,
        query: &Message,
        encoded: &[u8],
    ) -> Result<Message, String> {
        let mut stream =
            TcpStream::connect_timeout(nameserver, self.timeout).map_err(|exc| exc.to_string())?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|exc| exc.to_string())?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|exc| exc.to_string())?;
        let length = (encoded.len() as u16).to_be_bytes();
        stream.write_all(&length).map_err(|exc| exc.to_string())?;
        stream.write_all(encoded).map_err(|exc| exc.to_string())?;
        let mut header = [0u8; 2];
        stream
            .read_exact(&mut header)
            .map_err(|exc| exc.to_string())?;
        let size = u16::from_be_bytes(header) as usize;
        if size < 12 {
            return Err("DNS response validation failed: short TCP reply".into());
        }
        let mut body = vec![0u8; size];
        stream
            .read_exact(&mut body)
            .map_err(|exc| exc.to_string())?;
        let response = Message::from_bytes(&body).map_err(|exc| exc.to_string())?;
        validate_response(query, &response)?;
        Ok(response)
    }
}

/// Reject a datagram or stream record unless it is the response to this exact
/// query: same ID, QR=response, same opcode, and the same single question.
///
/// This runs before the caller reads the answer section or the AD bit, so an
/// off-path packet cannot contribute records or a forged DNSSEC verdict.
pub fn validate_response(query: &Message, response: &Message) -> Result<(), String> {
    if response.metadata.id != query.metadata.id {
        return Err("DNS response validation failed: transaction ID mismatch".into());
    }
    if response.metadata.message_type != MessageType::Response {
        return Err("DNS response validation failed: message is not a response".into());
    }
    if response.metadata.op_code != query.metadata.op_code {
        return Err("DNS response validation failed: opcode mismatch".into());
    }
    if query.queries.len() != 1 || response.queries.len() != 1 {
        return Err("DNS response validation failed: question count mismatch".into());
    }
    let expected = &query.queries[0];
    let actual = &response.queries[0];
    if expected.name() != actual.name()
        || expected.query_type() != actual.query_type()
        || expected.query_class() != actual.query_class()
    {
        return Err("DNS response validation failed: question mismatch".into());
    }
    Ok(())
}

impl Resolver for SystemResolver {
    fn lookup(&self, name: &str, record_type: RecordType) -> Result<LookupAnswer, LookupFailure> {
        static NEXT_ID: AtomicU16 = AtomicU16::new(1);

        let fqdn = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        };
        let domain = Name::from_ascii(&fqdn)
            .map_err(|exc| LookupFailure::Unknown(format!("invalid DNS name: {exc}")))?;

        let mut message = Message::new(
            NEXT_ID.fetch_add(1, Ordering::Relaxed),
            MessageType::Query,
            OpCode::Query,
        );
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(domain, record_type));
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        message.edns = Some(edns);

        let response = self.exchange(&message)?;
        match response.metadata.response_code {
            ResponseCode::NoError => {}
            ResponseCode::NXDomain => return Err(LookupFailure::Absent(Some("NXDOMAIN".into()))),
            other => {
                return Err(LookupFailure::Unknown(format!("DNS response {other:?}")));
            }
        }

        let mut records = Vec::new();
        let mut rrsig_count = 0;
        for record in &response.answers {
            if record.record_type() == RecordType::RRSIG {
                rrsig_count += 1;
            }
            if record.record_type() != record_type {
                continue;
            }
            match &record.data {
                RData::NS(ns) => records.push(RecordData::Ns(ns.to_string())),
                RData::CAA(caa) => records.push(RecordData::Caa {
                    flags: caa.flags(),
                    tag: caa.tag.clone(),
                    value: String::from_utf8_lossy(&caa.value).to_string(),
                }),
                RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::DNSKEY(key)) => {
                    records.push(RecordData::Dnskey(key.to_string()))
                }
                _ => {}
            }
        }

        if records.is_empty() {
            return Err(LookupFailure::Absent(None));
        }
        Ok(LookupAnswer {
            ad: response.metadata.authentic_data,
            records,
            rrsig_count,
        })
    }
}

fn system_nameservers() -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    if let Ok(text) = fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                let token = rest.split_whitespace().next().unwrap_or("");
                if let Ok(ip) = token.parse::<IpAddr>() {
                    servers.push(SocketAddr::new(ip, 53));
                }
            }
        }
    }
    if servers.is_empty() {
        // A resolver-less container still gets a bounded, explicit attempt.
        servers.push(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            53,
        ));
    }
    servers
}
