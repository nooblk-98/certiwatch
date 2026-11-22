//! Monitoring lifecycle: public history, private alert state and the opt-in
//! Discord delivery path.
//!
//! `history.json` is public and has a fixed shape. The alert state is private:
//! last observations, threshold bands, fingerprints and undelivered events.
//! Delivery is at-least-once and persists the pending batch before the first
//! send, exactly like the legacy CLI.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, NaiveDate, NaiveDateTime, SecondsFormat, Utc};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::config::{band_for_days, Config, ConfigError};
use crate::results::{read_json, write_json_atomic};

pub const HISTORY_FILE: &str = "history.json";
pub const ALERT_STATE_FILE: &str = "alert_state.json";
pub const DISCORD_ENV: &str = "CERTIWATCH_DISCORD_WEBHOOK";
pub const STATE_VERSION: i64 = 1;
pub const MAX_DISCORD_CONTENT: usize = 2000;
pub const DISCORD_HEADER: &str = "**CertiWatch alert**";

#[derive(Debug, Clone)]
pub struct MonitoringError(pub String);

impl std::fmt::Display for MonitoringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MonitoringError {}

impl From<ConfigError> for MonitoringError {
    fn from(value: ConfigError) -> Self {
        MonitoringError(value.0)
    }
}

#[derive(Debug, Clone)]
pub struct MonitoringPlan {
    pub snapshot: Value,
    pub history: Value,
    pub alert_state: Value,
    pub events: Vec<Value>,
}

fn event_order(event_type: &str) -> u8 {
    match event_type {
        "status" => 0,
        "threshold" => 1,
        "fingerprint" => 2,
        "nameservers" => 3,
        _ => 9,
    }
}

fn utc_now() -> DateTime<Utc> {
    Utc::now()
}

/// Read the UTC date from a checker's `generated_at` value.
pub fn parse_generated_date(value: &Value) -> Option<String> {
    let text = value.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(parsed) = NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M UTC") {
        return Some(parsed.date().format("%Y-%m-%d").to_string());
    }
    if let Ok(parsed) = DateTime::parse_from_rfc3339(text) {
        return Some(
            parsed
                .with_timezone(&Utc)
                .date_naive()
                .format("%Y-%m-%d")
                .to_string(),
        );
    }
    if let Ok(date) = NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        return Some(date.format("%Y-%m-%d").to_string());
    }
    if let Ok(parsed) = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S") {
        return Some(parsed.date().format("%Y-%m-%d").to_string());
    }
    None
}

/// Choose the one UTC snapshot date, preferring an explicit override.
pub fn snapshot_date_for(
    ssl_output: &Value,
    domain_output: &Value,
    override_date: Option<&str>,
) -> Result<String, MonitoringError> {
    if let Some(value) = override_date {
        return NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .map(|date| date.format("%Y-%m-%d").to_string())
            .map_err(|_| MonitoringError(format!("--date must be YYYY-MM-DD: {value:?}")));
    }
    for output in [ssl_output, domain_output] {
        if let Some(date) = parse_generated_date(output.get("generated_at").unwrap_or(&Value::Null))
        {
            return Ok(date);
        }
    }
    Ok(utc_now().date_naive().format("%Y-%m-%d").to_string())
}

fn normalise_fingerprint(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?.trim().replace(' ', "").to_uppercase();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn last_known_fingerprints(
    previous_history: Option<&Value>,
    previous_alert_state: Option<&Value>,
) -> BTreeMap<String, String> {
    let mut known = BTreeMap::new();
    if let Some(history) = previous_history {
        if let Some(snapshots) = history.get("snapshots").and_then(Value::as_array) {
            for snapshot in snapshots.iter().rev() {
                let Some(rows) = snapshot.get("ssl").and_then(Value::as_array) else {
                    continue;
                };
                for row in rows {
                    let Some(domain) = row.get("domain").and_then(Value::as_str) else {
                        continue;
                    };
                    let Some(fingerprint) = normalise_fingerprint(row.get("fingerprint_sha256"))
                    else {
                        continue;
                    };
                    known.entry(format!("ssl:{domain}")).or_insert(fingerprint);
                }
            }
        }
    }
    if let Some(state) = previous_alert_state {
        if let Some(observations) = state.get("observations").and_then(Value::as_object) {
            for (key, observation) in observations {
                if let Some(fingerprint) =
                    normalise_fingerprint(observation.get("fingerprint_sha256"))
                {
                    known.insert(key.clone(), fingerprint);
                }
            }
        }
    }
    known
}

fn result_rows<'a>(output: &'a Value, label: &str) -> Result<&'a Vec<Value>, MonitoringError> {
    if !output.is_object() {
        return Err(MonitoringError(format!("{label}: expected a JSON object")));
    }
    let rows = output
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| MonitoringError(format!("{label}: missing 'results' list")))?;
    for (index, row) in rows.iter().enumerate() {
        if !row.is_object() {
            return Err(MonitoringError(format!(
                "{label}: results[{index}] is not an object"
            )));
        }
    }
    Ok(rows)
}

fn optional_int(value: Option<&Value>, label: &str) -> Result<Option<i64>, MonitoringError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_i64()
        .map(Some)
        .ok_or_else(|| MonitoringError(format!("{label}: days_left must be an integer or null")))
}

fn status_value(value: Option<&Value>, label: &str) -> Result<String, MonitoringError> {
    value
        .and_then(Value::as_str)
        .filter(|status| !status.is_empty())
        .map(str::to_string)
        .ok_or_else(|| MonitoringError(format!("{label}: status must be a non-empty string")))
}

/// Build one public snapshot with the exact history contract.
pub fn build_snapshot(
    ssl_output: &Value,
    domain_output: &Value,
    previous_history: Option<&Value>,
    previous_alert_state: Option<&Value>,
    snapshot_date: Option<&str>,
) -> Result<Value, MonitoringError> {
    let date = snapshot_date_for(ssl_output, domain_output, snapshot_date)?;
    let known = last_known_fingerprints(previous_history, previous_alert_state);

    let mut ssl_rows = Vec::new();
    for row in result_rows(ssl_output, "ssl_results.json")? {
        let domain = row
            .get("domain")
            .and_then(Value::as_str)
            .filter(|domain| !domain.is_empty())
            .ok_or_else(|| {
                MonitoringError("ssl_results.json contains a row without a domain".into())
            })?;
        let fingerprint = normalise_fingerprint(row.get("fingerprint_sha256"))
            .or_else(|| known.get(&format!("ssl:{domain}")).cloned());
        let mut map = Map::new();
        map.insert("domain".into(), json!(domain));
        map.insert(
            "days_left".into(),
            json!(optional_int(row.get("days_left"), "ssl_results.json")?),
        );
        map.insert(
            "status".into(),
            json!(status_value(row.get("status"), "ssl_results.json")?),
        );
        map.insert("fingerprint_sha256".into(), json!(fingerprint));
        ssl_rows.push(Value::Object(map));
    }

    let mut domain_rows = Vec::new();
    for row in result_rows(domain_output, "domain_results.json")? {
        let domain = row
            .get("domain")
            .and_then(Value::as_str)
            .filter(|domain| !domain.is_empty())
            .ok_or_else(|| {
                MonitoringError("domain_results.json contains a row without a domain".into())
            })?;
        let mut map = Map::new();
        map.insert("domain".into(), json!(domain));
        map.insert(
            "days_left".into(),
            json!(optional_int(row.get("days_left"), "domain_results.json")?),
        );
        map.insert(
            "status".into(),
            json!(status_value(row.get("status"), "domain_results.json")?),
        );
        domain_rows.push(Value::Object(map));
    }

    ssl_rows.sort_by(|left, right| {
        left["domain"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["domain"].as_str().unwrap_or_default())
    });
    domain_rows.sort_by(|left, right| {
        left["domain"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["domain"].as_str().unwrap_or_default())
    });

    let mut snapshot = Map::new();
    snapshot.insert("date".into(), json!(date));
    snapshot.insert("ssl".into(), Value::Array(ssl_rows));
    snapshot.insert("domains".into(), Value::Array(domain_rows));
    Ok(Value::Object(snapshot))
}

fn normalise_history(previous: Option<&Value>) -> Result<Value, MonitoringError> {
    let Some(previous) = previous else {
        let mut map = Map::new();
        map.insert("snapshots".into(), json!([]));
        return Ok(Value::Object(map));
    };
    let snapshots = previous
        .get("snapshots")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            MonitoringError("previous history must be an object with a snapshots list".into())
        })?;
    let mut normalised = Vec::new();
    for (index, snapshot) in snapshots.iter().enumerate() {
        if !snapshot.is_object() {
            return Err(MonitoringError(format!(
                "previous history snapshots[{index}] is not an object"
            )));
        }
        let date = snapshot
            .get("date")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                MonitoringError(format!(
                    "previous history snapshots[{index}].date is missing"
                ))
            })?;
        let date = NaiveDate::parse_from_str(date, "%Y-%m-%d")
            .map_err(|_| {
                MonitoringError(format!(
                    "previous history snapshots[{index}].date is not YYYY-MM-DD"
                ))
            })?
            .format("%Y-%m-%d")
            .to_string();
        let ssl = snapshot
            .get("ssl")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                MonitoringError(format!(
                    "previous history snapshots[{index}] must contain ssl and domains lists"
                ))
            })?;
        let domains = snapshot
            .get("domains")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                MonitoringError(format!(
                    "previous history snapshots[{index}] must contain ssl and domains lists"
                ))
            })?;
        let mut ssl_rows = Vec::new();
        for (row_index, row) in ssl.iter().enumerate() {
            let where_ = format!("previous history snapshots[{index}].ssl[{row_index}]");
            if !row.is_object() {
                return Err(MonitoringError(format!("{where_} is not an object")));
            }
            let domain = row
                .get("domain")
                .and_then(Value::as_str)
                .filter(|domain| !domain.is_empty())
                .ok_or_else(|| MonitoringError(format!("{where_}.domain is missing")))?;
            let status = status_value(row.get("status"), &where_)?;
            let mut map = Map::new();
            map.insert("domain".into(), json!(domain));
            map.insert(
                "days_left".into(),
                json!(optional_int(row.get("days_left"), &where_)?),
            );
            map.insert("status".into(), json!(status));
            map.insert(
                "fingerprint_sha256".into(),
                json!(normalise_fingerprint(row.get("fingerprint_sha256"))),
            );
            ssl_rows.push(Value::Object(map));
        }
        let mut domain_rows = Vec::new();
        for (row_index, row) in domains.iter().enumerate() {
            let where_ = format!("previous history snapshots[{index}].domains[{row_index}]");
            if !row.is_object() {
                return Err(MonitoringError(format!("{where_} is not an object")));
            }
            let domain = row
                .get("domain")
                .and_then(Value::as_str)
                .filter(|domain| !domain.is_empty())
                .ok_or_else(|| MonitoringError(format!("{where_}.domain is missing")))?;
            let status = status_value(row.get("status"), &where_)?;
            let mut map = Map::new();
            map.insert("domain".into(), json!(domain));
            map.insert(
                "days_left".into(),
                json!(optional_int(row.get("days_left"), &where_)?),
            );
            map.insert("status".into(), json!(status));
            domain_rows.push(Value::Object(map));
        }
        let mut entry = Map::new();
        entry.insert("date".into(), json!(date));
        entry.insert("ssl".into(), Value::Array(ssl_rows));
        entry.insert("domains".into(), Value::Array(domain_rows));
        normalised.push(Value::Object(entry));
    }
    normalised.sort_by(|left, right| {
        left["date"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["date"].as_str().unwrap_or_default())
    });
    let mut map = Map::new();
    map.insert("snapshots".into(), Value::Array(normalised));
    Ok(Value::Object(map))
}

/// Upsert by UTC date, sort ascending, and keep the newest `limit`.
pub fn merge_history(
    previous_history: Option<&Value>,
    snapshot: &Value,
    limit: u32,
) -> Result<Value, MonitoringError> {
    if limit < 1 {
        return Err(MonitoringError(
            "history_limit must be a positive integer".into(),
        ));
    }
    let previous = normalise_history(previous_history)?;
    let mut by_date: BTreeMap<String, Value> = BTreeMap::new();
    if let Some(snapshots) = previous.get("snapshots").and_then(Value::as_array) {
        for entry in snapshots {
            by_date.insert(
                entry["date"].as_str().unwrap_or_default().to_string(),
                entry.clone(),
            );
        }
    }
    let date = snapshot["date"].as_str().unwrap_or_default().to_string();
    by_date.insert(date, snapshot.clone());
    let kept: Vec<Value> = by_date
        .into_values()
        .rev()
        .take(limit as usize)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let mut map = Map::new();
    map.insert("snapshots".into(), Value::Array(kept));
    Ok(Value::Object(map))
}

// ── Observations and events ──────────────────────────────────────────────────

pub fn default_alert_state() -> Value {
    let mut map = Map::new();
    map.insert("version".into(), json!(STATE_VERSION));
    map.insert("observations".into(), json!({}));
    map.insert("pending_events".into(), json!([]));
    Value::Object(map)
}

fn normalise_alert_state(previous: Option<&Value>) -> Result<Value, MonitoringError> {
    let Some(previous) = previous else {
        return Ok(default_alert_state());
    };
    if !previous.is_object() {
        return Err(MonitoringError(
            "previous alert state must be a JSON object".into(),
        ));
    }
    let observations = previous
        .get("observations")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !observations.is_object() {
        return Err(MonitoringError(
            "previous alert state observations must be an object".into(),
        ));
    }
    let pending = previous
        .get("pending_events")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let Some(pending) = pending.as_array() else {
        return Err(MonitoringError(
            "previous alert state pending_events must be a list".into(),
        ));
    };
    for event in pending {
        if !event.is_object() || !event.get("id").map(Value::is_string).unwrap_or(false) {
            return Err(MonitoringError(
                "previous alert state contains an invalid pending event".into(),
            ));
        }
    }
    let mut map = Map::new();
    map.insert("version".into(), json!(STATE_VERSION));
    map.insert("observations".into(), observations);
    map.insert("pending_events".into(), Value::Array(pending.clone()));
    Ok(Value::Object(map))
}

fn dns_observations(
    ssl_output: &Value,
    domain_output: &Value,
    previous: &Map<String, Value>,
) -> Result<Map<String, Value>, MonitoringError> {
    let mut observations = Map::new();
    for (output, label) in [
        (ssl_output, "ssl_results.json"),
        (domain_output, "domain_results.json"),
    ] {
        for row in result_rows(output, label)? {
            let Some(dns) = row.get("dns").and_then(Value::as_object) else {
                continue;
            };
            let Some(name) = dns
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
            else {
                continue;
            };
            let ns = dns.get("ns").and_then(Value::as_object);
            let mut status = ns
                .and_then(|ns| ns.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            if status != "present" && status != "absent" {
                status = "unknown".into();
            }
            let raw_records = ns
                .and_then(|ns| ns.get("records"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut current: Vec<String> = raw_records
                .iter()
                .filter_map(Value::as_str)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect();
            current.sort();
            current.dedup();

            let key = format!("dns:{name}");
            let previous_observation = previous.get(&key).and_then(Value::as_object);
            let previous_nameservers: Vec<String> = previous_observation
                .and_then(|observation| observation.get("nameservers"))
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let lookup_status = status.clone();
            let nameservers = if status == "present" {
                current
            } else if status == "absent" {
                Vec::new()
            } else {
                if let Some(previous_status) = previous_observation
                    .and_then(|observation| observation.get("status"))
                    .and_then(Value::as_str)
                {
                    if previous_status == "present" || previous_status == "absent" {
                        status = previous_status.to_string();
                    }
                }
                previous_nameservers
            };

            let mut observation = Map::new();
            observation.insert("kind".into(), json!("dns"));
            observation.insert("domain".into(), json!(name));
            observation.insert("status".into(), json!(status));
            observation.insert("lookup_status".into(), json!(lookup_status));
            observation.insert("nameservers".into(), json!(nameservers));

            let priority = |value: &str| match value {
                "present" => 2,
                "absent" => 1,
                _ => 0,
            };
            let should_replace = observations
                .get(&key)
                .and_then(Value::as_object)
                .and_then(|existing| existing.get("status"))
                .and_then(Value::as_str)
                .map(|existing| priority(&status) > priority(existing))
                .unwrap_or(true);
            if should_replace {
                observations.insert(key, Value::Object(observation));
            }
        }
    }
    Ok(observations)
}

fn observations_from_snapshot(
    snapshot: &Value,
    thresholds: &[i64; 4],
    ssl_output: &Value,
    domain_output: &Value,
    previous_observations: &Map<String, Value>,
) -> Result<Map<String, Value>, MonitoringError> {
    let mut observations = Map::new();
    for row in snapshot["ssl"].as_array().into_iter().flatten() {
        let domain = row["domain"].as_str().unwrap_or_default();
        let days_left = row.get("days_left").and_then(Value::as_i64);
        let mut observation = Map::new();
        observation.insert("kind".into(), json!("ssl"));
        observation.insert("domain".into(), json!(domain));
        observation.insert("status".into(), row["status"].clone());
        observation.insert("days_left".into(), json!(days_left));
        observation.insert("band".into(), json!(band_for_days(days_left, thresholds)));
        observation.insert(
            "fingerprint_sha256".into(),
            row.get("fingerprint_sha256")
                .cloned()
                .unwrap_or(Value::Null),
        );
        observations.insert(format!("ssl:{domain}"), Value::Object(observation));
    }
    for row in snapshot["domains"].as_array().into_iter().flatten() {
        let domain = row["domain"].as_str().unwrap_or_default();
        let days_left = row.get("days_left").and_then(Value::as_i64);
        let mut observation = Map::new();
        observation.insert("kind".into(), json!("domain"));
        observation.insert("domain".into(), json!(domain));
        observation.insert("status".into(), row["status"].clone());
        observation.insert("days_left".into(), json!(days_left));
        observation.insert("band".into(), json!(band_for_days(days_left, thresholds)));
        observations.insert(format!("domain:{domain}"), Value::Object(observation));
    }
    for (key, value) in dns_observations(ssl_output, domain_output, previous_observations)? {
        observations.insert(key, value);
    }
    Ok(observations)
}

#[allow(clippy::too_many_arguments)]
fn make_event(
    key: &str,
    kind: &str,
    domain: &str,
    event_type: &str,
    before: Value,
    after: Value,
    days_left: Option<i64>,
    date: &str,
) -> Value {
    let identity = format!(
        "{key}|{event_type}|{}|{}|{date}",
        compact_value(&before),
        compact_value(&after)
    );
    let mut hasher = Sha256::new();
    hasher.update(identity.as_bytes());
    let digest = hasher.finalize();
    let id: String = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut map = Map::new();
    map.insert("id".into(), json!(id));
    map.insert("key".into(), json!(key));
    map.insert("kind".into(), json!(kind));
    map.insert("domain".into(), json!(domain));
    map.insert("type".into(), json!(event_type));
    map.insert("from".into(), before);
    map.insert("to".into(), after);
    map.insert("days_left".into(), json!(days_left));
    map.insert("date".into(), json!(date));
    Value::Object(map)
}

fn compact_value(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(|value| format!("'{}'", compact_value(value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Object(_) => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn compare_observations(
    previous: &Map<String, Value>,
    current: &Map<String, Value>,
    date: &str,
) -> Vec<Value> {
    let mut events = Vec::new();
    let mut keys: Vec<&String> = current.keys().collect();
    keys.sort();
    for key in keys {
        let observation = &current[key];
        let Some(before) = previous.get(key).and_then(Value::as_object) else {
            continue; // first observation is the baseline
        };
        if observation.get("kind").and_then(Value::as_str) == Some("dns") {
            let before_status = before.get("status").and_then(Value::as_str).unwrap_or("");
            let after_status = observation
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("");
            let before_nameservers = before.get("nameservers").and_then(Value::as_array);
            let after_nameservers = observation.get("nameservers").and_then(Value::as_array);
            if ["present", "absent"].contains(&before_status)
                && ["present", "absent"].contains(&after_status)
                && before_nameservers != after_nameservers
            {
                events.push(make_event(
                    key,
                    "dns",
                    observation
                        .get("domain")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    "nameservers",
                    Value::Array(before_nameservers.cloned().unwrap_or_default()),
                    Value::Array(after_nameservers.cloned().unwrap_or_default()),
                    None,
                    date,
                ));
            }
            continue;
        }

        let before_status = before.get("status").cloned().unwrap_or(Value::Null);
        let after_status = observation.get("status").cloned().unwrap_or(Value::Null);
        let status_changed = before_status != after_status;
        let days_left = observation.get("days_left").and_then(Value::as_i64);
        if status_changed {
            events.push(make_event(
                key,
                observation
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                observation
                    .get("domain")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                "status",
                before_status,
                after_status,
                days_left,
                date,
            ));
        }
        let before_band = before.get("band").and_then(Value::as_str);
        let after_band = observation.get("band").and_then(Value::as_str);
        if !status_changed
            && !matches!(before_band, None | Some("unknown"))
            && !matches!(after_band, None | Some("unknown"))
            && before_band != after_band
        {
            events.push(make_event(
                key,
                observation
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                observation
                    .get("domain")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                "threshold",
                json!(before_band),
                json!(after_band),
                days_left,
                date,
            ));
        }
        if observation.get("kind").and_then(Value::as_str) == Some("ssl") {
            let before_fingerprint = normalise_fingerprint(before.get("fingerprint_sha256"));
            let after_fingerprint = normalise_fingerprint(observation.get("fingerprint_sha256"));
            if let (Some(before_fingerprint), Some(after_fingerprint)) =
                (before_fingerprint, after_fingerprint)
            {
                if before_fingerprint != after_fingerprint {
                    events.push(make_event(
                        key,
                        "ssl",
                        observation
                            .get("domain")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                        "fingerprint",
                        json!(before_fingerprint),
                        json!(after_fingerprint),
                        days_left,
                        date,
                    ));
                }
            }
        }
    }
    events.sort_by(|left, right| {
        let left_key = left["key"].as_str().unwrap_or_default();
        let right_key = right["key"].as_str().unwrap_or_default();
        left_key.cmp(right_key).then_with(|| {
            event_order(left["type"].as_str().unwrap_or_default())
                .cmp(&event_order(right["type"].as_str().unwrap_or_default()))
        })
    });
    events
}

fn merge_events(pending: &[Value], new_events: &[Value]) -> Vec<Value> {
    let mut merged: BTreeMap<String, Value> = BTreeMap::new();
    for event in pending.iter().chain(new_events.iter()) {
        let id = event["id"].as_str().unwrap_or_default().to_string();
        merged.entry(id).or_insert_with(|| event.clone());
    }
    let mut events: Vec<Value> = merged.into_values().collect();
    events.sort_by(|left, right| {
        left["date"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["date"].as_str().unwrap_or_default())
            .then_with(|| {
                left["key"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(right["key"].as_str().unwrap_or_default())
            })
            .then_with(|| {
                event_order(left["type"].as_str().unwrap_or_default())
                    .cmp(&event_order(right["type"].as_str().unwrap_or_default()))
            })
    });
    events
}

/// Combine both result files with previous state. Pure: no network or files.
pub fn prepare_monitoring(
    config: &Config,
    ssl_output: &Value,
    domain_output: &Value,
    previous_history: Option<&Value>,
    previous_alert_state: Option<&Value>,
    snapshot_date: Option<&str>,
) -> Result<MonitoringPlan, MonitoringError> {
    if result_rows(ssl_output, "ssl_results.json")?.is_empty()
        && result_rows(domain_output, "domain_results.json")?.is_empty()
    {
        return Err(MonitoringError(
            "both result files are empty; refusing to write a blank snapshot".into(),
        ));
    }

    let history_before = normalise_history(previous_history)?;
    let state_before = normalise_alert_state(previous_alert_state)?;
    let previous_observations = state_before
        .get("observations")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let snapshot = build_snapshot(
        ssl_output,
        domain_output,
        Some(&history_before),
        Some(&state_before),
        snapshot_date,
    )?;
    let history = merge_history(Some(&history_before), &snapshot, config.history_limit)?;
    let date = snapshot["date"].as_str().unwrap_or_default().to_string();
    let current = observations_from_snapshot(
        &snapshot,
        &config.thresholds,
        ssl_output,
        domain_output,
        &previous_observations,
    )?;
    let new_events = compare_observations(&previous_observations, &current, &date);
    let pending = state_before
        .get("pending_events")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let events = merge_events(&pending, &new_events);

    let mut alert_state = Map::new();
    alert_state.insert("version".into(), json!(STATE_VERSION));
    alert_state.insert(
        "updated_at".into(),
        json!(utc_now().to_rfc3339_opts(SecondsFormat::Secs, true)),
    );
    alert_state.insert("observations".into(), Value::Object(current));
    alert_state.insert("pending_events".into(), json!([]));

    Ok(MonitoringPlan {
        snapshot,
        history,
        alert_state: Value::Object(alert_state),
        events,
    })
}

/// Advance observations and either retain pending events for delivery/retry or
/// clear them when no delivery path exists.
pub fn finalize_alert_state_pending(
    alert_state: &Value,
    events: &[Value],
    retain_pending: bool,
) -> Value {
    let mut map = Map::new();
    map.insert("version".into(), json!(STATE_VERSION));
    map.insert(
        "updated_at".into(),
        alert_state
            .get("updated_at")
            .cloned()
            .unwrap_or_else(|| json!(utc_now().to_rfc3339_opts(SecondsFormat::Secs, true))),
    );
    map.insert(
        "observations".into(),
        alert_state
            .get("observations")
            .cloned()
            .unwrap_or_else(|| json!({})),
    );
    map.insert(
        "pending_events".into(),
        if retain_pending {
            Value::Array(events.to_vec())
        } else {
            json!([])
        },
    );
    Value::Object(map)
}

/// Clear delivered events, or retain them for the next run.
pub fn finalize_alert_state(alert_state: &Value, events: &[Value], delivered: bool) -> Value {
    finalize_alert_state_pending(alert_state, events, !delivered)
}

// ── TLS coverage gate ────────────────────────────────────────────────────────

pub fn validate_ssl_coverage(results: &[Value]) -> Result<(), MonitoringError> {
    let observed = results.iter().filter(|row| {
        matches!(
            row.get("status").and_then(Value::as_str),
            Some("valid") | Some("expired") | Some("invalid")
        )
    });
    if observed.count() > 0 {
        return Ok(());
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in results {
        let status = row
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("<missing>")
            .to_string();
        *counts.entry(status).or_insert(0) += 1;
    }
    let summary = counts
        .into_iter()
        .map(|(status, count)| format!("{status}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    Err(MonitoringError(format!(
        "ssl_results.json: all {} rows are connection/DNS failures ({summary}); no certificate was read, so this run must not replace the published results",
        results.len()
    )))
}

// ── Discord ──────────────────────────────────────────────────────────────────

const MAX_NAMESERVER_ITEMS: usize = 8;
const MAX_NAMESERVER_ITEM_CHARS: usize = 80;
const MAX_NAMESERVER_TEXT: usize = 700;

fn short_fingerprint(value: Option<&Value>) -> String {
    let text = match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    };
    if text.chars().count() > 23 {
        let prefix: String = text.chars().take(23).collect();
        format!("{prefix}…")
    } else {
        text
    }
}

fn bounded_nameservers(value: Option<&Value>) -> String {
    let items: Vec<String> = value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .map(|value| value.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default();
    if items.is_empty() {
        return "none".into();
    }
    let shown: Vec<String> = items
        .iter()
        .take(MAX_NAMESERVER_ITEMS)
        .map(|item| item.chars().take(MAX_NAMESERVER_ITEM_CHARS).collect())
        .collect();
    let omitted = items.len() - shown.len();
    let mut text = shown.join(", ");
    if omitted > 0 {
        text.push_str(&format!(" … (+{omitted} more)"));
    }
    if text.chars().count() > MAX_NAMESERVER_TEXT {
        let mut truncated: String = text.chars().take(MAX_NAMESERVER_TEXT - 1).collect();
        truncated.push('…');
        text = truncated;
    }
    text
}

pub fn event_line(event: &Value) -> String {
    let domain = event
        .get("domain")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .or_else(|| event.get("key").and_then(Value::as_str))
        .unwrap_or("unknown");
    let kind = event
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("target")
        .to_uppercase();
    let days = event.get("days_left").and_then(Value::as_i64);
    let days_text = match days {
        Some(days) => format!("{days} days left"),
        None => "days unknown".into(),
    };
    match event
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("status")
    {
        "fingerprint" => format!(
            "- {kind} {domain}: certificate fingerprint changed ({} -> {})",
            short_fingerprint(event.get("from")),
            short_fingerprint(event.get("to"))
        ),
        "nameservers" => format!(
            "- DNS {domain}: nameservers changed ({} -> {})",
            bounded_nameservers(event.get("from")),
            bounded_nameservers(event.get("to"))
        ),
        "threshold" => format!(
            "- {kind} {domain}: threshold {} -> {} ({days_text})",
            text_value(event.get("from")),
            text_value(event.get("to"))
        ),
        _ => format!(
            "- {kind} {domain}: status {} -> {} ({days_text})",
            text_value(event.get("from")),
            text_value(event.get("to"))
        ),
    }
}

fn text_value(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Null) | None => "None".into(),
        Some(other) => other.to_string(),
    }
}

pub fn escape_mentions(text: &str) -> String {
    text.replace('@', "@\u{200b}")
}

fn payload_for_lines(lines: &[String]) -> Result<Value, MonitoringError> {
    let content = format!("{DISCORD_HEADER}\n{}", lines.join("\n"));
    if content.chars().count() > MAX_DISCORD_CONTENT {
        return Err(MonitoringError(format!(
            "one Discord alert line is too large for {MAX_DISCORD_CONTENT} characters; refusing to truncate silently"
        )));
    }
    let mut map = Map::new();
    map.insert("content".into(), json!(content));
    map.insert("allowed_mentions".into(), json!({"parse": []}));
    Ok(Value::Object(map))
}

pub fn build_discord_payload(events: &[Value]) -> Result<Value, MonitoringError> {
    let lines: Vec<String> = events
        .iter()
        .map(|event| escape_mentions(&event_line(event)))
        .collect();
    let lines = if lines.is_empty() {
        vec!["- no changes".to_string()]
    } else {
        lines
    };
    payload_for_lines(&lines)
}

#[derive(Debug, Clone)]
pub struct DiscordBatch {
    pub events: Vec<Value>,
    pub payload: Value,
}

/// Partition events into bounded messages without dropping any event.
pub fn build_discord_batches(events: &[Value]) -> Result<Vec<DiscordBatch>, MonitoringError> {
    if events.is_empty() {
        return Ok(vec![DiscordBatch {
            events: Vec::new(),
            payload: build_discord_payload(&[])?,
        }]);
    }
    let header_length = DISCORD_HEADER.chars().count() + 1;
    let mut batches = Vec::new();
    let mut batch_events = Vec::new();
    let mut batch_lines: Vec<String> = Vec::new();
    let mut used = header_length;

    for event in events {
        let line = escape_mentions(&event_line(event));
        let addition = line.chars().count() + 1;
        if header_length + addition > MAX_DISCORD_CONTENT {
            return Err(MonitoringError(
                "one alert line exceeds the Discord message limit; refusing to truncate it".into(),
            ));
        }
        if !batch_lines.is_empty() && used + addition > MAX_DISCORD_CONTENT {
            batches.push(DiscordBatch {
                events: std::mem::take(&mut batch_events),
                payload: payload_for_lines(&batch_lines)?,
            });
            batch_lines.clear();
            used = header_length;
        }
        batch_events.push(event.clone());
        batch_lines.push(line);
        used += addition;
    }
    if !batch_lines.is_empty() {
        batches.push(DiscordBatch {
            events: batch_events,
            payload: payload_for_lines(&batch_lines)?,
        });
    }
    Ok(batches)
}

#[derive(Debug, Clone)]
pub struct TransportError {
    pub retryable: bool,
}

pub trait DiscordTransport {
    /// Return the HTTP status; transport failures return `Err`.
    fn send(&self, payload: &Value) -> Result<u16, TransportError>;
}

#[derive(Debug, Clone)]
pub struct DeliveryError {
    pub message: String,
    pub delivered: usize,
}

pub fn post_with_retry(
    transport: &dyn DiscordTransport,
    payload: &Value,
    max_attempts: u32,
    base_delay: Duration,
    max_delay: Duration,
    sleep: &dyn Fn(Duration),
) -> Result<u16, DeliveryError> {
    if max_attempts < 1 {
        return Err(DeliveryError {
            message: "max_attempts must be at least 1".into(),
            delivered: 0,
        });
    }
    let mut attempt = 0;
    while attempt < max_attempts {
        attempt += 1;
        match transport.send(payload) {
            Ok(status) if (200..300).contains(&status) => return Ok(status),
            Ok(status) => {
                let retryable = status == 429 || (500..600).contains(&status);
                if !retryable || attempt >= max_attempts {
                    return Err(DeliveryError {
                        message: format!(
                            "Discord delivery failed with HTTP {status} after {attempt} attempt(s)"
                        ),
                        delivered: 0,
                    });
                }
                let delay = base_delay.mul_f64(2f64.powi(attempt as i32 - 1));
                sleep(delay.min(max_delay));
            }
            Err(error) => {
                if !error.retryable || attempt >= max_attempts {
                    return Err(DeliveryError {
                        message: format!(
                            "Discord delivery failed after {attempt} attempt(s): transport error"
                        ),
                        delivered: 0,
                    });
                }
                let delay = base_delay.mul_f64(2f64.powi(attempt as i32 - 1));
                sleep(delay.min(max_delay));
            }
        }
    }
    Err(DeliveryError {
        message: "Discord delivery failed".into(),
        delivered: 0,
    })
}

/// Send batches in order; persist the remaining events after each ack.
pub fn deliver_batches(
    plan: &MonitoringPlan,
    batches: &[DiscordBatch],
    transport: &dyn DiscordTransport,
    max_attempts: u32,
    retry_delay: Duration,
    sleep: &dyn Fn(Duration),
    persist: &mut dyn FnMut(&Value) -> std::io::Result<()>,
) -> Result<usize, DeliveryError> {
    let mut remaining: Vec<Value> = plan.events.clone();
    let mut delivered = 0;
    for batch in batches {
        if let Err(error) = post_with_retry(
            transport,
            &batch.payload,
            max_attempts,
            retry_delay,
            Duration::from_secs(30),
            sleep,
        ) {
            return Err(DeliveryError {
                message: error.message,
                delivered,
            });
        }
        delivered += batch.events.len();
        remaining = remaining.into_iter().skip(batch.events.len()).collect();
        let state = finalize_alert_state(&plan.alert_state, &remaining, false);
        if let Err(error) = persist(&state) {
            return Err(DeliveryError {
                message: format!(
                    "alert batches were delivered up to the last acknowledged checkpoint, but state could not be advanced: {error}"
                ),
                delivered,
            });
        }
    }
    Ok(delivered)
}

/// A redacted Discord webhook transport.
pub struct DiscordWebhookTransport {
    url: String,
    agent: ureq::Agent,
}

impl std::fmt::Debug for DiscordWebhookTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DiscordWebhookTransport(<redacted>)")
    }
}

impl DiscordWebhookTransport {
    pub fn new(webhook_url: &str, timeout: Duration) -> Result<Self, MonitoringError> {
        let url = validate_webhook_url(webhook_url)?;
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .build();
        Ok(DiscordWebhookTransport {
            url,
            agent: ureq::Agent::new_with_config(config),
        })
    }

    pub fn from_env(timeout: Duration) -> Result<Self, MonitoringError> {
        let url = std::env::var(DISCORD_ENV).unwrap_or_default();
        let url = url.trim();
        if url.is_empty() {
            return Err(MonitoringError(format!(
                "{DISCORD_ENV} is not set; Discord delivery needs the webhook secret"
            )));
        }
        Self::new(url, timeout)
    }
}

impl DiscordTransport for DiscordWebhookTransport {
    fn send(&self, payload: &Value) -> Result<u16, TransportError> {
        let body = serde_json::to_vec(payload).unwrap_or_default();
        let response = self
            .agent
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "CertiWatch/1.0")
            .send(&body);
        match response {
            Ok(response) => Ok(response.status().as_u16()),
            Err(ureq::Error::Timeout(_))
            | Err(ureq::Error::Io(_))
            | Err(ureq::Error::HostNotFound) => Err(TransportError { retryable: true }),
            Err(ureq::Error::StatusCode(status)) => Ok(status),
            Err(_) => Err(TransportError { retryable: true }),
        }
    }
}

fn validate_webhook_url(value: &str) -> Result<String, MonitoringError> {
    let text = value.trim();
    let parsed = url::Url::parse(text)
        .map_err(|_| MonitoringError("the Discord webhook URL is malformed".into()))?;
    let host = parsed.host_str().unwrap_or("").to_lowercase();
    let allowed_host = host == "discord.com"
        || host.ends_with(".discord.com")
        || host == "discordapp.com"
        || host.ends_with(".discordapp.com");
    if parsed.scheme() != "https" || !allowed_host || !parsed.path().starts_with("/api/webhooks/") {
        return Err(MonitoringError(format!(
            "{DISCORD_ENV} must be an https Discord webhook URL"
        )));
    }
    Ok(text.to_string())
}

// ── State files ──────────────────────────────────────────────────────────────

pub fn load_json_if_exists(path: &Path) -> Result<Option<Value>, MonitoringError> {
    if !path.exists() {
        return Ok(None);
    }
    let value = read_json(path).map_err(MonitoringError)?;
    if !value.is_object() {
        return Err(MonitoringError(format!(
            "{}: expected a JSON object",
            path.display()
        )));
    }
    Ok(Some(value))
}

pub fn write_state(path: &Path, value: &Value) -> std::io::Result<()> {
    write_json_atomic(path, value)
}
