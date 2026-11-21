//! The running service: one bounded refresh pipeline owned by the scheduler.
//!
//! A refresh never publishes a half-finished run. Checker output is assembled
//! in memory, the TLS coverage gate runs before anything is written, and each
//! public file is replaced atomically. A failed run leaves the previous public
//! snapshot in place.

use std::collections::BTreeSet;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chrono::{SecondsFormat, Utc};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::config::{self, format_endpoint, parse_endpoint, Config, Target};
use crate::dns::{Resolver, SystemResolver};
use crate::feeds;
use crate::monitor::{self, DiscordTransport, DiscordWebhookTransport, MonitoringError};
use crate::registration::{RegistrationOptions, RegistrationService};
use crate::results::{
    base_domain_result, base_ssl_result, build_domain_output, build_ssl_output, json_bytes,
    read_json, write_atomic, write_json_atomic, ALERT_STATE_FILE, DOMAIN_OUTPUT_FILE, HISTORY_FILE,
    SSL_OUTPUT_FILE,
};
use crate::tls::{check_ssl, TlsOptions};

pub const DEFAULT_REFRESH_SECONDS: u64 = 3600;
pub const DEFAULT_RUN_TIMEOUT_SECONDS: u64 = 900;
pub const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 15;
pub const DEFAULT_MAX_CONCURRENCY: usize = 4;

#[derive(Debug, Clone)]
pub struct Settings {
    pub config_path: Option<PathBuf>,
    pub data_dir: PathBuf,
    pub refresh_interval: Duration,
    pub run_timeout: Duration,
    pub request_timeout: Duration,
    pub max_concurrency: usize,
    pub run_on_start: bool,
    pub listen: String,
    pub discord_timeout: Duration,
    pub max_delivery_attempts: u32,
}

impl Settings {
    pub fn from_env() -> Self {
        let data_dir = std::env::var("CERTIWATCH_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data"));
        Settings {
            config_path: std::env::var("CERTIWATCH_CONFIG")
                .ok()
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            data_dir,
            refresh_interval: Duration::from_secs(env_u64(
                "CERTIWATCH_REFRESH_INTERVAL",
                DEFAULT_REFRESH_SECONDS,
            )),
            run_timeout: Duration::from_secs(env_u64(
                "CERTIWATCH_RUN_TIMEOUT",
                DEFAULT_RUN_TIMEOUT_SECONDS,
            )),
            request_timeout: Duration::from_secs_f64(
                std::env::var("SSL_CHECK_TIMEOUT")
                    .ok()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECONDS as f64),
            ),
            max_concurrency: env_u64("CERTIWATCH_MAX_CONCURRENCY", DEFAULT_MAX_CONCURRENCY as u64)
                .max(1) as usize,
            run_on_start: std::env::var("CERTIWATCH_RUN_ON_START")
                .map(|value| value != "0" && !value.eq_ignore_ascii_case("false"))
                .unwrap_or(true),
            listen: std::env::var("CERTIWATCH_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            discord_timeout: Duration::from_secs(15),
            max_delivery_attempts: 3,
        }
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[derive(Debug, Clone, Default)]
pub struct RunSummary {
    pub started_at: String,
    pub finished_at: String,
    pub trigger: String,
    pub ok: bool,
    pub error: Option<String>,
    pub published: bool,
    pub ssl_rows: usize,
    pub domain_rows: usize,
    pub valid: usize,
    pub expired: usize,
    pub ssl_errors: usize,
    pub events: usize,
    pub delivered: usize,
    pub duration_ms: u128,
}

impl RunSummary {
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("started_at".into(), json!(self.started_at));
        map.insert("finished_at".into(), json!(self.finished_at));
        map.insert("trigger".into(), json!(self.trigger));
        map.insert("ok".into(), json!(self.ok));
        map.insert("error".into(), json!(self.error));
        map.insert("published".into(), json!(self.published));
        map.insert("ssl_rows".into(), json!(self.ssl_rows));
        map.insert("domain_rows".into(), json!(self.domain_rows));
        map.insert("valid".into(), json!(self.valid));
        map.insert("expired".into(), json!(self.expired));
        map.insert("ssl_errors".into(), json!(self.ssl_errors));
        map.insert("events".into(), json!(self.events));
        map.insert("delivered".into(), json!(self.delivered));
        map.insert("duration_ms".into(), json!(self.duration_ms));
        Value::Object(map)
    }
}

pub struct RuntimeState {
    pub last_run: Option<RunSummary>,
    pub last_success: Option<String>,
    pub running: bool,
    pub started_at: Instant,
    pub next_run_at: Option<String>,
}

/// One coherent view of the three dashboard inputs. `None` means the file is
/// absent; an unreadable or malformed file is represented by a non-object
/// value so the dashboard reports it as unavailable instead of showing the
/// previous run as if it were current.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub ssl: Option<Value>,
    pub domains: Option<Value>,
    pub history: Option<Value>,
}

pub struct Service {
    pub settings: Settings,
    pub resolver: Arc<dyn Resolver + Send + Sync>,
    pub registration: Arc<RegistrationService>,
    pub tls_options: TlsOptions,
    pub state: Mutex<RuntimeState>,
    running: AtomicBool,
    /// Writers take this exclusively while replacing the public bundle;
    /// readers take it shared so ssl, domain and history always come from the
    /// same published run.
    snapshot_lock: RwLock<()>,
}

impl Service {
    pub fn new(settings: Settings) -> Arc<Self> {
        let resolver = Arc::new(SystemResolver::new(Duration::from_secs(5)));
        let registration = Arc::new(RegistrationService::new(RegistrationOptions {
            timeout: Duration::from_secs(20),
            ..RegistrationOptions::default()
        }));
        Arc::new(Service {
            tls_options: TlsOptions {
                timeout: settings.request_timeout,
                ca_file: std::env::var("SSL_CA_FILE")
                    .ok()
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from),
            },
            settings,
            resolver,
            registration,
            state: Mutex::new(RuntimeState {
                last_run: None,
                last_success: None,
                running: false,
                started_at: Instant::now(),
                next_run_at: None,
            }),
            running: AtomicBool::new(false),
            snapshot_lock: RwLock::new(()),
        })
    }

    /// Read the published dashboard inputs under the snapshot lock.
    pub fn read_snapshot(&self) -> Snapshot {
        let _guard = self
            .snapshot_lock
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        Snapshot {
            ssl: read_public_json(&self.public_dir(), SSL_OUTPUT_FILE),
            domains: read_public_json(&self.public_dir(), DOMAIN_OUTPUT_FILE),
            history: read_public_json(&self.public_dir(), HISTORY_FILE),
        }
    }

    /// Read one published file under the snapshot lock. Feeds and result files
    /// are replaced together, so readers never mix runs.
    pub fn read_public_file(&self, relative: &Path) -> Option<Vec<u8>> {
        let _guard = self
            .snapshot_lock
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        fs::read(self.public_dir().join(relative)).ok()
    }

    pub fn public_dir(&self) -> PathBuf {
        self.settings.data_dir.join("public")
    }

    pub fn private_dir(&self) -> PathBuf {
        self.settings.data_dir.join("private")
    }

    pub fn ensure_directories(&self) -> std::io::Result<()> {
        fs::create_dir_all(self.public_dir())?;
        fs::create_dir_all(self.private_dir())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(self.private_dir(), fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }

    pub fn config(&self) -> Result<Config, config::ConfigError> {
        config::load_config(self.settings.config_path.as_deref())
    }

    pub fn is_ready(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.running {
            return self.public_dir().join(SSL_OUTPUT_FILE).exists();
        }
        self.public_dir().join(SSL_OUTPUT_FILE).exists() || state.last_success.is_some()
    }

    /// Claim the single refresh slot. Returns false when a run is in flight.
    pub fn try_begin(&self) -> bool {
        if self.running.swap(true, Ordering::SeqCst) {
            return false;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.running = true;
        true
    }

    pub fn finish(&self, summary: RunSummary) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.running = false;
        if summary.ok && summary.published {
            state.last_success = Some(summary.finished_at.clone());
        }
        state.last_run = Some(summary);
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn set_next_run(&self, value: Option<String>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.next_run_at = value;
    }

    /// Run one refresh. The caller must own the refresh slot.
    pub async fn run_once(&self, trigger: &str) -> RunSummary {
        let started = Instant::now();
        let started_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let mut summary = RunSummary {
            started_at: started_at.clone(),
            trigger: trigger.to_string(),
            ..RunSummary::default()
        };

        if let Err(error) = self.ensure_directories() {
            return self.fail(
                summary,
                format!("cannot create data directories: {error}"),
                started,
            );
        }

        let config = match self.config() {
            Ok(config) => config,
            Err(error) => {
                return self.fail(summary, format!("configuration error: {error}"), started)
            }
        };

        let outcome = tokio::time::timeout(
            self.settings.run_timeout,
            self.collect_and_publish(&config, &mut summary),
        )
        .await;

        match outcome {
            Err(_) => self.fail(
                summary,
                format!(
                    "run deadline of {} seconds exceeded; previous snapshot kept",
                    self.settings.run_timeout.as_secs()
                ),
                started,
            ),
            Ok(Err(error)) => self.fail(summary, error, started),
            Ok(Ok(())) => {
                summary.ok = true;
                summary.published = true;
                summary.finished_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
                summary.duration_ms = started.elapsed().as_millis();
                self.write_last_run(&summary);
                summary
            }
        }
    }

    fn fail(&self, mut summary: RunSummary, error: String, started: Instant) -> RunSummary {
        summary.ok = false;
        summary.error = Some(error);
        summary.finished_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        summary.duration_ms = started.elapsed().as_millis();
        self.write_last_run(&summary);
        summary
    }

    fn write_last_run(&self, summary: &RunSummary) {
        let path = self.private_dir().join("last_run.json");
        let _ = write_json_atomic(&path, &summary.to_json());
    }

    async fn collect_and_publish(
        &self,
        config: &Config,
        summary: &mut RunSummary,
    ) -> Result<(), String> {
        let ssl_rows = self.check_ssl_targets(config).await;
        let domain_rows = self.check_domain_targets(config).await;
        summary.ssl_rows = ssl_rows.len();
        summary.domain_rows = domain_rows.len();
        summary.valid = ssl_rows
            .iter()
            .filter(|row| row.get("status").and_then(Value::as_str) == Some("valid"))
            .count();
        summary.expired = ssl_rows
            .iter()
            .filter(|row| row.get("status").and_then(Value::as_str) == Some("expired"))
            .count();
        summary.ssl_errors = ssl_rows
            .iter()
            .filter(|row| {
                !matches!(
                    row.get("status").and_then(Value::as_str),
                    Some("valid") | Some("expired")
                )
            })
            .count();

        if !ssl_rows.is_empty() {
            monitor::validate_ssl_coverage(&ssl_rows).map_err(|error| error.0)?;
        }

        let ssl_output = build_ssl_output(config.ssl_targets().len(), ssl_rows);
        let domain_output = build_domain_output(domain_rows);

        let history_path = self.public_dir().join(HISTORY_FILE);
        let previous_history = match monitor::load_json_if_exists(&history_path) {
            Ok(value) => value,
            Err(error) => return Err(error.0),
        };
        let state_path = self.private_dir().join(ALERT_STATE_FILE);
        let previous_state = match monitor::load_json_if_exists(&state_path) {
            Ok(value) => value,
            Err(error) => return Err(error.0),
        };

        let plan = monitor::prepare_monitoring(
            config,
            &ssl_output,
            &domain_output,
            previous_history.as_ref(),
            previous_state.as_ref(),
            None,
        )
        .map_err(|error: MonitoringError| error.0)?;
        summary.events = plan.events.len();

        // Build and validate every public artifact before replacing anything,
        // so a feed error cannot leave a half-published snapshot.
        let feed_files = self.prepare_feeds(&ssl_output, &domain_output)?;
        self.publish_public(&ssl_output, &domain_output, &plan.history, feed_files)?;

        let pending = monitor::finalize_alert_state(&plan.alert_state, &plan.events, false);
        write_json_atomic(&state_path, &pending)
            .map_err(|error| format!("cannot write private alert state: {error}"))?;

        if config.alerts_discord && !plan.events.is_empty() {
            match self.deliver(&plan, &state_path).await {
                Ok(delivered) => summary.delivered = delivered,
                Err(error) => {
                    // Results are published; the pending batch stays durable.
                    summary.error = Some(error);
                }
            }
        }

        Ok(())
    }

    async fn check_ssl_targets(&self, config: &Config) -> Vec<Value> {
        let endpoints = config.ssl_endpoints();
        let semaphore = Arc::new(Semaphore::new(self.settings.max_concurrency));
        let mut set = tokio::task::JoinSet::new();
        for (endpoint, target) in endpoints {
            let target = target.clone();
            let resolver = Arc::clone(&self.resolver);
            let options = self.tls_options.clone();
            let permit = Arc::clone(&semaphore);
            let endpoint_for_error = endpoint.clone();
            set.spawn(async move {
                let _permit = permit.acquire_owned().await;
                match tokio::task::spawn_blocking(move || {
                    check_one_ssl(&endpoint, &target, &options, resolver.as_ref())
                })
                .await
                {
                    Ok(row) => row,
                    Err(error) => {
                        error_ssl_row(&endpoint_for_error, &format!("Unexpected error: {error}"))
                    }
                }
            });
        }
        let mut rows = Vec::new();
        while let Some(result) = set.join_next().await {
            match result {
                Ok(row) => rows.push(row),
                Err(join_error) => rows.push(error_ssl_row(
                    "",
                    &format!("Unexpected error: {join_error}"),
                )),
            }
        }
        rows
    }

    async fn check_domain_targets(&self, config: &Config) -> Vec<Value> {
        let rows = config.registration_rows();
        let semaphore = Arc::new(Semaphore::new(self.settings.max_concurrency));
        let mut set = tokio::task::JoinSet::new();
        for (domain, target) in rows {
            let target = target.clone();
            let resolver = Arc::clone(&self.resolver);
            let registration = Arc::clone(&self.registration);
            let permit = Arc::clone(&semaphore);
            set.spawn(async move {
                let _permit = permit.acquire_owned().await;
                let domain_for_error = domain.clone();
                tokio::task::spawn_blocking(move || {
                    registration.check(&domain, Some(&target), resolver.as_ref())
                })
                .await
                .map_err(|error| (domain_for_error, error.to_string()))
            });
        }
        let mut rows = Vec::new();
        while let Some(result) = set.join_next().await {
            match result {
                Ok(Ok(row)) => rows.push(Value::Object(row)),
                Ok(Err((domain, error))) => {
                    let mut row = base_domain_result(&domain);
                    row.insert("status".into(), json!("unknown"));
                    row.insert("error".into(), json!(error));
                    rows.push(Value::Object(row));
                }
                Err(join_error) => {
                    let mut row = base_domain_result("");
                    row.insert("status".into(), json!("unknown"));
                    row.insert("error".into(), json!(join_error.to_string()));
                    rows.push(Value::Object(row));
                }
            }
        }
        rows
    }

    fn prepare_feeds(
        &self,
        ssl_output: &Value,
        domain_output: &Value,
    ) -> Result<Option<std::collections::BTreeMap<String, Vec<u8>>>, String> {
        // Feeds need both checks; a registration-only deployment keeps the
        // previous feeds rather than publishing an empty dashboard.
        let ssl_rows = ssl_output
            .get("results")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let domain_rows = domain_output
            .get("results")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        if ssl_rows == 0 || domain_rows == 0 {
            return Ok(None);
        }
        feeds::build_feeds(ssl_output, domain_output)
            .map(Some)
            .map_err(|error| format!("public feeds: {error}"))
    }

    fn publish_public(
        &self,
        ssl_output: &Value,
        domain_output: &Value,
        history: &Value,
        feed_files: Option<std::collections::BTreeMap<String, Vec<u8>>>,
    ) -> Result<(), String> {
        let _guard = self
            .snapshot_lock
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        let public = self.public_dir();
        write_json_atomic(&public.join(SSL_OUTPUT_FILE), ssl_output)
            .map_err(|error| format!("cannot write {SSL_OUTPUT_FILE}: {error}"))?;
        write_json_atomic(&public.join(DOMAIN_OUTPUT_FILE), domain_output)
            .map_err(|error| format!("cannot write {DOMAIN_OUTPUT_FILE}: {error}"))?;
        write_json_atomic(&public.join(HISTORY_FILE), history)
            .map_err(|error| format!("cannot write {HISTORY_FILE}: {error}"))?;

        let Some(files) = feed_files else {
            return Ok(());
        };
        let badges_dir = public.join(crate::results::BADGES_DIR);
        fs::create_dir_all(&badges_dir)
            .map_err(|error| format!("cannot create badges directory: {error}"))?;
        let mut written_badges: BTreeSet<String> = BTreeSet::new();
        for (relative, bytes) in &files {
            let target = public.join(relative);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
            }
            if relative.starts_with("badges/") && relative.ends_with(".svg") {
                written_badges.insert(relative.clone());
            }
            write_atomic(&target, bytes)
                .map_err(|error| format!("cannot write {relative}: {error}"))?;
        }
        // Stale badges are unreachable once the manifest is replaced; remove
        // them after every new file is in place.
        if let Ok(entries) = fs::read_dir(&badges_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.ends_with(".svg") {
                    continue;
                }
                let relative = format!("{}/{}", crate::results::BADGES_DIR, name);
                if !written_badges.contains(&relative) {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        Ok(())
    }

    async fn deliver(
        &self,
        plan: &monitor::MonitoringPlan,
        state_path: &Path,
    ) -> Result<usize, String> {
        let transport = DiscordWebhookTransport::from_env(self.settings.discord_timeout)
            .map_err(|error| format!("Discord delivery skipped: {}", error.0))?;
        let plan = plan.clone();
        let state_path = state_path.to_path_buf();
        let max_attempts = self.settings.max_delivery_attempts;
        tokio::task::spawn_blocking(move || {
            let batches = monitor::build_discord_batches(&plan.events).map_err(|error| error.0)?;
            let mut persist =
                |state: &Value| -> std::io::Result<()> { write_json_atomic(&state_path, state) };
            monitor::deliver_batches(
                &plan,
                &batches,
                &transport as &dyn DiscordTransport,
                max_attempts,
                Duration::from_secs(1),
                &|delay| std::thread::sleep(delay),
                &mut persist,
            )
            .map_err(|error| error.message)
        })
        .await
        .map_err(|error| error.to_string())?
    }
}

fn check_one_ssl(
    endpoint: &str,
    target: &Target,
    options: &TlsOptions,
    resolver: &dyn Resolver,
) -> Value {
    let result = catch_unwind(AssertUnwindSafe(|| {
        check_ssl(endpoint, Some(target), options, resolver)
    }));
    match result {
        Ok(row) => Value::Object(row),
        Err(payload) => {
            let message = panic_message(payload);
            error_ssl_row(endpoint, &format!("Unexpected error: {message}"))
        }
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "checker panicked".into()
    }
}

fn error_ssl_row(endpoint: &str, message: &str) -> Value {
    let (host, port) = parse_endpoint(endpoint).unwrap_or_else(|| (endpoint.to_string(), 443));
    let canonical = format_endpoint(&host, port);
    let mut row = base_ssl_result(&canonical, &host, port, Utc::now());
    row.insert("status".into(), json!("error"));
    row.insert("error".into(), json!(message));
    Value::Object(row)
}

/// Read one published JSON document. `None` means absent or unreadable; a
/// malformed document becomes a non-object value so the dashboard can show
/// its "unavailable" state without treating the previous run as current.
fn read_public_json(public: &Path, name: &str) -> Option<Value> {
    let bytes = match fs::read(public.join(name)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return Some(Value::String("unreadable".into())),
    };
    Some(serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String("invalid".into())))
}

/// Read and validate the public result files, for readiness and diagnostics.
pub fn read_public_result(public: &Path, name: &str) -> Option<Value> {
    let value = read_json(&public.join(name)).ok()?;
    value.get("results")?.as_array()?;
    Some(value)
}

/// A content digest used by tests and the status endpoint.
pub fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn summary_bytes(summary: &RunSummary) -> Vec<u8> {
    json_bytes(&summary.to_json())
}

/// Write a bundle of public files atomically, used by the CLI feed command.
pub fn write_files(
    root: &Path,
    files: &std::collections::BTreeMap<String, Vec<u8>>,
) -> std::io::Result<()> {
    for (relative, bytes) in files {
        let target = root.join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        write_atomic(&target, bytes)?;
    }
    Ok(())
}
