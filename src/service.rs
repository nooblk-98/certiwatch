//! The running service: one bounded refresh pipeline owned by the scheduler.
//!
//! A refresh never publishes a half-finished run. Checker output is assembled
//! in memory, the TLS coverage gate runs before anything is written, and each
//! public file is replaced atomically. A failed run leaves the previous public
//! snapshot in place.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
/// A per-request timeout beyond one day is not a usable configuration.
const MAX_REQUEST_TIMEOUT_SECONDS: f64 = 86_400.0;

const GENERATIONS_DIR: &str = "generations";
const COMMITS_DIR: &str = "commits";
const CURRENT_FILE: &str = "current.json";
const COMPLETE_FILE: &str = ".complete.json";
const GENERATION_SCHEMA: u64 = 1;
const KEEP_GENERATIONS: usize = 3;

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
            request_timeout: env_seconds(
                "SSL_CHECK_TIMEOUT",
                DEFAULT_REQUEST_TIMEOUT_SECONDS as f64,
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

/// Parse a positive, finite seconds value before handing it to
/// `Duration::from_secs_f64`, which panics on invalid input.
fn parse_timeout_seconds(value: &str) -> Option<Duration> {
    let seconds = value.trim().parse::<f64>().ok()?;
    if !seconds.is_finite() || seconds <= 0.0 || seconds > MAX_REQUEST_TIMEOUT_SECONDS {
        return None;
    }
    Some(Duration::from_secs_f64(seconds))
}

fn env_seconds(name: &str, default: f64) -> Duration {
    match std::env::var(name) {
        Ok(raw) => match parse_timeout_seconds(&raw) {
            Some(value) => value,
            None => {
                eprintln!("certiwatch: ignoring invalid {name}={raw:?}; using {default} seconds");
                Duration::from_secs_f64(default)
            }
        },
        Err(_) => Duration::from_secs_f64(default),
    }
}

#[derive(Debug, Clone, Default)]
pub struct RunSummary {
    pub started_at: String,
    pub finished_at: String,
    pub trigger: String,
    pub ok: bool,
    pub error: Option<String>,
    pub published: bool,
    pub publish_error: Option<String>,
    pub delivered: usize,
    pub delivery_error: Option<String>,
    pub deadline_exceeded: bool,
    pub ssl_rows: usize,
    pub domain_rows: usize,
    pub valid: usize,
    pub expired: usize,
    pub ssl_errors: usize,
    pub events: usize,
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
        map.insert("publish_error".into(), json!(self.publish_error));
        map.insert("delivery_error".into(), json!(self.delivery_error));
        map.insert("deadline_exceeded".into(), json!(self.deadline_exceeded));
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

/// One fully committed publication: a public tree and the private alert
/// checkpoint written together. A durable commit record binds this directory
/// to its completion manifest; the pointer is only a cache.
#[derive(Debug, Clone)]
struct Generation {
    id: String,
    root: PathBuf,
}

/// Durable evidence that a sealed generation was committed. The record binds
/// the generation ID to the exact completion manifest; a sealed directory
/// without one is an uncommitted orphan and is never selected.
#[derive(Debug, Clone)]
struct CommitRecord {
    generation: String,
    manifest_sha256: String,
}

impl Generation {
    fn public_dir(&self) -> PathBuf {
        self.root.join("public")
    }

    fn private_dir(&self) -> PathBuf {
        self.root.join("private")
    }

    fn alert_state_path(&self) -> PathBuf {
        self.private_dir().join(ALERT_STATE_FILE)
    }
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
    /// The committed generation. `None` before recovery or when only legacy
    /// top-level files exist.
    generation: RwLock<Option<Generation>>,
    /// Set when durable commit records exist but none can be verified. Readers
    /// then fail closed instead of serving a stale legacy tree.
    fail_closed: AtomicBool,
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
            generation: RwLock::new(None),
            fail_closed: AtomicBool::new(false),
        })
    }

    fn current_generation(&self) -> Option<Generation> {
        self.generation
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    /// The directory readers use: the committed generation, or the legacy
    /// top-level `public/` tree before migration. When commit evidence is
    /// corrupt, no directory is exposed.
    pub fn active_public_dir(&self) -> PathBuf {
        if self.fail_closed.load(Ordering::SeqCst) && self.current_generation().is_none() {
            return self.settings.data_dir.join(".unavailable");
        }
        self.current_generation()
            .map(|generation| generation.public_dir())
            .unwrap_or_else(|| self.public_dir())
    }

    fn active_alert_state_path(&self) -> PathBuf {
        if self.fail_closed.load(Ordering::SeqCst) && self.current_generation().is_none() {
            return self.settings.data_dir.join(".unavailable-alert-state");
        }
        self.current_generation()
            .map(|generation| generation.alert_state_path())
            .unwrap_or_else(|| self.private_dir().join(ALERT_STATE_FILE))
    }

    /// Read the published dashboard inputs under the snapshot lock.
    pub fn read_snapshot(&self) -> Snapshot {
        let _guard = self
            .snapshot_lock
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        let public = self.active_public_dir();
        Snapshot {
            ssl: read_public_json(&public, SSL_OUTPUT_FILE),
            domains: read_public_json(&public, DOMAIN_OUTPUT_FILE),
            history: read_public_json(&public, HISTORY_FILE),
        }
    }

    /// Read one published file under the snapshot lock. Feeds and result files
    /// are replaced together, so readers never mix runs.
    pub fn read_public_file(&self, relative: &Path) -> Option<Vec<u8>> {
        let _guard = self
            .snapshot_lock
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        fs::read(self.active_public_dir().join(relative)).ok()
    }

    pub fn public_dir(&self) -> PathBuf {
        self.settings.data_dir.join("public")
    }

    fn generations_dir(&self) -> PathBuf {
        self.settings.data_dir.join(GENERATIONS_DIR)
    }

    fn commits_dir(&self) -> PathBuf {
        self.settings.data_dir.join(COMMITS_DIR)
    }

    fn current_file(&self) -> PathBuf {
        self.settings.data_dir.join(CURRENT_FILE)
    }

    pub fn private_dir(&self) -> PathBuf {
        self.settings.data_dir.join("private")
    }

    pub fn ensure_directories(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.settings.data_dir)?;
        fs::create_dir_all(self.public_dir())?;
        fs::create_dir_all(self.private_dir())?;
        fs::create_dir_all(self.generations_dir())?;
        fs::create_dir_all(self.commits_dir())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(self.private_dir(), fs::Permissions::from_mode(0o700));
        }
        // New commits/ and generations/ entries must be durable in their
        // parent before any recovery decision relies on them.
        sync_directory(&self.commits_dir())?;
        sync_directory(&self.generations_dir())?;
        sync_directory(&self.private_dir())?;
        sync_directory(&self.public_dir())?;
        sync_directory(&self.settings.data_dir)?;
        self.recover_publication().map_err(std::io::Error::other)?;
        Ok(())
    }

    pub fn config(&self) -> Result<Config, config::ConfigError> {
        config::load_config(self.settings.config_path.as_deref())
    }

    /// Ready only when the active generation is complete and parses as one
    /// coherent publication. A run in flight never overrides the last
    /// committed generation.
    pub fn is_ready(&self) -> bool {
        self.current_generation()
            .map(|generation| self.generation_is_coherent(&generation))
            .unwrap_or(false)
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
        if summary.published && summary.publish_error.is_none() {
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
    ///
    /// The slot is not released until every blocking writer has stopped. A
    /// deadline can mark a run late, but publication and delivery jobs are
    /// still joined before this returns.
    pub async fn run_once(&self, trigger: &str) -> RunSummary {
        let started = Instant::now();
        let started_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let deadline = started + self.settings.run_timeout;
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

        let delivery_ready = if config.alerts_discord {
            match DiscordWebhookTransport::from_env(self.settings.discord_timeout) {
                Ok(_) => true,
                Err(error) => {
                    summary.delivery_error =
                        Some(format!("Discord delivery unavailable: {}", error.0));
                    false
                }
            }
        } else {
            false
        };

        let collected = match tokio::time::timeout(
            self.settings.run_timeout,
            self.collect(&config, &mut summary, delivery_ready),
        )
        .await
        {
            Err(_) => {
                summary.deadline_exceeded = true;
                return self.fail(
                    summary,
                    format!(
                        "run deadline of {} seconds exceeded during collection; previous snapshot kept",
                        self.settings.run_timeout.as_secs()
                    ),
                    started,
                );
            }
            Ok(Err(error)) => return self.fail(summary, error, started),
            Ok(Ok(collected)) => collected,
        };

        if Instant::now() >= deadline {
            summary.deadline_exceeded = true;
            return self.fail(
                summary,
                format!(
                    "run deadline of {} seconds exceeded before publication; previous snapshot kept",
                    self.settings.run_timeout.as_secs()
                ),
                started,
            );
        }

        let previous_public = self
            .current_generation()
            .map(|generation| generation.public_dir());
        let job = PublishJob {
            generations_dir: self.generations_dir(),
            commits_dir: self.commits_dir(),
            current_file: self.current_file(),
            previous_public,
            ssl_output: collected.ssl_output,
            domain_output: collected.domain_output,
            history: collected.plan.history.clone(),
            alert_state: collected.pending_alert_state,
            feed_files: collected.feed_files,
        };
        let handle = tokio::task::spawn_blocking(move || publish_generation(job));
        let remaining = deadline.saturating_duration_since(Instant::now());
        let (published, publish_late) = wait_for_writer(handle, remaining).await;
        if publish_late {
            // The blocking writer can be past the point of no return. It was
            // joined above, so the scheduler slot is still exclusive.
            summary.deadline_exceeded = true;
        }
        let generation = match published {
            Ok(Ok(generation)) => generation,
            Ok(Err(error)) => {
                summary.publish_error = Some(error);
                return self.finish_summary(summary, started);
            }
            Err(error) => {
                summary.publish_error = Some(format!("publication task failed: {error}"));
                return self.finish_summary(summary, started);
            }
        };

        {
            let _guard = self
                .snapshot_lock
                .write()
                .unwrap_or_else(|poison| poison.into_inner());
            *self
                .generation
                .write()
                .unwrap_or_else(|poison| poison.into_inner()) = Some(generation.clone());
            self.fail_closed.store(false, Ordering::SeqCst);
        }
        summary.published = true;

        if delivery_ready && !collected.plan.events.is_empty() {
            let state_path = generation.alert_state_path();
            let plan = collected.plan.clone();
            let max_attempts = self.settings.max_delivery_attempts;
            let discord_timeout = self.settings.discord_timeout;
            let delivery = tokio::task::spawn_blocking(move || {
                deliver_blocking(plan, state_path, max_attempts, discord_timeout)
            });
            let delivery_deadline = Instant::now() + self.settings.run_timeout;
            let (delivered, delivery_late) = wait_for_writer(
                delivery,
                delivery_deadline.saturating_duration_since(Instant::now()),
            )
            .await;
            if delivery_late {
                // Delivery persists its own checkpoints; it was joined above
                // so no writer survives into the next scheduled run.
                summary.deadline_exceeded = true;
            }
            match delivered {
                Ok(Ok(count)) => summary.delivered = count,
                Ok(Err(error)) => summary.delivery_error = Some(error),
                Err(error) => {
                    summary.delivery_error = Some(format!("delivery task failed: {error}"))
                }
            }
        }

        self.finish_summary(summary, started)
    }

    fn finish_summary(&self, mut summary: RunSummary, started: Instant) -> RunSummary {
        summary.ok = summary.publish_error.is_none() && summary.error.is_none();
        summary.finished_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        summary.duration_ms = started.elapsed().as_millis();
        self.write_last_run(&summary);
        summary
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

    async fn collect(
        &self,
        config: &Config,
        summary: &mut RunSummary,
        delivery_ready: bool,
    ) -> Result<Collected, String> {
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

        let history_path = self.active_public_dir().join(HISTORY_FILE);
        let previous_history = match monitor::load_json_if_exists(&history_path) {
            Ok(value) => value,
            Err(error) => return Err(error.0),
        };
        let state_path = self.active_alert_state_path();
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
        // Only retain undelivered events when there is a working delivery
        // path. Disabled or unconfigured delivery must not grow forever.
        let pending_alert_state =
            monitor::finalize_alert_state_pending(&plan.alert_state, &plan.events, delivery_ready);

        Ok(Collected {
            ssl_output,
            domain_output,
            plan,
            feed_files,
            pending_alert_state,
        })
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
        // Build feeds from whichever checks are configured. A TLS-only or
        // registration-only deployment still gets status, calendar and badges.
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
        if ssl_rows == 0 && domain_rows == 0 {
            return Ok(None);
        }
        feeds::build_feeds(ssl_output, domain_output)
            .map(Some)
            .map_err(|error| format!("public feeds: {error}"))
    }

    fn write_current_pointer(&self, generation: &Generation) -> Result<(), String> {
        write_json_atomic(
            &self.current_file(),
            &json!({
                "schema_version": GENERATION_SCHEMA,
                "generation": generation.id,
                "committed_at": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            }),
        )
        .map_err(|error| format!("cannot write commit pointer: {error}"))
    }

    /// Seal the durable commit record for a generation. This is the commit
    /// point: it is written after the generation rename and before the
    /// convenience pointer, so a crash in between leaves durable evidence.
    fn write_commit_record(&self, generation: &Generation) -> Result<(), String> {
        write_commit_record_file(&self.commits_dir(), generation)
    }

    /// Read every commit record. `present` distinguishes "no records at all"
    /// (legacy upgrade may migrate) from "records exist but none verify"
    /// (fail closed). Readable invalid records are evidence, not fatal.
    fn list_commit_records(&self) -> Result<(Vec<CommitRecord>, bool), String> {
        scan_commit_records(&self.commits_dir())
    }

    /// Load a generation only when a commit record binds its exact manifest.
    /// A sealed directory with no record is never selected.
    fn recover_publication(&self) -> Result<(), String> {
        if self.current_generation().is_some() {
            return Ok(());
        }
        self.fail_closed.store(false, Ordering::SeqCst);

        // Staging directories are never committed; a crash can leave one
        // behind, but it must never be served or mistaken for a generation.
        if let Ok(entries) = fs::read_dir(self.generations_dir()) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(".tmp-") {
                    let _ = fs::remove_dir_all(entry.path());
                }
            }
        }

        let (records, records_present) = match self.list_commit_records() {
            Ok(value) => value,
            Err(error) => {
                // Incomplete enumeration is not "no records": never migrate
                // legacy files or clean up directories from a partial view.
                self.fail_closed.store(true, Ordering::SeqCst);
                return Err(error);
            }
        };
        let mut recovered = None;
        for record in &records {
            if let Some(generation) = self.recover_committed_generation(record) {
                recovered = Some(generation);
                break;
            }
        }

        // Legacy migration is allowed only when no commit record exists at
        // all. If records exist but verify none, stale legacy files must not
        // be promoted.
        if recovered.is_none() && !records_present {
            if let Some(generation) = self.migrate_legacy_public()? {
                if let Err(error) = self.write_commit_record(&generation) {
                    // The commit record is the durable point. A failed or
                    // unsynced record must not leave a migrated generation or
                    // a partial record that would fail closed on the restart.
                    if let Ok(path) = commit_record_path(&self.commits_dir(), &generation.id) {
                        let _ = fs::remove_file(path);
                    }
                    let _ = sync_directory(&self.commits_dir());
                    let _ = fs::remove_dir_all(&generation.root);
                    let _ = sync_directory(&self.generations_dir());
                    return Err(error);
                }
                recovered = Some(generation);
            }
        }

        if let Some(generation) = recovered {
            let pointer_matches = read_json(&self.current_file())
                .ok()
                .and_then(|value| {
                    value
                        .get("generation")
                        .and_then(Value::as_str)
                        .map(|id| id == generation.id)
                })
                .unwrap_or(false);
            if !pointer_matches {
                // The commit record is authoritative; the pointer is only a
                // convenience cache and its failure must not hide a commit.
                let _ = self.write_current_pointer(&generation);
            }
            *self
                .generation
                .write()
                .unwrap_or_else(|poison| poison.into_inner()) = Some(generation);
        } else if records_present {
            self.fail_closed.store(true, Ordering::SeqCst);
        }

        cleanup_uncommitted_generations(&self.generations_dir(), &self.commits_dir()).inspect_err(
            |_| {
                self.fail_closed.store(true, Ordering::SeqCst);
            },
        )?;
        Ok(())
    }

    fn recover_committed_generation(&self, record: &CommitRecord) -> Option<Generation> {
        self.verify_generation(&record.generation, Some(&record.manifest_sha256))
    }

    fn verify_generation(&self, id: &str, expected_manifest: Option<&str>) -> Option<Generation> {
        verify_generation_at(&self.generations_dir(), id, expected_manifest)
    }

    fn generation_is_coherent(&self, generation: &Generation) -> bool {
        generation_is_coherent(generation)
    }

    fn migrate_legacy_public(&self) -> Result<Option<Generation>, String> {
        let public = self.public_dir();
        let ssl = read_public_result(&public, SSL_OUTPUT_FILE);
        let domain = read_public_result(&public, DOMAIN_OUTPUT_FILE);
        let history = read_json(&public.join(HISTORY_FILE)).ok();
        let history_ok = history
            .as_ref()
            .and_then(|value| value.get("snapshots"))
            .map(Value::is_array)
            .unwrap_or(false);
        if ssl.is_none() || domain.is_none() || !history_ok {
            return Ok(None);
        }

        let id = generation_id_tagged("-legacy");
        let staging = self.generations_dir().join(format!(".tmp-{id}"));
        let final_root = self.generations_dir().join(&id);
        let _ = fs::remove_dir_all(&staging);
        let result = (|| -> Result<(), String> {
            let target_public = staging.join("public");
            let target_private = staging.join("private");
            fs::create_dir_all(&target_public)
                .map_err(|error| format!("cannot create migration directory: {error}"))?;
            fs::create_dir_all(&target_private)
                .map_err(|error| format!("cannot create migration directory: {error}"))?;
            let mut files = Vec::new();
            collect_files(&public, &public, &mut files)
                .map_err(|error| format!("cannot enumerate legacy public files: {error}"))?;
            for (relative, source) in files {
                let target = target_public.join(&relative);
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
                }
                let bytes = fs::read(&source)
                    .map_err(|error| format!("cannot read legacy {relative}: {error}"))?;
                write_atomic(&target, &bytes)
                    .map_err(|error| format!("cannot migrate {relative}: {error}"))?;
            }
            let legacy_state = self.private_dir().join(ALERT_STATE_FILE);
            let state = if legacy_state.is_file() {
                monitor::load_json_if_exists(&legacy_state)
                    .map_err(|error| error.0)?
                    .unwrap_or_else(monitor::default_alert_state)
            } else {
                monitor::default_alert_state()
            };
            write_json_atomic(&target_private.join(ALERT_STATE_FILE), &state)
                .map_err(|error| format!("cannot migrate alert state: {error}"))?;
            sync_directory_tree(&target_public)
                .map_err(|error| format!("cannot sync migrated public files: {error}"))?;
            sync_directory_tree(&target_private)
                .map_err(|error| format!("cannot sync migrated private state: {error}"))?;
            let manifest = generation_manifest(&staging, &id)?;
            write_json_atomic(&staging.join(COMPLETE_FILE), &manifest)
                .map_err(|error| format!("cannot write migration manifest: {error}"))?;
            sync_directory(&staging)
                .map_err(|error| format!("cannot sync migration directory: {error}"))?;
            fs::rename(&staging, &final_root)
                .map_err(|error| format!("cannot finish legacy migration: {error}"))?;
            sync_directory(&self.generations_dir())
                .map_err(|error| format!("cannot sync generations directory: {error}"))?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_dir_all(&staging);
            let _ = fs::remove_dir_all(&final_root);
            return Err(error);
        }
        let generation = Generation {
            id,
            root: final_root,
        };
        if !self.generation_is_coherent(&generation) {
            let _ = fs::remove_dir_all(&generation.root);
            return Ok(None);
        }
        Ok(Some(generation))
    }
}

/// Wait for a blocking writer, but never return while it is still running.
/// `true` means the deadline fired first; the handle was still joined.
async fn wait_for_writer<T>(
    mut handle: tokio::task::JoinHandle<T>,
    timeout: Duration,
) -> (Result<T, tokio::task::JoinError>, bool) {
    match tokio::time::timeout(timeout, &mut handle).await {
        Ok(joined) => (joined, false),
        Err(_) => (handle.await, true),
    }
}

struct Collected {
    ssl_output: Value,
    domain_output: Value,
    plan: monitor::MonitoringPlan,
    feed_files: Option<BTreeMap<String, Vec<u8>>>,
    pending_alert_state: Value,
}

struct PublishJob {
    generations_dir: PathBuf,
    commits_dir: PathBuf,
    current_file: PathBuf,
    previous_public: Option<PathBuf>,
    ssl_output: Value,
    domain_output: Value,
    history: Value,
    alert_state: Value,
    feed_files: Option<BTreeMap<String, Vec<u8>>>,
}

fn generation_id() -> String {
    generation_id_tagged("")
}

fn generation_id_tagged(tag: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let counter = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("g-{nanos:020}{tag}-{}-{counter}", std::process::id())
}

/// Write one complete generation to a staging directory, seal it with a
/// digest manifest, rename it into place, and only then move the commit
/// pointer. The private alert checkpoint is part of the same generation.
fn publish_generation(job: PublishJob) -> Result<Generation, String> {
    let id = generation_id();
    let staging = job.generations_dir.join(format!(".tmp-{id}"));
    let final_root = job.generations_dir.join(&id);
    let _ = fs::remove_dir_all(&staging);

    let result = (|| -> Result<(), String> {
        let public = staging.join("public");
        let private = staging.join("private");
        fs::create_dir_all(&public)
            .map_err(|error| format!("cannot create staging public directory: {error}"))?;
        fs::create_dir_all(&private)
            .map_err(|error| format!("cannot create staging private directory: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&private, fs::Permissions::from_mode(0o700));
        }

        write_json_atomic(&public.join(SSL_OUTPUT_FILE), &job.ssl_output)
            .map_err(|error| format!("cannot write {SSL_OUTPUT_FILE}: {error}"))?;
        write_json_atomic(&public.join(DOMAIN_OUTPUT_FILE), &job.domain_output)
            .map_err(|error| format!("cannot write {DOMAIN_OUTPUT_FILE}: {error}"))?;
        write_json_atomic(&public.join(HISTORY_FILE), &job.history)
            .map_err(|error| format!("cannot write {HISTORY_FILE}: {error}"))?;

        match &job.feed_files {
            Some(files) => write_feed_files(&public, files)?,
            // Feeds need both checks. When they cannot be rebuilt, carry the
            // previous generation's feed files into this complete generation
            // instead of leaving them behind in an older directory.
            None => {
                if let Some(previous) = &job.previous_public {
                    copy_feed_files(previous, &public)?;
                }
            }
        }

        write_json_atomic(&private.join(ALERT_STATE_FILE), &job.alert_state)
            .map_err(|error| format!("cannot write private alert state: {error}"))?;

        sync_directory_tree(&private)
            .map_err(|error| format!("cannot sync private state: {error}"))?;
        sync_directory_tree(&public)
            .map_err(|error| format!("cannot sync public files: {error}"))?;
        let manifest = generation_manifest(&staging, &id)?;
        write_json_atomic(&staging.join(COMPLETE_FILE), &manifest)
            .map_err(|error| format!("cannot write generation manifest: {error}"))?;
        sync_directory(&staging).map_err(|error| format!("cannot sync generation: {error}"))?;

        fs::rename(&staging, &final_root)
            .map_err(|error| format!("cannot commit generation directory: {error}"))?;
        sync_directory(&job.generations_dir)
            .map_err(|error| format!("cannot sync generations directory: {error}"))?;

        // Durable commit evidence comes before the convenience pointer. A
        // crash after the rename but before this write leaves an orphan that
        // recovery will never select.
        let committed = Generation {
            id: id.clone(),
            root: final_root.clone(),
        };
        write_commit_record_file(&job.commits_dir, &committed)?;

        if write_json_atomic(
            &job.current_file,
            &json!({
                "schema_version": GENERATION_SCHEMA,
                "generation": id,
                "committed_at": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            }),
        )
        .is_ok()
        {
            if let Some(parent) = job.current_file.parent() {
                let _ = sync_directory(parent);
            }
        }
        Ok(())
    })();

    if let Err(error) = result {
        // A record can only exist here if the commit seal itself failed after
        // writing it; remove that evidence as well as any renamed directory.
        if let Ok(path) = commit_record_path(&job.commits_dir, &id) {
            let _ = fs::remove_file(path);
        }
        let _ = sync_directory(&job.commits_dir);
        let _ = fs::remove_dir_all(&staging);
        // A directory renamed without a durable commit record is not committed.
        let _ = fs::remove_dir_all(&final_root);
        let _ = sync_directory(&job.generations_dir);
        return Err(error);
    }

    let generation = Generation {
        id,
        root: final_root,
    };
    if let Err(error) = prune_generations(&job.generations_dir, &job.commits_dir, &generation.id) {
        // Housekeeping must never delete from an incomplete record view, but
        // it also must not fail an already committed publication.
        eprintln!("certiwatch: generation pruning skipped: {error}");
    }
    Ok(generation)
}

fn write_feed_files(public: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    for (relative, bytes) in files {
        let target = public.join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        write_atomic(&target, bytes)
            .map_err(|error| format!("cannot write {relative}: {error}"))?;
    }
    Ok(())
}

/// Copy feeds that are not rebuilt on this run. The three core result files
/// always come from the current run.
fn copy_feed_files(previous: &Path, public: &Path) -> Result<(), String> {
    if !previous.is_dir() {
        return Ok(());
    }
    let mut files = Vec::new();
    collect_files(previous, previous, &mut files)
        .map_err(|error| format!("cannot read previous feeds: {error}"))?;
    for (relative, source) in files {
        if matches!(
            relative.as_str(),
            SSL_OUTPUT_FILE | DOMAIN_OUTPUT_FILE | HISTORY_FILE
        ) {
            continue;
        }
        let target = public.join(&relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        let bytes = fs::read(&source)
            .map_err(|error| format!("cannot read previous feed {relative}: {error}"))?;
        write_atomic(&target, &bytes)
            .map_err(|error| format!("cannot write previous feed {relative}: {error}"))?;
    }
    Ok(())
}

fn collect_files(
    root: &Path,
    base: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> std::io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_files(&path, base, out)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(base)
                .map_err(std::io::Error::other)?
                .to_string_lossy()
                .replace('\\', "/");
            out.push((relative, path));
        }
    }
    Ok(())
}

fn generation_manifest(root: &Path, id: &str) -> Result<Value, String> {
    let mut entries = BTreeMap::new();
    for (directory, prefix) in [("public", "public"), ("private", "private")] {
        let base = root.join(directory);
        let mut files = Vec::new();
        collect_files(&base, &base, &mut files)
            .map_err(|error| format!("cannot enumerate {directory}: {error}"))?;
        for (relative, path) in files {
            let bytes = fs::read(&path)
                .map_err(|error| format!("cannot read {relative} for manifest: {error}"))?;
            entries.insert(format!("{prefix}/{relative}"), json!(digest(&bytes)));
        }
    }
    Ok(json!({
        "schema_version": GENERATION_SCHEMA,
        "generation": id,
        "committed_at": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "files": entries,
    }))
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let handle = fs::File::open(path)?;
        handle.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Sync every directory under `root` bottom-up, then `root` itself. This makes
/// newly created nested directories (for example `public/badges`) durable
/// before the generation manifest and rename commit them.
fn sync_directory_tree(root: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        fn visit(directory: &Path) -> std::io::Result<()> {
            let entries = fs::read_dir(directory)?;
            for entry in entries {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_dir() && !file_type.is_symlink() {
                    visit(&entry.path())?;
                }
            }
            sync_directory(directory)
        }
        visit(root)
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Ok(())
    }
}

/// Persist the Discord checkpoint and then make its renamed entry durable in
/// the private generation directory.
fn persist_alert_state(path: &Path, state: &Value) -> std::io::Result<()> {
    write_json_atomic(path, state)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn write_commit_record_file(commits_dir: &Path, generation: &Generation) -> Result<(), String> {
    let manifest = fs::read(generation.root.join(COMPLETE_FILE))
        .map_err(|error| format!("cannot read generation manifest: {error}"))?;
    let record = json!({
        "schema_version": GENERATION_SCHEMA,
        "generation": generation.id,
        "manifest_sha256": digest(&manifest),
        "committed_at": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    });
    let path = commit_record_path(commits_dir, &generation.id)?;
    write_json_atomic(&path, &record)
        .map_err(|error| format!("cannot write commit record: {error}"))?;
    sync_directory(commits_dir).map_err(|error| format!("cannot sync commit records: {error}"))
}

const MAX_RECORD_ID_LEN: usize = 96;

/// A generation ID is one lowercase path component. Record filenames and
/// payload IDs are accepted only in this shape; nothing else becomes a path.
fn valid_record_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("g-") else {
        return false;
    };
    if rest.is_empty() || id.len() > MAX_RECORD_ID_LEN {
        return false;
    }
    if !rest
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return false;
    }
    let bytes = id.as_bytes();
    bytes[0].is_ascii_alphanumeric() && bytes[bytes.len() - 1].is_ascii_alphanumeric()
}

fn record_id_from_name(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".json")?;
    valid_record_id(stem).then(|| stem.to_string())
}

fn commit_record_path(commits_dir: &Path, id: &str) -> Result<PathBuf, String> {
    if !valid_record_id(id) {
        return Err(format!("invalid generation id {id:?}"));
    }
    Ok(commits_dir.join(format!("{id}.json")))
}

/// Scan commit records without trusting payload-derived paths.
///
/// - read-dir, entry and record file I/O errors are returned as `Err`;
/// - a readable but schema-invalid record, or one whose payload ID differs
///   from its strict filename ID, is ignored but marks `present`;
/// - only a record whose filename and payload agree can be returned.
fn scan_commit_records(commits_dir: &Path) -> Result<(Vec<CommitRecord>, bool), String> {
    let entries = match fs::read_dir(commits_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), false))
        }
        Err(error) => {
            return Err(format!(
                "cannot enumerate commit records {}: {error}",
                commits_dir.display()
            ))
        }
    };
    let mut records = Vec::new();
    let mut present = false;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "cannot enumerate commit records {}: {error}",
                commits_dir.display()
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(id) = record_id_from_name(name) else {
            continue;
        };
        present = true;
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "cannot inspect commit record {}: {error}",
                entry.path().display()
            )
        })?;
        // A directory or symlink named like a record is invalid evidence:
        // present, never followed or trusted.
        if !file_type.is_file() {
            continue;
        }
        let bytes = fs::read(entry.path()).map_err(|error| {
            format!(
                "cannot read commit record {}: {error}",
                entry.path().display()
            )
        })?;
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if value.get("schema_version").and_then(Value::as_u64) != Some(GENERATION_SCHEMA) {
            continue;
        }
        let Some(payload_id) = value.get("generation").and_then(Value::as_str) else {
            continue;
        };
        if payload_id != id {
            continue;
        }
        let Some(manifest_sha256) = value.get("manifest_sha256").and_then(Value::as_str) else {
            continue;
        };
        records.push(CommitRecord {
            generation: id,
            manifest_sha256: manifest_sha256.to_string(),
        });
    }
    records.sort_by(|left, right| left.generation.cmp(&right.generation));
    records.reverse();
    Ok((records, present))
}

/// IDs with a strict record filename, whether or not the record parses. Used
/// only to protect a generation directory from orphan cleanup.
fn recorded_ids(commits_dir: &Path) -> Result<BTreeSet<String>, String> {
    let mut ids = BTreeSet::new();
    let entries = match fs::read_dir(commits_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(ids),
        Err(error) => {
            return Err(format!(
                "cannot enumerate commit records {}: {error}",
                commits_dir.display()
            ))
        }
    };
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "cannot enumerate commit records {}: {error}",
                commits_dir.display()
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(id) = record_id_from_name(name) {
            ids.insert(id);
        }
    }
    Ok(ids)
}

/// Remove generation directories that have no commit record at all. A crash
/// after the rename and before the record leaves exactly this orphan.
fn cleanup_uncommitted_generations(
    generations_dir: &Path,
    commits_dir: &Path,
) -> Result<(), String> {
    let recorded = recorded_ids(commits_dir)?;
    let entries = match fs::read_dir(generations_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "cannot enumerate generations {}: {error}",
                generations_dir.display()
            ))
        }
    };
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "cannot enumerate generations {}: {error}",
                generations_dir.display()
            )
        })?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("g-") {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "cannot inspect generation {}: {error}",
                entry.path().display()
            )
        })?;
        if !file_type.is_dir() {
            continue;
        }
        if !recorded.contains(&name) {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
    Ok(())
}

/// Keep the newest *usable* generations and drop older verified evidence.
///
/// - retention counts only generations that pass the same eligibility checks
///   as recovery;
/// - `current_id` is always protected;
/// - unverifiable, invalid or mismatched entries are preserved independently
///   and never count toward the limit;
/// - a record is removed only after its generation directory is removed.
fn prune_generations(
    generations_dir: &Path,
    commits_dir: &Path,
    current_id: &str,
) -> Result<(), String> {
    let (records, _present) = scan_commit_records(commits_dir)?;
    let mut usable: Vec<(CommitRecord, Generation)> = Vec::new();
    for record in records {
        if let Some(generation) = verify_generation_at(
            generations_dir,
            &record.generation,
            Some(&record.manifest_sha256),
        ) {
            usable.push((record, generation));
        }
    }

    let current_is_usable = usable
        .iter()
        .any(|(record, _)| record.generation == current_id);
    let mut keep = BTreeSet::new();
    keep.insert(current_id.to_string());
    // If current is usable it counts toward the retention target. If it is
    // unverifiable it is preserved in addition to the usable target.
    let target = if current_is_usable {
        KEEP_GENERATIONS
    } else {
        KEEP_GENERATIONS.saturating_add(1)
    };
    for (record, _) in &usable {
        if keep.len() >= target {
            break;
        }
        keep.insert(record.generation.clone());
    }

    let mut removed_any = false;
    for (record, generation) in &usable {
        if keep.contains(&record.generation) {
            continue;
        }
        // The directory must disappear before its commit record. If removal
        // fails, the record and the unknown data remain for a later attempt.
        if fs::remove_dir_all(&generation.root).is_err() {
            continue;
        }
        removed_any = true;
        if let Ok(path) = commit_record_path(commits_dir, &record.generation) {
            if let Err(error) = fs::remove_file(path) {
                eprintln!(
                    "certiwatch: generation {} removed but its record remains: {error}",
                    record.generation
                );
            }
        }
    }
    if removed_any {
        let _ = sync_directory(generations_dir);
        let _ = sync_directory(commits_dir);
    }
    Ok(())
}

/// The recovery eligibility check, usable without a `Service` instance.
fn verify_generation_at(
    generations_dir: &Path,
    id: &str,
    expected_manifest: Option<&str>,
) -> Option<Generation> {
    let root = generations_dir.join(id);
    let manifest_bytes = fs::read(root.join(COMPLETE_FILE)).ok()?;
    if let Some(expected) = expected_manifest {
        if digest(&manifest_bytes) != expected {
            return None;
        }
    }
    let manifest: Value = serde_json::from_slice(&manifest_bytes).ok()?;
    if manifest.get("schema_version").and_then(Value::as_u64) != Some(GENERATION_SCHEMA)
        || manifest.get("generation").and_then(Value::as_str) != Some(id)
    {
        return None;
    }
    let files = manifest.get("files")?.as_object()?;
    let alert_relative = format!("private/{ALERT_STATE_FILE}");
    for (relative, expected) in files {
        let path = root.join(relative);
        if relative == &alert_relative {
            // Delivery advances this checkpoint atomically after the commit;
            // it must exist, but its bytes legitimately change.
            if !path.is_file() {
                return None;
            }
            continue;
        }
        let expected = expected.as_str()?;
        let bytes = fs::read(&path).ok()?;
        if digest(&bytes) != expected {
            return None;
        }
    }
    for required in [SSL_OUTPUT_FILE, DOMAIN_OUTPUT_FILE, HISTORY_FILE] {
        if !files.contains_key(&format!("public/{required}")) {
            return None;
        }
    }
    if !files.contains_key(&format!("private/{ALERT_STATE_FILE}")) {
        return None;
    }
    let generation = Generation {
        id: id.to_string(),
        root,
    };
    generation_is_coherent(&generation).then_some(generation)
}

fn generation_is_coherent(generation: &Generation) -> bool {
    let public = generation.public_dir();
    if !generation.root.join(COMPLETE_FILE).is_file() {
        return false;
    }
    let ssl = read_public_result(&public, SSL_OUTPUT_FILE);
    let domain = read_public_result(&public, DOMAIN_OUTPUT_FILE);
    let history = read_json(&public.join(HISTORY_FILE)).ok();
    let alert = read_json(&generation.alert_state_path()).ok();
    ssl.is_some()
        && domain.is_some()
        && history
            .as_ref()
            .and_then(|value| value.get("snapshots"))
            .map(Value::is_array)
            .unwrap_or(false)
        && alert.map(|value| value.is_object()).unwrap_or(false)
}
fn deliver_blocking(
    plan: monitor::MonitoringPlan,
    state_path: PathBuf,
    max_attempts: u32,
    discord_timeout: Duration,
) -> Result<usize, String> {
    let transport = DiscordWebhookTransport::from_env(discord_timeout)
        .map_err(|error| format!("Discord delivery skipped: {}", error.0))?;
    let batches = monitor::build_discord_batches(&plan.events).map_err(|error| error.0)?;
    let mut persist =
        |state: &Value| -> std::io::Result<()> { persist_alert_state(&state_path, state) };
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
