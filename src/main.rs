//! CertiWatch command line.
//!
//! `serve` runs the HTTP service and scheduler. `check` runs one refresh with
//! the same pipeline and prints its summary. `feeds` rebuilds the static feed
//! bundle from existing result files.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};
use tokio::sync::watch;

use certiwatch::config;
use certiwatch::feeds;
use certiwatch::http::{router, AppState};
use certiwatch::scheduler;
use certiwatch::service::{RunSummary, Service, Settings};

#[derive(Debug, Parser)]
#[command(
    name = "certiwatch",
    version,
    about = "Certificate and domain expiry monitoring as one Rust service"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the HTTP service and the built-in scheduler.
    Serve {
        /// certiwatch.toml path (default: $CERTIWATCH_CONFIG or ./certiwatch.toml).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Persistent data directory (public/, private/).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Listen address, for example 0.0.0.0:8080.
        #[arg(long)]
        listen: Option<String>,
        /// Seconds between scheduled refreshes.
        #[arg(long)]
        refresh_interval: Option<u64>,
    },
    /// Run one refresh and print the result summary.
    Check {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Validate the configuration and print its effective summary.
    Validate {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Build status.json, expiries.ics and badges from existing result files.
    Feeds {
        /// Directory containing ssl_results.json and domain_results.json.
        #[arg(long, default_value = ".")]
        source: PathBuf,
        /// Feed directory to create.
        #[arg(long, default_value = "feeds")]
        out: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Serve {
            config,
            data_dir,
            listen,
            refresh_interval,
        } => {
            serve(config, data_dir, listen, refresh_interval).await;
            0
        }
        Command::Check { config, data_dir } => check(config, data_dir).await,
        Command::Validate { config } => validate(config),
        Command::Feeds { source, out } => build_feeds(&source, &out),
    };
    std::process::exit(code);
}

fn settings_with(config: Option<PathBuf>, data_dir: Option<PathBuf>) -> Settings {
    let mut settings = Settings::from_env();
    if config.is_some() {
        settings.config_path = config;
    }
    if let Some(data_dir) = data_dir {
        settings.data_dir = data_dir;
    }
    settings
}

async fn serve(
    config: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    listen: Option<String>,
    refresh_interval: Option<u64>,
) {
    let mut settings = settings_with(config, data_dir);
    if let Some(listen) = listen {
        settings.listen = listen;
    }
    if let Some(seconds) = refresh_interval {
        settings.refresh_interval = std::time::Duration::from_secs(seconds.max(1));
    }
    if let Err(error) = settings_validate(&settings) {
        eprintln!("certiwatch: {error}");
        std::process::exit(1);
    }

    let service = Service::new(settings.clone());
    if let Err(error) = service.ensure_directories() {
        eprintln!("certiwatch: cannot create data directories: {error}");
        std::process::exit(1);
    }
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let scheduler_service = Arc::clone(&service);
    let scheduler_task = tokio::spawn(async move {
        scheduler::run_scheduler(scheduler_service, shutdown_rx).await;
    });

    let state = Arc::new(AppState {
        service: Arc::clone(&service),
        started: Instant::now(),
    });
    let app = router(state);
    let listener = match tokio::net::TcpListener::bind(&settings.listen).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("certiwatch: cannot listen on {}: {error}", settings.listen);
            std::process::exit(1);
        }
    };
    eprintln!(
        "certiwatch: listening on {} (config={:?}, data={}, refresh={}s)",
        settings.listen,
        settings.config_path,
        settings.data_dir.display(),
        settings.refresh_interval.as_secs()
    );

    let shutdown = shutdown_signal();
    if let Err(error) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        eprintln!("certiwatch: server error: {error}");
    }
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), scheduler_task).await;
}

/// Resolve on Ctrl-C or SIGTERM. Docker and process supervisors send SIGTERM;
/// both paths stop accepting connections and give the scheduler a bounded exit.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("certiwatch: cannot install SIGTERM handler: {error}");
                let _ = tokio::signal::ctrl_c().await;
                eprintln!("certiwatch: shutting down");
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    eprintln!("certiwatch: shutting down");
}

fn settings_validate(settings: &Settings) -> Result<(), String> {
    let path = config::CONFIG_FILE;
    if settings.config_path.is_none() && !std::path::Path::new(path).exists() {
        return Err(format!(
            "no {path} found; pass --config or set CERTIWATCH_CONFIG"
        ));
    }
    let config = config::load_config(settings.config_path.as_deref())
        .map_err(|error| format!("configuration error: {error}"))?;
    if config.targets.is_empty() {
        return Err("configuration contains no targets".into());
    }
    Ok(())
}

async fn check(config: Option<PathBuf>, data_dir: Option<PathBuf>) -> i32 {
    let settings = settings_with(config, data_dir);
    if let Err(error) = settings_validate(&settings) {
        eprintln!("certiwatch: {error}");
        return 1;
    }
    let service = Service::new(settings);
    if let Err(error) = service.ensure_directories() {
        eprintln!("certiwatch: cannot create data directories: {error}");
        return 1;
    }
    if !service.try_begin() {
        eprintln!("certiwatch: a refresh is already running");
        return 1;
    }
    let summary: RunSummary = service.run_once("cli").await;
    service.finish(summary.clone());
    println!(
        "{}",
        serde_json::to_string_pretty(&summary.to_json()).unwrap_or_default()
    );
    if summary.ok {
        if summary.error.is_some() {
            return 2;
        }
        0
    } else {
        1
    }
}

fn validate(config: Option<PathBuf>) -> i32 {
    let path = config
        .or_else(|| {
            std::env::var("CERTIWATCH_CONFIG")
                .ok()
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(config::CONFIG_FILE));
    match config::load_config(Some(&path)) {
        Ok(config) => {
            println!(
                "configuration ok: {} target(s), {} TLS, {} registration, thresholds {:?}, history_limit {}",
                config.targets.len(),
                config.ssl_targets().len(),
                config.registration_targets().len(),
                config.thresholds,
                config.history_limit
            );
            0
        }
        Err(error) => {
            eprintln!("certiwatch: configuration error: {error}");
            1
        }
    }
}

fn build_feeds(source: &std::path::Path, out: &std::path::Path) -> i32 {
    match feeds::build_bundle(source, out) {
        Ok(files) => {
            println!("feeds: {} ({} files)", out.display(), files.len());
            0
        }
        Err(error) => {
            eprintln!("certiwatch: feeds: {error}");
            error.code
        }
    }
}
