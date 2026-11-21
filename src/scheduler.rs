//! Built-in scheduler: one bounded refresh per interval, plus a startup run.
//!
//! The scheduler is deliberately simple: no cron arithmetic, no catch-up
//! storms. A run slower than the interval coalesces missed ticks, and a failed
//! run keeps the previous public snapshot.

use std::sync::Arc;

use chrono::{Duration as ChronoDuration, SecondsFormat, Utc};
use tokio::sync::watch;

use crate::service::Service;

pub async fn run_scheduler(service: Arc<Service>, mut shutdown: watch::Receiver<bool>) {
    if service.settings.run_on_start && service.try_begin() {
        let summary = service.run_once("startup").await;
        log_run(&summary);
        service.finish(summary);
    }

    let period = service
        .settings
        .refresh_interval
        .max(std::time::Duration::from_secs(1));
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await; // the first tick is immediate; the startup run covered it

    loop {
        let next = Utc::now()
            + ChronoDuration::from_std(period).unwrap_or_else(|_| ChronoDuration::seconds(3600));
        service.set_next_run(Some(next.to_rfc3339_opts(SecondsFormat::Secs, true)));

        tokio::select! {
            _ = interval.tick() => {
                if service.try_begin() {
                    let summary = service.run_once("schedule").await;
                    log_run(&summary);
                    service.finish(summary);
                } else {
                    eprintln!("certiwatch: scheduled refresh skipped, a run is in progress");
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    service.set_next_run(None);
    eprintln!("certiwatch: scheduler stopped");
}

fn log_run(summary: &crate::service::RunSummary) {
    let result = if summary.ok { "ok" } else { "failed" };
    let published = if summary.published {
        "published"
    } else {
        "previous snapshot kept"
    };
    eprintln!(
        "certiwatch: refresh {result} trigger={} ssl={} domains={} events={} delivered={} ({} ms, {published}){}",
        summary.trigger,
        summary.ssl_rows,
        summary.domain_rows,
        summary.events,
        summary.delivered,
        summary.duration_ms,
        summary
            .error
            .as_deref()
            .map(|error| format!(": {error}"))
            .unwrap_or_default()
    );
}
