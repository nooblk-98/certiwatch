//! CertiWatch backend: one Axum/Tokio service for certificate and domain
//! expiry monitoring.
//!
//! The public surface is deliberately read-only: one server-rendered dashboard
//! plus JSON, history, status, badge and calendar feeds. Checks run in-process
//! on a bounded schedule; there is no operator HTTP API and no static web
//! directory to mount.

pub mod certinfo;
pub mod config;
pub mod dashboard;
pub mod dns;
pub mod feeds;
pub mod http;
pub mod monitor;
pub mod registration;
pub mod results;
pub mod scheduler;
pub mod service;
pub mod tls;
