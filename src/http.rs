//! Public, read-only HTTP surface.
//!
//! The dashboard is rendered from the published result snapshot on every GET,
//! so filters work without browser JavaScript. Everything else the public can
//! read is a generated file under the public data directory. There is no
//! operator or administration API: refreshes belong to the built-in scheduler
//! and the `certiwatch check` CLI.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{Path as AxumPath, RawQuery, State};
use axum::http::{header, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::json;

use crate::dashboard::{self, DashboardQuery};
use crate::service::Service;

/// CSP for the server-rendered page: no scripts at all, inline styles only
/// (the stylesheet is embedded), same-origin GET forms for the filters, and no
/// framing or base-URL tricks.
pub const DASHBOARD_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; \
     img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

pub struct AppState {
    pub service: Arc<Service>,
    pub started: Instant,
}

pub fn router(state: Arc<AppState>) -> Router {
    let app: Router<Arc<AppState>> = Router::new()
        .route("/", get(dashboard_page))
        .route("/dashboard.css", get(dashboard_css))
        .route("/favicon.ico", get(no_content))
        .route("/robots.txt", get(robots))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/ssl_results.json", get(ssl_results))
        .route("/domain_results.json", get(domain_results))
        .route("/history.json", get(history))
        .route("/status.json", get(status_feed))
        .route("/expiries.ics", get(calendar))
        .route("/badges/manifest.json", get(badge_manifest))
        .route("/badges/{file}", get(badge_file))
        .fallback(fallback);
    app.with_state(state)
}

// ── Responses ────────────────────────────────────────────────────────────────

fn base_headers() -> header::HeaderMap {
    let mut headers = header::HeaderMap::new();
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers
}

fn text_response(status: StatusCode, body: &str) -> Response {
    let mut response = (status, body.to_string()).into_response();
    for (key, value) in base_headers() {
        if let Some(key) = key {
            response.headers_mut().insert(key, value);
        }
    }
    response
}

fn json_response(status: StatusCode, value: &serde_json::Value, cache: &str) -> Response {
    let body = serde_json::to_vec_pretty(value).unwrap_or_else(|_| b"{}".to_vec());
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        "application/json; charset=utf-8".parse().unwrap(),
    );
    headers.insert(header::CACHE_CONTROL, cache.parse().unwrap());
    for (key, value) in base_headers() {
        headers.insert(key.unwrap(), value);
    }
    response
}

fn bytes_response(status: StatusCode, bytes: Vec<u8>, content_type: &str, cache: &str) -> Response {
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    headers.insert(header::CACHE_CONTROL, cache.parse().unwrap());
    for (key, value) in base_headers() {
        headers.insert(key.unwrap(), value);
    }
    response
}

/// Serve one published file through the service's snapshot lock, so a request
/// never observes a half-replaced public directory.
fn published_file(state: &AppState, relative: &Path, content_type: &str, cache: &str) -> Response {
    match state.service.read_public_file(relative) {
        Some(bytes) => bytes_response(StatusCode::OK, bytes, content_type, cache),
        None => text_response(StatusCode::NOT_FOUND, "not found"),
    }
}

// ── Dashboard ────────────────────────────────────────────────────────────────

async fn dashboard_page(State(state): State<Arc<AppState>>, RawQuery(query): RawQuery) -> Response {
    let query = query
        .as_deref()
        .and_then(|raw| serde_urlencoded::from_str::<DashboardQuery>(raw).ok())
        .unwrap_or_default();
    let snapshot = state.service.read_snapshot();
    let html = dashboard::render_dashboard(
        snapshot.ssl.as_ref(),
        snapshot.domains.as_ref(),
        snapshot.history.as_ref(),
        &query,
    );
    let mut response = Response::new(Body::from(html));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        "text/html; charset=utf-8".parse().unwrap(),
    );
    headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        DASHBOARD_CSP.parse().unwrap(),
    );
    for (key, value) in base_headers() {
        headers.insert(key.unwrap(), value);
    }
    response
}

async fn dashboard_css() -> Response {
    bytes_response(
        StatusCode::OK,
        dashboard::DASHBOARD_CSS.as_bytes().to_vec(),
        "text/css; charset=utf-8",
        "public, max-age=3600",
    )
}

async fn robots() -> Response {
    text_response(StatusCode::OK, "User-agent: *\nDisallow: /\n")
}

async fn no_content() -> Response {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::NO_CONTENT.into_response())
}

// ── Public feeds ─────────────────────────────────────────────────────────────

async fn ssl_results(State(state): State<Arc<AppState>>) -> Response {
    published_file(
        &state,
        Path::new("ssl_results.json"),
        "application/json; charset=utf-8",
        "no-cache, must-revalidate",
    )
}

async fn domain_results(State(state): State<Arc<AppState>>) -> Response {
    published_file(
        &state,
        Path::new("domain_results.json"),
        "application/json; charset=utf-8",
        "no-cache, must-revalidate",
    )
}

async fn history(State(state): State<Arc<AppState>>) -> Response {
    published_file(
        &state,
        Path::new("history.json"),
        "application/json; charset=utf-8",
        "no-cache, must-revalidate",
    )
}

async fn status_feed(State(state): State<Arc<AppState>>) -> Response {
    published_file(
        &state,
        Path::new("status.json"),
        "application/json; charset=utf-8",
        "no-cache, must-revalidate",
    )
}

async fn calendar(State(state): State<Arc<AppState>>) -> Response {
    published_file(
        &state,
        Path::new("expiries.ics"),
        "text/calendar; charset=utf-8",
        "public, max-age=300, must-revalidate",
    )
}

async fn badge_manifest(State(state): State<Arc<AppState>>) -> Response {
    published_file(
        &state,
        Path::new("badges/manifest.json"),
        "application/json; charset=utf-8",
        "no-cache, must-revalidate",
    )
}

async fn badge_file(
    State(state): State<Arc<AppState>>,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if !valid_badge_name(&name) {
        return text_response(StatusCode::NOT_FOUND, "not found");
    }
    published_file(
        &state,
        &PathBuf::from("badges").join(name),
        "image/svg+xml; charset=utf-8",
        "public, max-age=300, must-revalidate",
    )
}

/// Badge names are generated (`<slug>-<16 hex>.svg`), never user input.
fn valid_badge_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".svg") else {
        return false;
    };
    let Some((slug, digest)) = stem.rsplit_once('-') else {
        return false;
    };
    !slug.is_empty()
        && slug.len() <= 120
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && digest.len() == 32
        && digest.bytes().all(|b| b.is_ascii_hexdigit())
}

// ── Health ───────────────────────────────────────────────────────────────────

async fn healthz(State(state): State<Arc<AppState>>) -> Response {
    json_response(
        StatusCode::OK,
        &json!({
            "status": "ok",
            "uptime_seconds": state.started.elapsed().as_secs(),
        }),
        "no-store",
    )
}

async fn readyz(State(state): State<Arc<AppState>>) -> Response {
    if state.service.is_ready() {
        json_response(StatusCode::OK, &json!({"status": "ready"}), "no-store")
    } else {
        let mut response = json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"status": "starting", "detail": "no successful snapshot yet"}),
            "no-store",
        );
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, "30".parse().unwrap());
        response
    }
}

async fn fallback(method: Method, uri: axum::http::Uri) -> Response {
    // Unknown paths, including every retired /api admin route, are 404 for all
    // methods. Nothing here mutates state.
    let _ = (method, uri);
    text_response(StatusCode::NOT_FOUND, "not found")
}
