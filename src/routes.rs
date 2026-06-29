use crate::parsing::INFRA_DOMAINS;
use crate::scan_store::ScanStore;
use crate::scanner::scan_targets;
use crate::store::SharedStore;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tower_http::compression::CompressionLayer;

#[derive(Clone)]
pub struct AppState {
    pub store: SharedStore,
    pub scan_store: Arc<ScanStore>,
    pub config: Arc<crate::config::Config>,
    pub template_path: PathBuf,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/records", get(api_records))
        .route("/api/records/:ip/:port", get(api_record_detail))
        .route("/api/stats", get(api_stats))
        .route("/api/duplicates", get(api_duplicates))
        .route("/api/infra-domains", get(api_infra_domains))
        .route("/api/scans", get(api_scans))
        .route("/api/hosts", post(api_hosts))
        .route("/api/scan", post(api_scan))
        .route("/api/report", post(api_report))
        .route("/api/reload", post(api_reload))
        .layer(CompressionLayer::new())
        .with_state(state)
}

async fn index(State(state): State<AppState>) -> impl IntoResponse {
    match tokio::fs::read_to_string(&state.template_path).await {
        Ok(html) => Html(html).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "index.html not found").into_response(),
    }
}

async fn api_records(State(state): State<AppState>) -> impl IntoResponse {
    let arc = state.store.read().await.summaries();
    Json(arc)
}

async fn api_record_detail(
    State(state): State<AppState>,
    Path((ip, port)): Path<(String, String)>,
) -> impl IntoResponse {
    let port_num: i64 = match port.parse() {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid port"}))).into_response(),
    };
    let store = state.store.read().await;
    match store.get_detail(&ip, port_num) {  // read-only, no lock contention
        Some(record) => Json(record.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}

async fn api_stats(State(state): State<AppState>) -> impl IntoResponse {
    let arc = state.store.read().await.stats();
    Json(arc)
}

async fn api_duplicates(State(state): State<AppState>) -> impl IntoResponse {
    let arc = state.store.read().await.duplicates();
    Json(arc)
}

async fn api_infra_domains(State(_state): State<AppState>) -> Json<Value> {
    let mut domains: Vec<&str> = INFRA_DOMAINS.to_vec();
    domains.sort();
    Json(Value::Array(domains.iter().map(|d| Value::String(d.to_string())).collect()))
}

async fn api_scans(State(state): State<AppState>) -> Json<Value> {
    Json(state.scan_store.all())
}

async fn api_scan(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let payload: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
    let requested = payload.get("targets")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let max_targets = state.config.scan_max_targets;

    // Build the target list while holding the store lock, then release before awaiting
    let (targets, skipped) = {
        let store = state.store.read().await;
        let mut targets: Vec<(String, u16, Option<String>)> = Vec::new();
        let mut skipped = 0usize;

        for t in &requested {
            let ip = match t.get("ip").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => { skipped += 1; continue; }
            };
            let port: i64 = match t.get("port").and_then(|v| {
                v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            }) {
                Some(p) => p,
                None => { skipped += 1; continue; }
            };

            if port < 1 || port > 65535 { skipped += 1; continue; }
            let port_u16 = port as u16;

            if store.get_detail(&ip, port).is_none() {
                skipped += 1;
                continue;
            }

            let hostname = t.get("hostname").and_then(|v| v.as_str()).map(|s| s.to_string())
                .or_else(|| {
                    store.get_detail(&ip, port).and_then(|r| {
                        r.get("hostnames").and_then(|v| v.as_array())
                            .and_then(|a| a.first())
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
                });

            targets.push((ip, port_u16, hostname));
        }
        (targets, skipped)
        // store guard dropped here
    };

    if targets.len() > max_targets {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("too many targets (max {})", max_targets)})),
        ).into_response();
    }

    let connect_timeout = Duration::from_secs_f64(state.config.scan_connect_timeout_secs);
    let read_timeout = Duration::from_secs_f64(state.config.scan_read_timeout_secs);
    let workers = state.config.scan_workers;

    let results = scan_targets(targets, workers, connect_timeout, read_timeout).await;
    let stored = state.scan_store.record(results);
    let scanned = stored.len();

    Json(json!({
        "results": stored,
        "scanned": scanned,
        "skipped": skipped,
    })).into_response()
}

async fn api_hosts(
    State(state): State<AppState>,
    Json(params): Json<crate::filter::FilterParams>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    let summaries = store.summaries();
    let total = summaries.len();
    let result = crate::filter::apply(&summaries, &params, total);
    drop(store);
    Json(result)
}

async fn api_report(
    State(state): State<AppState>,
    Json(config): Json<crate::report::ReportConfig>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    let html = crate::report::generate(
        &config,
        &store.records,
        &store.index,
        &state.scan_store,
    );
    drop(store);

    let date = chrono::Utc::now().format("%Y-%m-%d");
    let filename = format!("shodanify-report-{date}.html");

    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("text/html; charset=utf-8"));
    headers.insert(
        "Content-Disposition",
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")).unwrap(),
    );
    (headers, html)
}

async fn api_reload(State(state): State<AppState>) -> Json<Value> {
    let data_dir = state.config.data_dir.clone();
    let new_store = tokio::task::spawn_blocking(move || {
        crate::store::DataStore::load(&data_dir)
    }).await.expect("reload panicked");

    let count = new_store.records.len();
    let files_loaded = new_store.files_loaded;
    let dups = new_store.duplicates_removed;
    let errors = new_store.parse_errors;

    *state.store.write().await = new_store;

    Json(json!({
        "status": "ok",
        "count": count,
        "files_loaded": files_loaded,
        "duplicates_removed": dups,
        "parse_errors": errors,
    }))
}
