//! Health and metrics HTTP server.
//!
//! Two routes:
//! - GET /healthz — liveness probe (200 OK or 503 Service Unavailable)
//! - GET /metrics — Prometheus text format (enforcement counters per hook)

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

/// Shared health state, written by the main loop, read by HTTP handlers.
pub struct HealthState {
    pub attached: bool,
    pub zones_loaded: usize,
    pub containers_active: usize,
    pub start_time: Instant,
}

impl HealthState {
    pub fn new() -> Self {
        Self {
            attached: false,
            zones_loaded: 0,
            containers_active: 0,
            start_time: Instant::now(),
        }
    }
}

pub type SharedHealth = Arc<RwLock<HealthState>>;

/// Spawn the HTTP server on a separate tokio task.
/// Returns immediately — the server runs in the background.
pub fn spawn_health_server(port: u16, state: SharedHealth) {
    tokio::spawn(async move {
        let app = Router::new()
            .route("/healthz", get(healthz))
            .route("/metrics", get(metrics))
            .with_state(state);

        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        tracing::info!(%addr, "health server listening");

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(%e, %addr, "failed to bind health server");
                return;
            }
        };

        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(%e, "health server exited with error");
        }
    });
}

async fn healthz(State(state): State<SharedHealth>) -> Response {
    let health = state.read().unwrap_or_else(|e| e.into_inner());

    let healthy = health.attached && health.zones_loaded > 0;
    let status = if healthy { "ok" } else { "unavailable" };
    let uptime_secs = health.start_time.elapsed().as_secs();

    let body = serde_json::json!({
        "status": status,
        "attached": health.attached,
        "zones_loaded": health.zones_loaded,
        "containers_active": health.containers_active,
        "uptime_secs": uptime_secs,
    });

    let code = if healthy { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (code, axum::Json(body)).into_response()
}

async fn metrics(State(state): State<SharedHealth>) -> String {
    let health = state.read().unwrap_or_else(|e| e.into_inner());

    // Prometheus text format — simple gauges for health state.
    // Enforcement counters come from BPF maps via `syva status`; the health
    // endpoint exposes agent-level state only.
    let mut out = String::with_capacity(512);

    out.push_str("# HELP syva_up Whether syva is attached and enforcing.\n");
    out.push_str("# TYPE syva_up gauge\n");
    out.push_str(&format!("syva_up {}\n", if health.attached { 1 } else { 0 }));

    out.push_str("# HELP syva_zones_loaded Number of policy zones loaded.\n");
    out.push_str("# TYPE syva_zones_loaded gauge\n");
    out.push_str(&format!("syva_zones_loaded {}\n", health.zones_loaded));

    out.push_str("# HELP syva_containers_active Number of containers under enforcement.\n");
    out.push_str("# TYPE syva_containers_active gauge\n");
    out.push_str(&format!("syva_containers_active {}\n", health.containers_active));

    out.push_str("# HELP syva_uptime_seconds Seconds since agent started.\n");
    out.push_str("# TYPE syva_uptime_seconds gauge\n");
    out.push_str(&format!("syva_uptime_seconds {}\n", health.start_time.elapsed().as_secs()));

    out
}
