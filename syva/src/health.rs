//! Health and metrics HTTP server.
//!
//! Two routes:
//! - GET /healthz — readiness check (200 OK when BPF attached, 503 otherwise)
//! - GET /metrics — Prometheus text format (agent-level gauges)

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;

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

/// Bind the HTTP server and spawn it on a separate tokio task.
/// Returns Err if the port cannot be bound (fail-fast for probe misconfiguration).
pub async fn spawn_health_server(port: u16, state: SharedHealth) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await
        .map_err(|e| anyhow::anyhow!("failed to bind health server on {addr}: {e}"))?;
    tracing::info!(%addr, "health server listening");

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(%e, "health server exited with error");
        }
    });

    Ok(())
}

async fn healthz(State(state): State<SharedHealth>) -> Response {
    let health = state.read().await;

    // Healthy = BPF programs attached and self-tests passed.
    // Zero zones loaded is valid (empty policy dir) — not a liveness failure.
    let healthy = health.attached;
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
    let health = state.read().await;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn shared_state(attached: bool, zones_loaded: usize, containers_active: usize) -> SharedHealth {
        Arc::new(RwLock::new(HealthState {
            attached,
            zones_loaded,
            containers_active,
            start_time: Instant::now(),
        }))
    }

    #[tokio::test]
    async fn healthz_returns_503_when_not_attached() {
        let state = shared_state(false, 3, 2);
        let response = healthz(State(state)).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn healthz_returns_200_when_attached() {
        let state = shared_state(true, 3, 7);
        let response = healthz(State(state)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn healthz_returns_200_with_zero_zones() {
        let state = shared_state(true, 0, 0);
        let response = healthz(State(state)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_contains_expected_gauges() {
        let state = shared_state(true, 4, 9);
        let output = metrics(State(state)).await;
        assert!(output.contains("syva_up 1\n"));
        assert!(output.contains("syva_zones_loaded 4\n"));
        assert!(output.contains("syva_containers_active 9\n"));
        assert!(output.contains("syva_uptime_seconds "));
    }

    #[tokio::test]
    async fn metrics_shows_down_when_not_attached() {
        let state = shared_state(false, 0, 0);
        let output = metrics(State(state)).await;
        assert!(output.contains("syva_up 0\n"));
    }
}
