//! Health + Prometheus endpoints.
//!
//! `/healthz` returns 200 once the gRPC server is serving, 503 before
//! and during shutdown. `/metrics` renders the shared
//! `PrometheusHandle`; cheap enough to re-render on every scrape at our
//! metric volume.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use metrics_exporter_prometheus::PrometheusHandle;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::task::JoinHandle;

#[derive(Clone)]
struct AppState {
    ready: Arc<AtomicBool>,
    metrics: PrometheusHandle,
}

pub struct HealthReady(Arc<AtomicBool>);

impl HealthReady {
    pub fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::SeqCst);
    }
}

pub fn spawn(addr: SocketAddr, metrics: PrometheusHandle) -> (JoinHandle<()>, HealthReady) {
    let ready = Arc::new(AtomicBool::new(false));
    let state = AppState {
        ready: ready.clone(),
        metrics,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_handler))
        .with_state(state);

    let handle = tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("health server bind failed: {e}");
                return;
            }
        };
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("health server error: {e}");
        }
    });

    tracing::info!("health listening on {addr}");
    (handle, HealthReady(ready))
}

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    if state.ready.load(Ordering::SeqCst) {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, state.metrics.render())
}
