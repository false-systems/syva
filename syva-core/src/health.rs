//! Health and metrics HTTP server.
//!
//! Two routes:
//! - GET /healthz — readiness check and enforcement security status
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

/// Per-hook enforcement counter snapshot, summed across CPUs.
#[derive(Debug, Clone, Default)]
pub struct HookCounters {
    pub allow: u64,
    pub deny: u64,
    pub error: u64,
    pub lost: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityStatus {
    Healthy,
    Degraded,
    Unsafe,
}

impl SecurityStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unsafe => "unsafe",
        }
    }
}

/// Shared health state, written by the main loop, read by HTTP handlers.
pub struct HealthState {
    pub attached: bool,
    pub zones_loaded: usize,
    pub containers_active: usize,
    pub start_time: Instant,
    /// Latest per-hook enforcement counter snapshot.
    /// Index matches `events::HOOK_NAMES`. Empty until first snapshot.
    pub hook_counters: Vec<HookCounters>,
    pub membership_degraded: bool,
    pub membership_message: Option<String>,
}

impl HealthState {
    pub fn new() -> Self {
        Self {
            attached: false,
            zones_loaded: 0,
            containers_active: 0,
            start_time: Instant::now(),
            hook_counters: Vec::new(),
            membership_degraded: false,
            membership_message: None,
        }
    }

    pub fn mark_membership_degraded(&mut self, message: impl Into<String>) {
        self.membership_degraded = true;
        self.membership_message = Some(message.into());
    }

    pub fn security_status(&self) -> SecurityStatus {
        if !self.attached {
            return SecurityStatus::Unsafe;
        }

        if self.membership_degraded
            || self
                .hook_counters
                .iter()
                .any(|counter| counter.error > 0 || counter.lost > 0)
        {
            return SecurityStatus::Degraded;
        }

        SecurityStatus::Healthy
    }

    pub fn degraded_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();

        if !self.attached {
            reasons.push("BPF programs are not attached".to_string());
        }
        if let Some(message) = self.membership_message.as_ref() {
            reasons.push(message.clone());
        } else if self.membership_degraded {
            reasons.push("membership reconciliation is degraded".to_string());
        }

        for (idx, counters) in self.hook_counters.iter().enumerate() {
            if counters.error > 0 || counters.lost > 0 {
                let hook = crate::events::HOOK_NAMES
                    .get(idx)
                    .copied()
                    .unwrap_or("unknown");
                reasons.push(format!(
                    "hook '{hook}' has error={} lost={} counters",
                    counters.error, counters.lost
                ));
            }
        }

        reasons
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
    let listener = tokio::net::TcpListener::bind(addr)
        .await
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

    let security_status = health.security_status();
    let uptime_secs = health.start_time.elapsed().as_secs();

    let body = serde_json::json!({
        "status": security_status.as_str(),
        "attached": health.attached,
        "zones_loaded": health.zones_loaded,
        "containers_active": health.containers_active,
        "uptime_secs": uptime_secs,
        "degraded_reasons": health.degraded_reasons(),
    });

    let code = if security_status == SecurityStatus::Unsafe {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (code, axum::Json(body)).into_response()
}

async fn metrics(State(state): State<SharedHealth>) -> String {
    let health = state.read().await;
    render_metrics(&health)
}

/// Pure function — testable without HTTP server.
pub fn render_metrics(health: &HealthState) -> String {
    type HookMetric = (&'static str, &'static str, fn(&HookCounters) -> u64);

    let mut out = String::with_capacity(2048);

    out.push_str("# HELP syva_up Whether syva is attached and enforcing.\n");
    out.push_str("# TYPE syva_up gauge\n");
    out.push_str(&format!(
        "syva_up {}\n",
        if health.attached { 1 } else { 0 }
    ));

    out.push_str(
        "# HELP syva_security_status Current enforcement security status as labeled gauges.\n",
    );
    out.push_str("# TYPE syva_security_status gauge\n");
    let current = health.security_status();
    for status in [
        SecurityStatus::Healthy,
        SecurityStatus::Degraded,
        SecurityStatus::Unsafe,
    ] {
        out.push_str(&format!(
            "syva_security_status{{status=\"{}\"}} {}\n",
            status.as_str(),
            if status == current { 1 } else { 0 }
        ));
    }

    out.push_str("# HELP syva_zones_loaded Number of policy zones loaded.\n");
    out.push_str("# TYPE syva_zones_loaded gauge\n");
    out.push_str(&format!("syva_zones_loaded {}\n", health.zones_loaded));

    out.push_str("# HELP syva_containers_active Number of containers under enforcement.\n");
    out.push_str("# TYPE syva_containers_active gauge\n");
    out.push_str(&format!(
        "syva_containers_active {}\n",
        health.containers_active
    ));

    out.push_str("# HELP syva_uptime_seconds Seconds since agent started.\n");
    out.push_str("# TYPE syva_uptime_seconds gauge\n");
    out.push_str(&format!(
        "syva_uptime_seconds {}\n",
        health.start_time.elapsed().as_secs()
    ));

    // Per-hook enforcement counters — always emitted (default 0 before first
    // snapshot) so Prometheus series exist from the start.
    let hook_names = &crate::events::HOOK_NAMES;
    let metrics: [HookMetric; 4] = [
        (
            "syva_hook_allow_total",
            "Events allowed per hook",
            |c: &HookCounters| c.allow,
        ),
        (
            "syva_hook_deny_total",
            "Events denied per hook",
            |c: &HookCounters| c.deny,
        ),
        (
            "syva_hook_error_total",
            "Hook errors that fail open and degrade security per hook",
            |c: &HookCounters| c.error,
        ),
        (
            "syva_hook_lost_total",
            "Ring buffer lost events per hook",
            |c: &HookCounters| c.lost,
        ),
    ];
    for (metric, help, extractor) in metrics {
        out.push_str(&format!(
            "# HELP {} {}\n# TYPE {} counter\n",
            metric, help, metric
        ));
        for (i, name) in hook_names.iter().enumerate() {
            let val = health.hook_counters.get(i).map(extractor).unwrap_or(0);
            out.push_str(&format!("{}{{hook=\"{}\"}} {}\n", metric, name, val));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(attached: bool, zones: usize, containers: usize) -> HealthState {
        HealthState {
            attached,
            zones_loaded: zones,
            containers_active: containers,
            start_time: Instant::now(),
            hook_counters: Vec::new(),
            membership_degraded: false,
            membership_message: None,
        }
    }

    fn shared(state: HealthState) -> SharedHealth {
        Arc::new(RwLock::new(state))
    }

    #[tokio::test]
    async fn healthz_returns_503_when_not_attached() {
        let state = shared(make_state(false, 3, 2));
        let response = healthz(State(state)).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn healthz_returns_200_when_attached() {
        let state = shared(make_state(true, 3, 7));
        let response = healthz(State(state)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn healthz_returns_200_when_degraded() {
        let mut state = make_state(true, 3, 7);
        state.hook_counters = vec![HookCounters {
            allow: 0,
            deny: 0,
            error: 1,
            lost: 0,
        }];
        let response = healthz(State(shared(state))).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn healthz_returns_200_with_zero_zones() {
        let state = shared(make_state(true, 0, 0));
        let response = healthz(State(state)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn hook_counters_default_zero() {
        let c = HookCounters::default();
        assert_eq!(c.allow, 0);
        assert_eq!(c.deny, 0);
        assert_eq!(c.error, 0);
        assert_eq!(c.lost, 0);
    }

    #[test]
    fn render_metrics_includes_agent_gauges() {
        let state = make_state(true, 4, 9);
        let output = render_metrics(&state);
        assert!(output.contains("syva_up 1\n"));
        assert!(output.contains("syva_zones_loaded 4\n"));
        assert!(output.contains("syva_containers_active 9\n"));
        assert!(output.contains("syva_security_status{status=\"healthy\"} 1"));
    }

    #[test]
    fn bpf_error_counter_moves_security_status_to_degraded() {
        let mut state = make_state(true, 4, 9);
        state.hook_counters = vec![HookCounters {
            allow: 0,
            deny: 0,
            error: 1,
            lost: 0,
        }];

        assert_eq!(state.security_status(), SecurityStatus::Degraded);
        assert!(state
            .degraded_reasons()
            .iter()
            .any(|reason| reason.contains("error=1")));
    }

    #[test]
    fn membership_degradation_moves_security_status_to_degraded() {
        let mut state = make_state(true, 4, 9);
        state.mark_membership_degraded("membership backend stale");

        assert_eq!(state.security_status(), SecurityStatus::Degraded);
        assert_eq!(
            state.degraded_reasons(),
            vec!["membership backend stale".to_string()]
        );
    }

    #[test]
    fn unattached_is_unsafe() {
        let state = make_state(false, 0, 0);

        assert_eq!(state.security_status(), SecurityStatus::Unsafe);
    }

    #[test]
    fn render_metrics_includes_hook_counters() {
        let mut state = make_state(true, 2, 5);
        state.hook_counters = vec![
            HookCounters {
                allow: 100,
                deny: 2,
                error: 0,
                lost: 0,
            },
            HookCounters {
                allow: 50,
                deny: 0,
                error: 1,
                lost: 0,
            },
            HookCounters::default(),
            HookCounters::default(),
            HookCounters::default(),
            HookCounters::default(),
            HookCounters::default(),
        ];

        let output = render_metrics(&state);
        assert!(output.contains("syva_hook_allow_total{hook=\"file_open\"} 100"));
        assert!(output.contains("syva_hook_deny_total{hook=\"file_open\"} 2"));
        assert!(output.contains("syva_hook_error_total{hook=\"bprm_check\"} 1"));
        assert!(output.contains("syva_hook_deny_total{hook=\"unix_connect\"} 0"));
    }

    #[test]
    fn render_metrics_empty_counters_shows_zeros() {
        // Hook series always present so Prometheus doesn't churn on first snapshot.
        let state = make_state(false, 0, 0);
        let output = render_metrics(&state);
        assert!(output.contains("syva_hook_allow_total{hook=\"file_open\"} 0"));
        assert!(output.contains("syva_hook_deny_total{hook=\"unix_connect\"} 0"));
    }

    #[test]
    fn render_metrics_down_when_not_attached() {
        let state = make_state(false, 0, 0);
        let output = render_metrics(&state);
        assert!(output.contains("syva_up 0\n"));
    }
}
