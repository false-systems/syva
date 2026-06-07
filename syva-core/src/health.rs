//! Health and metrics HTTP server.
//!
//! Two routes:
//! - GET /healthz — readiness check and enforcement security status
//! - GET /metrics — Prometheus text format (agent-level gauges)

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfTestStatus {
    Pending,
    Passed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfTestName {
    Cgroup,
    Inode,
    Unix,
}

impl SelfTestName {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cgroup => "cgroup",
            Self::Inode => "inode",
            Self::Unix => "unix",
        }
    }
}

impl SelfTestStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }

    fn passed_metric(self) -> u8 {
        match self {
            Self::Passed => 1,
            Self::Pending | Self::Failed => 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SelfTestState {
    pub cgroup: SelfTestStatus,
    pub inode: SelfTestStatus,
    pub unix: SelfTestStatus,
}

impl Default for SelfTestState {
    fn default() -> Self {
        Self {
            cgroup: SelfTestStatus::Pending,
            inode: SelfTestStatus::Pending,
            unix: SelfTestStatus::Pending,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BpfMapErrors {
    pub read: u64,
    pub update: u64,
    pub delete: u64,
}

#[derive(Debug, Clone, Default)]
pub struct MembershipMetrics {
    pub applied: u64,
    pub unchanged: u64,
    pub stale: u64,
    pub conflict: u64,
    pub error: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfMapOperation {
    Read,
    Update,
    Delete,
}

impl BpfMapOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipUpdateResult {
    Applied,
    Unchanged,
    Stale,
    Conflict,
    Error,
}

impl MembershipUpdateResult {
    fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Unchanged => "unchanged",
            Self::Stale => "stale",
            Self::Conflict => "conflict",
            Self::Error => "error",
        }
    }
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

const ACTIVE_DEGRADATION_WINDOW_SECS: u64 = 300;

/// Shared health state, written by the main loop, read by HTTP handlers.
pub struct HealthState {
    pub ebpf_loaded: bool,
    pub attached: bool,
    pub expected_hooks: usize,
    pub attached_hooks: usize,
    pub selftests: SelfTestState,
    pub zones_loaded: usize,
    pub containers_active: usize,
    pub start_time: Instant,
    pub start_time_unix: u64,
    /// Latest per-hook enforcement counter snapshot.
    /// Index matches `events::HOOK_NAMES`. Empty until first snapshot.
    pub hook_counters: Vec<HookCounters>,
    pub hook_degraded_reasons: Vec<String>,
    pub last_counter_read_ok: bool,
    pub last_counter_read_success_unix: Option<u64>,
    pub bpf_map_errors: BpfMapErrors,
    pub degraded_message: Option<String>,
    pub degraded_until_unix: Option<u64>,
    pub membership_updates: MembershipMetrics,
}

impl HealthState {
    pub fn new() -> Self {
        Self {
            ebpf_loaded: false,
            attached: false,
            expected_hooks: crate::events::HOOK_NAMES.len(),
            attached_hooks: 0,
            selftests: SelfTestState::default(),
            zones_loaded: 0,
            containers_active: 0,
            start_time: Instant::now(),
            start_time_unix: unix_now(),
            hook_counters: Vec::new(),
            hook_degraded_reasons: Vec::new(),
            last_counter_read_ok: true,
            last_counter_read_success_unix: None,
            bpf_map_errors: BpfMapErrors::default(),
            degraded_message: None,
            degraded_until_unix: None,
            membership_updates: MembershipMetrics::default(),
        }
    }

    pub fn mark_ebpf_loaded(&mut self) {
        self.ebpf_loaded = true;
    }

    pub fn mark_attached(&mut self, attached_hooks: usize) {
        self.attached = attached_hooks == self.expected_hooks;
        self.attached_hooks = attached_hooks;
    }

    pub fn mark_selftest(&mut self, test: SelfTestName, status: SelfTestStatus) {
        match test {
            SelfTestName::Cgroup => self.selftests.cgroup = status,
            SelfTestName::Inode => self.selftests.inode = status,
            SelfTestName::Unix => self.selftests.unix = status,
        }
    }

    pub fn record_bpf_map_error(&mut self, operation: BpfMapOperation, message: impl Into<String>) {
        match operation {
            BpfMapOperation::Read => self.bpf_map_errors.read += 1,
            BpfMapOperation::Update => self.bpf_map_errors.update += 1,
            BpfMapOperation::Delete => self.bpf_map_errors.delete += 1,
        }
        self.mark_active_degradation(message);
    }

    pub fn mark_counter_read_failed(&mut self, message: impl Into<String>) {
        self.last_counter_read_ok = false;
        self.bpf_map_errors.read += 1;
        self.mark_active_degradation(message);
    }

    pub fn mark_membership_degraded(&mut self, message: impl Into<String>) {
        self.mark_active_degradation(message);
    }

    pub fn record_membership_update(&mut self, result: MembershipUpdateResult) {
        match result {
            MembershipUpdateResult::Applied => self.membership_updates.applied += 1,
            MembershipUpdateResult::Unchanged => self.membership_updates.unchanged += 1,
            MembershipUpdateResult::Stale => self.membership_updates.stale += 1,
            MembershipUpdateResult::Conflict => self.membership_updates.conflict += 1,
            MembershipUpdateResult::Error => self.membership_updates.error += 1,
        }
    }

    fn mark_active_degradation(&mut self, message: impl Into<String>) {
        self.degraded_message = Some(message.into());
        self.degraded_until_unix = Some(unix_now().saturating_add(ACTIVE_DEGRADATION_WINDOW_SECS));
    }

    fn active_degradation_message(&self) -> Option<&str> {
        let until = self.degraded_until_unix?;
        if unix_now() <= until {
            self.degraded_message.as_deref()
        } else {
            None
        }
    }

    pub fn update_hook_counters(&mut self, next: Vec<HookCounters>) {
        let mut reasons = Vec::new();
        for (idx, next_counter) in next.iter().enumerate() {
            let previous = self.hook_counters.get(idx).cloned().unwrap_or_default();
            let error_delta = next_counter.error.saturating_sub(previous.error);
            let lost_delta = next_counter.lost.saturating_sub(previous.lost);
            if error_delta > 0 || lost_delta > 0 {
                let hook = crate::events::HOOK_NAMES
                    .get(idx)
                    .copied()
                    .unwrap_or("unknown");
                reasons.push(format!(
                    "hook '{hook}' has recent error_delta={error_delta} lost_delta={lost_delta}"
                ));
            }
        }
        self.hook_counters = next;
        self.hook_degraded_reasons = reasons;
        self.last_counter_read_ok = true;
        self.last_counter_read_success_unix = Some(unix_now());
    }

    pub fn security_status(&self) -> SecurityStatus {
        if !self.ebpf_loaded
            || !self.attached
            || self.attached_hooks < self.expected_hooks
            || self.selftests.cgroup != SelfTestStatus::Passed
            || self.selftests.inode != SelfTestStatus::Passed
            || self.selftests.unix != SelfTestStatus::Passed
        {
            return SecurityStatus::Unsafe;
        }

        if self.active_degradation_message().is_some()
            || !self.hook_degraded_reasons.is_empty()
            || !self.last_counter_read_ok
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
        if !self.ebpf_loaded {
            reasons.push("BPF object is not loaded".to_string());
        }
        if self.attached_hooks < self.expected_hooks {
            reasons.push(format!(
                "only {} of {} expected BPF-LSM hooks are attached",
                self.attached_hooks, self.expected_hooks
            ));
        }
        for (name, status) in [
            (SelfTestName::Cgroup, self.selftests.cgroup),
            (SelfTestName::Inode, self.selftests.inode),
            (SelfTestName::Unix, self.selftests.unix),
        ] {
            if status != SelfTestStatus::Passed {
                reasons.push(format!(
                    "mandatory {} self-test is {}",
                    name.as_str(),
                    status.as_str()
                ));
            }
        }
        if !self.last_counter_read_ok {
            reasons.push("last BPF counter read failed".to_string());
        }
        if let Some(message) = self.active_degradation_message() {
            reasons.push(message.to_string());
        }

        reasons.extend(self.hook_degraded_reasons.iter().cloned());

        reasons
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
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
    let body = health_json(&health, uptime_secs);

    let code = if security_status == SecurityStatus::Unsafe {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (code, axum::Json(body)).into_response()
}

fn health_json(health: &HealthState, uptime_secs: u64) -> serde_json::Value {
    let security_status = health.security_status();
    serde_json::json!({
        "state": security_status.as_str(),
        "status": security_status.as_str(),
        "ebpf_loaded": health.ebpf_loaded,
        "expected_hooks": health.expected_hooks,
        "attached_hooks": health.attached_hooks,
        "attached": health.attached,
        "selftests": {
            "cgroup": health.selftests.cgroup.as_str(),
            "inode": health.selftests.inode.as_str(),
            "unix": health.selftests.unix.as_str(),
        },
        "zones_loaded": health.zones_loaded,
        "containers_active": health.containers_active,
        "uptime_secs": uptime_secs,
        "degraded_reasons": health.degraded_reasons(),
        "last_counter_read_ok": health.last_counter_read_ok,
        "last_counter_read_success_timestamp_seconds": health.last_counter_read_success_unix,
    })
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

    out.push_str("# HELP syva_core_up Whether syva-core is running.\n");
    out.push_str("# TYPE syva_core_up gauge\n");
    out.push_str("syva_core_up 1\n");

    out.push_str("# HELP syva_core_start_time_seconds Unix timestamp when syva-core started.\n");
    out.push_str("# TYPE syva_core_start_time_seconds gauge\n");
    out.push_str(&format!(
        "syva_core_start_time_seconds {}\n",
        health.start_time_unix
    ));

    out.push_str("# HELP syva_core_build_info Build metadata for syva-core.\n");
    out.push_str("# TYPE syva_core_build_info gauge\n");
    out.push_str(&format!(
        "syva_core_build_info{{version=\"{}\",git_sha=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION"),
        option_env!("GIT_SHA").unwrap_or("unknown")
    ));

    out.push_str("# HELP syva_ebpf_object_loaded Whether the eBPF object loaded successfully.\n");
    out.push_str("# TYPE syva_ebpf_object_loaded gauge\n");
    out.push_str(&format!(
        "syva_ebpf_object_loaded {}\n",
        if health.ebpf_loaded { 1 } else { 0 }
    ));

    out.push_str("# HELP syva_ebpf_expected_hooks Expected supported BPF-LSM hook count.\n");
    out.push_str("# TYPE syva_ebpf_expected_hooks gauge\n");
    out.push_str(&format!(
        "syva_ebpf_expected_hooks {}\n",
        health.expected_hooks
    ));

    out.push_str("# HELP syva_ebpf_attached_hooks Attached BPF-LSM hook count.\n");
    out.push_str("# TYPE syva_ebpf_attached_hooks gauge\n");
    out.push_str(&format!(
        "syva_ebpf_attached_hooks {}\n",
        health.attached_hooks
    ));

    out.push_str(
        "# HELP syva_ebpf_hook_attached Whether each supported BPF-LSM hook is attached.\n",
    );
    out.push_str("# TYPE syva_ebpf_hook_attached gauge\n");
    for (idx, hook) in crate::events::HOOK_NAMES.iter().enumerate() {
        out.push_str(&format!(
            "syva_ebpf_hook_attached{{hook=\"{}\"}} {}\n",
            hook,
            if health.attached && idx < health.attached_hooks {
                1
            } else {
                0
            }
        ));
    }

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

    out.push_str("# HELP syva_health_state Current enforcement confidence state.\n");
    out.push_str("# TYPE syva_health_state gauge\n");
    for status in [
        SecurityStatus::Healthy,
        SecurityStatus::Degraded,
        SecurityStatus::Unsafe,
    ] {
        out.push_str(&format!(
            "syva_health_state{{state=\"{}\"}} {}\n",
            status.as_str(),
            if status == current { 1 } else { 0 }
        ));
    }

    out.push_str("# HELP syva_health_degraded_reasons Active degraded or unsafe reasons.\n");
    out.push_str("# TYPE syva_health_degraded_reasons gauge\n");
    for reason in health.degraded_reasons() {
        out.push_str(&format!(
            "syva_health_degraded_reasons{{reason=\"{}\"}} 1\n",
            escape_label(&reason)
        ));
    }

    out.push_str("# HELP syva_health_last_counter_read_success_timestamp_seconds Last successful BPF counter read timestamp.\n");
    out.push_str("# TYPE syva_health_last_counter_read_success_timestamp_seconds gauge\n");
    out.push_str(&format!(
        "syva_health_last_counter_read_success_timestamp_seconds {}\n",
        health.last_counter_read_success_unix.unwrap_or(0)
    ));

    out.push_str("# HELP syva_selftest_passed Mandatory startup self-test status.\n");
    out.push_str("# TYPE syva_selftest_passed gauge\n");
    for (test, status) in [
        ("cgroup", health.selftests.cgroup),
        ("inode", health.selftests.inode),
        ("unix", health.selftests.unix),
    ] {
        out.push_str(&format!(
            "syva_selftest_passed{{test=\"{}\"}} {}\n",
            test,
            status.passed_metric()
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

    out.push_str("# HELP syva_hook_decisions_total Hook decisions by hook and decision.\n");
    out.push_str("# TYPE syva_hook_decisions_total counter\n");
    for (i, name) in hook_names.iter().enumerate() {
        let counters = health.hook_counters.get(i).cloned().unwrap_or_default();
        out.push_str(&format!(
            "syva_hook_decisions_total{{hook=\"{}\",decision=\"allow\"}} {}\n",
            name, counters.allow
        ));
        out.push_str(&format!(
            "syva_hook_decisions_total{{hook=\"{}\",decision=\"deny\"}} {}\n",
            name, counters.deny
        ));
        out.push_str(&format!(
            "syva_hook_decisions_total{{hook=\"{}\",decision=\"error\"}} {}\n",
            name, counters.error
        ));
    }

    out.push_str(
        "# HELP syva_bpf_map_errors_total BPF map operation failures observed by userspace.\n",
    );
    out.push_str("# TYPE syva_bpf_map_errors_total counter\n");
    for (operation, value) in [
        (BpfMapOperation::Read, health.bpf_map_errors.read),
        (BpfMapOperation::Update, health.bpf_map_errors.update),
        (BpfMapOperation::Delete, health.bpf_map_errors.delete),
    ] {
        out.push_str(&format!(
            "syva_bpf_map_errors_total{{operation=\"{}\",map=\"all\"}} {}\n",
            operation.as_str(),
            value
        ));
    }

    out.push_str("# HELP syva_bpf_counter_read_errors_total Failed ENFORCEMENT_COUNTERS reads.\n");
    out.push_str("# TYPE syva_bpf_counter_read_errors_total counter\n");
    out.push_str(&format!(
        "syva_bpf_counter_read_errors_total {}\n",
        health.bpf_map_errors.read
    ));

    out.push_str("# HELP syva_memberships_active Active workload memberships.\n");
    out.push_str("# TYPE syva_memberships_active gauge\n");
    out.push_str(&format!(
        "syva_memberships_active {}\n",
        health.containers_active
    ));

    out.push_str("# HELP syva_membership_updates_total Membership update outcomes.\n");
    out.push_str("# TYPE syva_membership_updates_total counter\n");
    for (result, value) in [
        (
            MembershipUpdateResult::Applied,
            health.membership_updates.applied,
        ),
        (
            MembershipUpdateResult::Unchanged,
            health.membership_updates.unchanged,
        ),
        (
            MembershipUpdateResult::Stale,
            health.membership_updates.stale,
        ),
        (
            MembershipUpdateResult::Conflict,
            health.membership_updates.conflict,
        ),
        (
            MembershipUpdateResult::Error,
            health.membership_updates.error,
        ),
    ] {
        out.push_str(&format!(
            "syva_membership_updates_total{{result=\"{}\"}} {}\n",
            result.as_str(),
            value
        ));
    }

    out.push_str("# HELP syva_membership_generation_stale_total Stale generation updates rejected or ignored.\n");
    out.push_str("# TYPE syva_membership_generation_stale_total counter\n");
    out.push_str(&format!(
        "syva_membership_generation_stale_total {}\n",
        health.membership_updates.stale
    ));

    out.push_str("# HELP syva_membership_conflicts_total Conflicting membership assignments.\n");
    out.push_str("# TYPE syva_membership_conflicts_total counter\n");
    out.push_str(&format!(
        "syva_membership_conflicts_total {}\n",
        health.membership_updates.conflict
    ));

    out
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(attached: bool, zones: usize, containers: usize) -> HealthState {
        let mut state = HealthState::new();
        state.zones_loaded = zones;
        state.containers_active = containers;
        if attached {
            state.mark_ebpf_loaded();
            state.mark_attached(crate::events::HOOK_NAMES.len());
            state.mark_selftest(SelfTestName::Cgroup, SelfTestStatus::Passed);
            state.mark_selftest(SelfTestName::Inode, SelfTestStatus::Passed);
            state.mark_selftest(SelfTestName::Unix, SelfTestStatus::Passed);
        }
        state
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
        state.update_hook_counters(vec![HookCounters {
            allow: 0,
            deny: 0,
            error: 1,
            lost: 0,
        }]);
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
        assert!(output.contains("syva_core_up 1\n"));
        assert!(output.contains("syva_ebpf_expected_hooks 6\n"));
        assert!(output.contains("syva_ebpf_attached_hooks 6\n"));
        assert!(output.contains("syva_zones_loaded 4\n"));
        assert!(output.contains("syva_containers_active 9\n"));
        assert!(output.contains("syva_security_status{status=\"healthy\"} 1"));
        assert!(output.contains("syva_health_state{state=\"healthy\"} 1"));
        assert!(output.contains("syva_selftest_passed{test=\"cgroup\"} 1"));
    }

    #[test]
    fn health_json_reports_enforcement_confidence_fields() {
        let state = make_state(true, 4, 9);
        let body = health_json(&state, 12);

        assert_eq!(body["state"], "healthy");
        assert_eq!(body["ebpf_loaded"], true);
        assert_eq!(body["expected_hooks"], 6);
        assert_eq!(body["attached_hooks"], 6);
        assert_eq!(body["selftests"]["cgroup"], "passed");
        assert_eq!(body["selftests"]["inode"], "passed");
        assert_eq!(body["selftests"]["unix"], "passed");
        assert_eq!(body["last_counter_read_ok"], true);
    }

    #[test]
    fn bpf_error_counter_moves_security_status_to_degraded() {
        let mut state = make_state(true, 4, 9);
        state.update_hook_counters(vec![HookCounters {
            allow: 0,
            deny: 0,
            error: 1,
            lost: 0,
        }]);

        assert_eq!(state.security_status(), SecurityStatus::Degraded);
        assert!(state
            .degraded_reasons()
            .iter()
            .any(|reason| reason.contains("error_delta=1")));
    }

    #[test]
    fn unchanged_error_counter_recovers_to_healthy() {
        let mut state = make_state(true, 4, 9);
        let snapshot = vec![HookCounters {
            allow: 0,
            deny: 0,
            error: 1,
            lost: 0,
        }];

        state.update_hook_counters(snapshot.clone());
        assert_eq!(state.security_status(), SecurityStatus::Degraded);

        state.update_hook_counters(snapshot);
        assert_eq!(state.security_status(), SecurityStatus::Healthy);
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
    fn transient_degradation_recovers_after_active_window() {
        let mut state = make_state(true, 4, 9);
        state.record_bpf_map_error(BpfMapOperation::Update, "BPF map update failed");

        assert_eq!(state.security_status(), SecurityStatus::Degraded);
        assert_eq!(state.bpf_map_errors.update, 1);

        state.degraded_until_unix = Some(unix_now().saturating_sub(1));

        assert_eq!(state.security_status(), SecurityStatus::Healthy);
        assert_eq!(state.bpf_map_errors.update, 1);
        assert!(state.degraded_reasons().is_empty());
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
        ];

        let output = render_metrics(&state);
        assert!(output.contains("syva_hook_allow_total{hook=\"file_open\"} 100"));
        assert!(output.contains("syva_hook_deny_total{hook=\"file_open\"} 2"));
        assert!(output.contains("syva_hook_error_total{hook=\"bprm_check_security\"} 1"));
        assert!(output.contains("syva_hook_deny_total{hook=\"unix_stream_connect\"} 0"));
        assert!(
            output.contains("syva_hook_decisions_total{hook=\"file_open\",decision=\"deny\"} 2")
        );
    }

    #[test]
    fn render_metrics_empty_counters_shows_zeros() {
        // Hook series always present so Prometheus doesn't churn on first snapshot.
        let state = make_state(false, 0, 0);
        let output = render_metrics(&state);
        assert!(output.contains("syva_hook_allow_total{hook=\"file_open\"} 0"));
        assert!(output.contains("syva_hook_deny_total{hook=\"unix_stream_connect\"} 0"));
    }

    #[test]
    fn render_metrics_represents_exactly_six_supported_hooks() {
        let state = make_state(true, 0, 0);
        let output = render_metrics(&state);

        let hook_attached_series = output
            .lines()
            .filter(|line| line.starts_with("syva_ebpf_hook_attached{hook="))
            .count();
        assert_eq!(hook_attached_series, 6);
        for hook in crate::events::HOOK_NAMES {
            assert!(output.contains(&format!("syva_ebpf_hook_attached{{hook=\"{hook}\"}} 1")));
        }
    }

    #[test]
    fn render_metrics_down_when_not_attached() {
        let state = make_state(false, 0, 0);
        let output = render_metrics(&state);
        assert!(output.contains("syva_up 0\n"));
        assert!(output.contains("syva_health_state{state=\"unsafe\"} 1"));
    }

    #[test]
    fn missing_selftest_is_unsafe() {
        let mut state = HealthState::new();
        state.mark_ebpf_loaded();
        state.mark_attached(crate::events::HOOK_NAMES.len());
        state.mark_selftest(SelfTestName::Cgroup, SelfTestStatus::Passed);
        state.mark_selftest(SelfTestName::Inode, SelfTestStatus::Passed);

        assert_eq!(state.security_status(), SecurityStatus::Unsafe);
        assert!(state
            .degraded_reasons()
            .iter()
            .any(|reason| reason.contains("unix self-test")));
    }

    #[test]
    fn counter_read_failure_degrades_health_and_metrics() {
        let mut state = make_state(true, 1, 1);
        state.mark_counter_read_failed("counter read failed");

        assert_eq!(state.security_status(), SecurityStatus::Degraded);
        let output = render_metrics(&state);
        assert!(output.contains("syva_bpf_counter_read_errors_total 1"));
        assert!(output.contains("syva_health_state{state=\"degraded\"} 1"));
    }

    #[test]
    fn membership_metrics_render_outcomes() {
        let mut state = make_state(true, 1, 1);
        state.record_membership_update(MembershipUpdateResult::Applied);
        state.record_membership_update(MembershipUpdateResult::Stale);
        state.record_membership_update(MembershipUpdateResult::Conflict);

        let output = render_metrics(&state);
        assert!(output.contains("syva_membership_updates_total{result=\"applied\"} 1"));
        assert!(output.contains("syva_membership_generation_stale_total 1"));
        assert!(output.contains("syva_membership_conflicts_total 1"));
    }
}
