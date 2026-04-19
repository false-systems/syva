//! Metrics setup. ADR 0003 Rule 10: transaction duration is a monitored SLO.
//!
//! `init()` installs the Prometheus recorder globally and returns a
//! handle that the /metrics HTTP endpoint renders on demand.

use anyhow::Result;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::time::Duration;

pub fn init() -> Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("metrics init failed: {e}"))?;

    // Describe metrics up front so they appear in `/metrics` output even
    // before the first observation — otherwise scrapers see gaps at boot.
    metrics::describe_histogram!(
        "syva_cp_transaction_duration_seconds",
        "Duration of write transactions in syva-cp, labeled by operation"
    );
    metrics::describe_counter!(
        "syva_cp_transaction_rollback_total",
        "Count of rolled-back transactions, labeled by operation and reason"
    );
    metrics::describe_counter!(
        "syva_cp_grpc_requests_total",
        "Total gRPC requests received, labeled by service and method"
    );

    Ok(handle)
}

pub fn record_transaction_duration(operation: &'static str, duration: Duration) {
    metrics::histogram!(
        "syva_cp_transaction_duration_seconds",
        "operation" => operation
    )
    .record(duration.as_secs_f64());
}

pub fn record_transaction_rollback(operation: &'static str, reason: &'static str) {
    metrics::counter!(
        "syva_cp_transaction_rollback_total",
        "operation" => operation,
        "reason" => reason
    )
    .increment(1);
}
