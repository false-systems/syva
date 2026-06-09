use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Router};

#[derive(Clone, Default)]
pub(crate) struct Metrics {
    inner: Arc<MetricsInner>,
}

#[derive(Default)]
struct MetricsInner {
    active_memberships: AtomicU64,
    attach: LabelCounters,
    detach: LabelCounters,
    errors: LabelCounters,
}

#[derive(Default)]
struct LabelCounters {
    values: std::sync::Mutex<BTreeMap<&'static str, u64>>,
}

impl Metrics {
    pub(crate) fn record_attach(&self, result: &'static str) {
        self.inner.attach.inc(result);
    }

    pub(crate) fn record_detach(&self, result: &'static str) {
        self.inner.detach.inc(result);
    }

    pub(crate) fn record_error(&self, reason: &'static str) {
        self.inner.errors.inc(reason);
    }

    pub(crate) fn set_active_memberships(&self, count: usize) {
        self.inner
            .active_memberships
            .store(count as u64, Ordering::Relaxed);
    }

    fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP syva_k8s_membership_attach_total Kubernetes membership attach attempts by result.\n");
        out.push_str("# TYPE syva_k8s_membership_attach_total counter\n");
        self.inner
            .attach
            .render("syva_k8s_membership_attach_total", "result", &mut out);

        out.push_str("# HELP syva_k8s_membership_detach_total Kubernetes membership detach attempts by result.\n");
        out.push_str("# TYPE syva_k8s_membership_detach_total counter\n");
        self.inner
            .detach
            .render("syva_k8s_membership_detach_total", "result", &mut out);

        out.push_str(
            "# HELP syva_k8s_memberships_active Active pod/container memberships tracked by syva-k8s.\n",
        );
        out.push_str("# TYPE syva_k8s_memberships_active gauge\n");
        out.push_str(&format!(
            "syva_k8s_memberships_active {}\n",
            self.inner.active_memberships.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP syva_k8s_reconcile_errors_total Kubernetes membership reconcile errors by reason.\n");
        out.push_str("# TYPE syva_k8s_reconcile_errors_total counter\n");
        self.inner
            .errors
            .render("syva_k8s_reconcile_errors_total", "reason", &mut out);
        out
    }
}

impl LabelCounters {
    fn inc(&self, label: &'static str) {
        let mut values = self.values.lock().expect("metrics lock poisoned");
        *values.entry(label).or_insert(0) += 1;
    }

    fn render(&self, metric: &str, label_name: &str, out: &mut String) {
        let values = self.values.lock().expect("metrics lock poisoned");
        for (label, value) in values.iter() {
            out.push_str(&format!("{metric}{{{label_name}=\"{label}\"}} {value}\n"));
        }
    }
}

pub(crate) async fn spawn_metrics_server(
    listen: SocketAddr,
    metrics: Metrics,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(metrics);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            tracing::warn!(%error, "syva-k8s metrics server stopped");
        }
    });
    Ok(())
}

async fn metrics_handler(State(metrics): State<Metrics>) -> impl IntoResponse {
    metrics.render()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_required_metric_names() {
        let metrics = Metrics::default();
        metrics.record_attach("applied");
        metrics.record_detach("applied");
        metrics.record_error("cgroup_resolution");
        metrics.set_active_memberships(1);

        let rendered = metrics.render();
        assert!(rendered.contains("syva_k8s_membership_attach_total{result=\"applied\"} 1"));
        assert!(rendered.contains("syva_k8s_membership_detach_total{result=\"applied\"} 1"));
        assert!(rendered.contains("syva_k8s_memberships_active 1"));
        assert!(
            rendered.contains("syva_k8s_reconcile_errors_total{reason=\"cgroup_resolution\"} 1")
        );
    }
}
