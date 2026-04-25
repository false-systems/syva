//! CP-mode reconciler.
//!
//! When syva-core runs with `--cp-endpoint`, this module drives the
//! assignment-to-BPF loop:
//!
//! 1. Receive a `NodeAssignmentUpdate` from syva-cp
//! 2. Diff against the last applied state
//! 3. Reuse the same registry/BPF mutation helpers as the former local gRPC path
//! 4. Report applied or failed status back to syva-cp

pub mod state;

use crate::ebpf::EnforceEbpf;
use crate::health::SharedHealth;
use crate::ingest::{
    allow_comm_local, deny_comm_local, register_zone_local, remove_zone_local, CoreZonePolicyInput,
};
use crate::types::ZoneType;
use crate::zone::ZoneRegistry;
use serde::Deserialize;
use state::AppliedState;
use std::sync::Arc;
use syva_cp_client::{
    AppliedReport, CpClient, FailedReport, NodeAssignmentUpdate, ZoneAssignment,
};
use syva_proto::syva_control::v1::node_assignment_update::Kind as UpdateKind;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

pub struct Reconciler {
    cp: CpClient,
    registry: Arc<RwLock<ZoneRegistry>>,
    ebpf: Arc<Mutex<EnforceEbpf>>,
    health: SharedHealth,
    applied: Arc<Mutex<AppliedState>>,
}

impl Reconciler {
    pub fn new(
        cp: CpClient,
        registry: Arc<RwLock<ZoneRegistry>>,
        ebpf: Arc<Mutex<EnforceEbpf>>,
        health: SharedHealth,
    ) -> Self {
        Self {
            cp,
            registry,
            ebpf,
            health,
            applied: Arc::new(Mutex::new(AppliedState::new())),
        }
    }

    pub async fn run(self) {
        let mut backoff_ms = 250_u64;
        let max_backoff_ms = 30_000_u64;

        loop {
            match self.run_once().await {
                Ok(()) => {
                    info!("reconcile stream closed by server, reconnecting");
                    backoff_ms = 250;
                }
                Err(error) => {
                    warn!("reconcile stream error: {error}; reconnecting in {backoff_ms}ms");
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(max_backoff_ms);
                }
            }
        }
    }

    async fn run_once(&self) -> anyhow::Result<()> {
        let mut stream = self.cp.subscribe_assignments().await?;

        while let Some(update) = stream.message().await? {
            self.handle_update(update).await;
        }

        Ok(())
    }

    async fn handle_update(&self, update: NodeAssignmentUpdate) {
        let kind = UpdateKind::try_from(update.kind).unwrap_or(UpdateKind::FullSnapshot);

        match kind {
            UpdateKind::FullSnapshot => self.apply_full_snapshot(update.assignments).await,
            UpdateKind::Upsert => self.apply_upserts(update.assignments).await,
            UpdateKind::Remove => self.apply_remove(&update.removed_zone_id).await,
        }
    }

    async fn apply_full_snapshot(&self, desired: Vec<ZoneAssignment>) {
        info!("applying FULL_SNAPSHOT with {} assignments", desired.len());

        let (to_apply, to_remove) = {
            let applied = self.applied.lock().await;
            applied.diff_against_snapshot(&desired)
        };

        self.apply_upserts(to_apply).await;
        for zone_id in to_remove {
            self.apply_remove(&zone_id).await;
        }
    }

    async fn apply_upserts(&self, assignments: Vec<ZoneAssignment>) {
        let mut applied_reports = Vec::new();
        let mut failed_reports = Vec::new();

        for assignment in assignments {
            match self.apply_one_upsert(&assignment).await {
                Ok(policy) => {
                    let assignment_id = match Uuid::parse_str(&assignment.assignment_id) {
                        Ok(value) => value,
                        Err(error) => {
                            error!(
                                assignment_id = %assignment.assignment_id,
                                error = %error,
                                "bad assignment_id from control plane"
                            );
                            continue;
                        }
                    };

                    let desired_policy_id = match Uuid::parse_str(&assignment.desired_policy_id) {
                            Ok(value) => value,
                            Err(error) => {
                                error!(
                                    assignment_id = %assignment.assignment_id,
                                    error = %error,
                                    "bad desired_policy_id from control plane"
                                );
                                continue;
                            }
                        };

                    {
                        let mut applied = self.applied.lock().await;
                        applied.record_applied_policy(
                            &assignment,
                            policy.allowed_zones.iter().cloned(),
                        );
                    }

                    applied_reports.push(AppliedReport {
                        assignment_id,
                        actual_zone_version: assignment.desired_zone_version,
                        actual_policy_id: desired_policy_id,
                    });
                }
                Err(error) => {
                    error!(zone_id = %assignment.zone_id, error = %error, "apply failed");

                    if let Ok(assignment_id) = Uuid::parse_str(&assignment.assignment_id) {
                        failed_reports.push(FailedReport {
                            assignment_id,
                            error_json: serde_json::json!({
                                "message": error.to_string(),
                                "zone_id": assignment.zone_id,
                            }),
                        });
                    }
                }
            }
        }

        self.sync_allowed_comms().await;

        if !applied_reports.is_empty() || !failed_reports.is_empty() {
            if let Err(error) = self
                .cp
                .report_assignment_state(applied_reports, failed_reports)
                .await
            {
                warn!("report_assignment_state failed: {error}");
            }
        }
    }

    async fn apply_remove(&self, zone_id_str: &str) {
        let zone_id = match Uuid::parse_str(zone_id_str) {
            Ok(value) => value,
            Err(_) => {
                warn!("remove with invalid zone_id: {zone_id_str}");
                return;
            }
        };

        let zone_name = {
            let applied = self.applied.lock().await;
            applied.zone_name_for(&zone_id)
        };
        let Some(zone_name) = zone_name else {
            debug!(zone_id = %zone_id, "remove for unknown zone ignored");
            return;
        };

        match remove_zone_local(
            &self.registry,
            &self.ebpf,
            &self.health,
            &zone_name,
            true,
        )
        .await
        {
            Ok(result) if result.ok && result.fully_removed => {
                {
                    let mut applied = self.applied.lock().await;
                    applied.record_removed(&zone_id);
                }
                self.sync_allowed_comms().await;
                info!(zone_name, "zone removed");
            }
            Ok(result) if result.ok => {
                info!(zone_name, "zone draining");
            }
            Ok(result) => {
                warn!(zone_name, message = result.message, "zone remove rejected");
            }
            Err(error) => {
                warn!(zone_name, error = %error, "zone remove failed");
            }
        }
    }

    async fn apply_one_upsert(
        &self,
        assignment: &ZoneAssignment,
    ) -> Result<CoreZonePolicyInput, anyhow::Error> {
        let policy = parse_policy_json(&assignment.policy_json)?;

        register_zone_local(
            &self.registry,
            &self.ebpf,
            &self.health,
            &assignment.zone_name,
            Some(policy.clone()),
        )
        .await
        .map_err(|error| anyhow::anyhow!("registry/BPF apply failed: {error}"))?;

        Ok(policy)
    }

    async fn sync_allowed_comms(&self) {
        let (to_allow, to_deny) = {
            let applied = self.applied.lock().await;
            applied.diff_comm_pairs()
        };

        for (zone_a, zone_b) in to_deny {
            match deny_comm_local(&self.registry, &self.ebpf, &zone_a, &zone_b).await {
                Ok(()) => {
                    let mut applied = self.applied.lock().await;
                    applied.record_denied_pair(&zone_a, &zone_b);
                }
                Err(error) => {
                    warn!(zone_a, zone_b, error = %error, "failed to deny comm pair");
                }
            }
        }

        for (zone_a, zone_b) in to_allow {
            match allow_comm_local(&self.registry, &self.ebpf, &zone_a, &zone_b).await {
                Ok(()) => {
                    let mut applied = self.applied.lock().await;
                    applied.record_allowed_pair(&zone_a, &zone_b);
                }
                Err(error) => {
                    warn!(zone_a, zone_b, error = %error, "failed to allow comm pair");
                }
            }
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct CompactPolicy {
    #[serde(default)]
    host_paths: Vec<String>,
    #[serde(default)]
    allowed_zones: Vec<String>,
    #[serde(default)]
    allow_ptrace: bool,
    #[serde(default)]
    zone_type: Option<String>,
}

fn parse_policy_json(policy_json: &str) -> Result<CoreZonePolicyInput, anyhow::Error> {
    if let Ok(full_policy) = serde_json::from_str::<crate::types::ZonePolicy>(policy_json) {
        return Ok(CoreZonePolicyInput {
            host_paths: full_policy.filesystem.host_paths,
            allowed_zones: full_policy.network.allowed_zones,
            allow_ptrace: full_policy
                .capabilities
                .allowed
                .iter()
                .any(|capability| capability == "CAP_SYS_PTRACE"),
            zone_type: ZoneType::NonGlobal,
        });
    }

    let compact = serde_json::from_str::<CompactPolicy>(policy_json)
        .map_err(|error| anyhow::anyhow!("policy parse: {error}"))?;
    let zone_type = match compact.zone_type.as_deref() {
        Some("privileged") => ZoneType::Privileged,
        _ => ZoneType::NonGlobal,
    };

    Ok(CoreZonePolicyInput {
        host_paths: compact.host_paths,
        allowed_zones: compact.allowed_zones,
        allow_ptrace: compact.allow_ptrace,
        zone_type,
    })
}
