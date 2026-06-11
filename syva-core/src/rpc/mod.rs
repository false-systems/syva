//! gRPC service implementation for syva-core.

use std::collections::HashSet;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use syva_ebpf_common::{EnforcementEvent, DECISION_DENY, DECISION_ESCAPE, DECISION_WOULD_DENY};
use syva_proto::syva_core::syva_core_server::SyvaCore;
use syva_proto::syva_core::{
    AllowCommRequest, AllowCommResponse, AttachContainerRequest, AttachContainerResponse, CommPair,
    DenyCommRequest, DenyCommResponse, DenyEvent, DetachContainerRequest, DetachContainerResponse,
    HookStatus, ListCommsRequest, ListCommsResponse, ListZonesRequest, ListZonesResponse,
    RegisterHostPathRequest, RegisterHostPathResponse, RegisterZoneRequest, RegisterZoneResponse,
    RemoveZoneRequest, RemoveZoneResponse, StatusRequest, StatusResponse, WatchEventsRequest,
    ZoneSummary,
};
use tokio::sync::{Mutex, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::container_id::is_valid_container_id;
use crate::ebpf::EnforceEbpf;
use crate::events::HOOK_NAMES;
use crate::health::{BpfMapOperation, MembershipUpdateResult, SharedHealth};
use crate::ingest::{self, CoreZonePolicyInput};
use crate::membership::{
    BpfMembershipIntent, MembershipObservation, MembershipOutcome, MembershipService,
    MembershipSource, PodIdentity,
};
use crate::types::ZoneType;
use crate::zone::{ZoneRegistry, ZoneState, ZoneTransition};

const CONTAINER_UPDATE_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct SyvaCoreService {
    pub(crate) registry: Arc<RwLock<ZoneRegistry>>,
    pub(crate) memberships: Arc<RwLock<MembershipService>>,
    pub(crate) container_updates: Arc<StdMutex<HashSet<String>>>,
    pub(crate) ebpf: Arc<Mutex<EnforceEbpf>>,
    pub(crate) health: SharedHealth,
    pub(crate) start_time: Instant,
}

impl SyvaCoreService {
    /// Return NotFound for the first zone that is not registered. Used by the
    /// comm RPCs so an unknown zone is a client error, leaving any later ingest
    /// failure as a genuine Internal (BPF/core) error.
    #[allow(clippy::result_large_err)]
    async fn ensure_zones_registered(&self, zone_a: &str, zone_b: &str) -> Result<(), Status> {
        let registry = self.registry.read().await;
        for zone in [zone_a, zone_b] {
            if registry.zone_id(zone).is_none() {
                return Err(Status::not_found(format!("zone '{zone}' not registered")));
            }
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl SyvaCore for SyvaCoreService {
    async fn register_zone(
        &self,
        request: Request<RegisterZoneRequest>,
    ) -> Result<Response<RegisterZoneResponse>, Status> {
        let req = request.into_inner();
        validate_zone_name(&req.zone_name)?;

        let policy = req.policy.map(proto_policy_to_core_input).transpose()?;

        let zone_id = ingest::register_zone_local(
            &self.registry,
            &self.ebpf,
            &self.health,
            &req.zone_name,
            policy,
        )
        .await
        .map_err(|error| Status::internal(format!("failed to register zone: {error}")))?;

        tracing::info!(zone = req.zone_name, zone_id, "zone registered via gRPC");
        Ok(Response::new(RegisterZoneResponse { zone_id }))
    }

    async fn remove_zone(
        &self,
        request: Request<RemoveZoneRequest>,
    ) -> Result<Response<RemoveZoneResponse>, Status> {
        let req = request.into_inner();
        validate_zone_name(&req.zone_name)?;

        let result = ingest::remove_zone_local(
            &self.registry,
            &self.ebpf,
            &self.health,
            &req.zone_name,
            req.drain,
        )
        .await
        .map_err(|error| Status::not_found(format!("{error}")))?;

        Ok(Response::new(RemoveZoneResponse {
            ok: result.ok,
            message: result.message,
        }))
    }

    async fn list_zones(
        &self,
        _request: Request<ListZonesRequest>,
    ) -> Result<Response<ListZonesResponse>, Status> {
        let registry = self.registry.read().await;
        let zones = registry
            .zones_summary()
            .map(|(name, zone_id, state, refcount)| ZoneSummary {
                name: name.to_string(),
                zone_id,
                state: match state {
                    ZoneState::Pending => "pending",
                    ZoneState::Active => "active",
                    ZoneState::Draining => "draining",
                }
                .to_string(),
                containers_active: refcount as u32,
            })
            .collect();
        Ok(Response::new(ListZonesResponse { zones }))
    }

    async fn attach_container(
        &self,
        request: Request<AttachContainerRequest>,
    ) -> Result<Response<AttachContainerResponse>, Status> {
        let req = request.into_inner();

        if !is_valid_container_id(&req.container_id) {
            return Ok(Response::new(AttachContainerResponse {
                ok: false,
                message: "invalid container_id: must be non-empty, max 128 chars, hex/dash/underscore only".to_string(),
            }));
        }
        validate_zone_name(&req.zone_name)?;
        if req.cgroup_id == 0 {
            return Err(Status::invalid_argument("cgroup_id must be non-zero"));
        }
        let _container_guard =
            acquire_container_update(&self.container_updates, &req.container_id).await?;

        let (zone_id, zone_type) = {
            let registry = self.registry.read().await;
            let Some(zone_id) = registry.zone_id(&req.zone_name) else {
                self.health
                    .write()
                    .await
                    .record_membership_update(MembershipUpdateResult::Error);
                tracing::warn!(
                    event = "syva.membership.attach",
                    component = "syva-core",
                    container_id = %req.container_id,
                    cgroup_id = req.cgroup_id,
                    zone = %req.zone_name,
                    generation = req.generation,
                    result = "error",
                    "container attach requested for unregistered zone"
                );
                return Ok(Response::new(AttachContainerResponse {
                    ok: false,
                    message: format!("zone '{}' is not registered", req.zone_name),
                }));
            };
            let zone_type = registry
                .zone_type(&req.zone_name)
                .unwrap_or(ZoneType::NonGlobal);
            (zone_id, zone_type)
        };

        let observation = attach_request_to_observation(&req);
        let membership_outcome = {
            let mut memberships = self.memberships.write().await;
            memberships.observe_upsert(observation, zone_id, zone_type)
        };

        let intent = match membership_outcome {
            MembershipOutcome::Applied { intent } => {
                let mut registry = self.registry.write().await;
                if let Err(error) =
                    registry.add_container(&req.container_id, &req.zone_name, req.cgroup_id)
                {
                    self.memberships
                        .write()
                        .await
                        .remove(&req.container_id, None);
                    return Ok(Response::new(AttachContainerResponse {
                        ok: false,
                        message: format!("{error}"),
                    }));
                }
                intent
            }
            MembershipOutcome::Unchanged { .. } => {
                let registry = self.registry.read().await;
                let mut health = self.health.write().await;
                health.containers_active = registry.container_count();
                health.record_membership_update(MembershipUpdateResult::Unchanged);

                tracing::info!(
                    event = "syva.membership.attach",
                    component = "syva-core",
                    container_id = %req.container_id,
                    zone = %req.zone_name,
                    zone_id,
                    cgroup_id = req.cgroup_id,
                    generation = req.generation,
                    result = "unchanged",
                    "container membership refreshed via gRPC"
                );

                return Ok(Response::new(AttachContainerResponse {
                    ok: true,
                    message: String::new(),
                }));
            }
            MembershipOutcome::Stale {
                existing_generation,
            } => {
                let mut health = self.health.write().await;
                health.record_membership_update(MembershipUpdateResult::Stale);
                health.mark_membership_degraded(format!(
                    "stale membership update ignored for container '{}' (existing generation {})",
                    req.container_id, existing_generation
                ));
                tracing::warn!(
                    event = "syva.membership.stale",
                    component = "syva-core",
                    container_id = %req.container_id,
                    cgroup_id = req.cgroup_id,
                    zone = %req.zone_name,
                    generation = req.generation,
                    existing_generation,
                    result = "stale",
                    "stale container membership update ignored"
                );
                return Ok(Response::new(AttachContainerResponse {
                    ok: false,
                    message: format!(
                        "stale membership update ignored; existing generation is {existing_generation}"
                    ),
                }));
            }
            MembershipOutcome::Conflict {
                existing_zone,
                requested_zone,
                ..
            } => {
                let mut health = self.health.write().await;
                health.record_membership_update(MembershipUpdateResult::Conflict);
                health.mark_membership_degraded(format!(
                        "conflicting membership for container '{}': existing zone '{}', requested zone '{}'",
                        req.container_id, existing_zone, requested_zone
                    ));
                tracing::warn!(
                    event = "syva.membership.conflict",
                    component = "syva-core",
                    container_id = %req.container_id,
                    cgroup_id = req.cgroup_id,
                    zone = %requested_zone,
                    existing_zone = %existing_zone,
                    generation = req.generation,
                    result = "conflict",
                    "conflicting container membership update rejected"
                );
                return Ok(Response::new(AttachContainerResponse {
                    ok: false,
                    message: format!(
                        "conflicting membership: existing zone '{existing_zone}', requested zone '{requested_zone}'"
                    ),
                }));
            }
            MembershipOutcome::Removed { .. } | MembershipOutcome::NotFound => {
                return Err(Status::internal("unexpected membership outcome"));
            }
        };

        let mut ebpf = self.ebpf.lock().await;
        if let BpfMembershipIntent::Add {
            cgroup_id,
            zone_id,
            zone_type,
        } = intent
        {
            if let Err(error) = ebpf.add_zone_member(cgroup_id, zone_id, zone_type) {
                self.registry
                    .write()
                    .await
                    .remove_container(&req.container_id, None);
                self.memberships
                    .write()
                    .await
                    .remove(&req.container_id, None);
                let mut health = self.health.write().await;
                health.record_membership_update(MembershipUpdateResult::Error);
                health.record_bpf_map_error(
                    BpfMapOperation::Update,
                    format!(
                        "BPF membership add failed for container '{}': {error}",
                        req.container_id
                    ),
                );
                tracing::error!(
                    event = "syva.membership.attach",
                    component = "syva-core",
                    container_id = %req.container_id,
                    cgroup_id,
                    zone = %req.zone_name,
                    generation = req.generation,
                    result = "error",
                    %error,
                    "BPF membership update failed"
                );
                return Err(Status::internal(format!(
                    "BPF add_zone_member failed: {error}"
                )));
            }
        } else {
            return Err(Status::internal(
                "unexpected BPF membership intent for attach",
            ));
        }
        self.memberships
            .write()
            .await
            .mark_applied(&req.container_id);

        let registry = self.registry.read().await;
        let mut health = self.health.write().await;
        health.containers_active = registry.container_count();
        health.record_membership_update(MembershipUpdateResult::Applied);

        tracing::info!(
            event = "syva.membership.attach",
            component = "syva-core",
            container_id = %req.container_id,
            zone = %req.zone_name,
            zone_id,
            cgroup_id = req.cgroup_id,
            generation = req.generation,
            result = "applied",
            "container attached via gRPC"
        );

        Ok(Response::new(AttachContainerResponse {
            ok: true,
            message: String::new(),
        }))
    }

    async fn detach_container(
        &self,
        request: Request<DetachContainerRequest>,
    ) -> Result<Response<DetachContainerResponse>, Status> {
        let req = request.into_inner();
        if req.container_id.is_empty() {
            return Err(Status::invalid_argument("container_id is required"));
        }
        let _container_guard =
            acquire_container_update(&self.container_updates, &req.container_id).await?;

        let generation = if req.generation == 0 {
            None
        } else {
            Some(req.generation)
        };
        let membership_outcome = self
            .memberships
            .write()
            .await
            .remove(&req.container_id, generation);
        match membership_outcome {
            MembershipOutcome::Stale {
                existing_generation,
            } => {
                let message =
                    format!("stale detach ignored; existing generation is {existing_generation}");
                let mut health = self.health.write().await;
                health.record_membership_update(MembershipUpdateResult::Stale);
                health.mark_membership_degraded(format!(
                    "stale detach ignored for container '{}' (existing generation {})",
                    req.container_id, existing_generation
                ));
                tracing::warn!(
                    event = "syva.membership.stale",
                    component = "syva-core",
                    container_id = %req.container_id,
                    generation = req.generation,
                    existing_generation,
                    result = "stale",
                    "stale container detach ignored"
                );
                return Ok(Response::new(DetachContainerResponse {
                    ok: false,
                    message,
                }));
            }
            MembershipOutcome::Removed { .. } => {}
            MembershipOutcome::NotFound => {
                self.health
                    .write()
                    .await
                    .record_membership_update(MembershipUpdateResult::Unchanged);
                tracing::info!(
                    event = "syva.membership.detach",
                    component = "syva-core",
                    container_id = %req.container_id,
                    generation = req.generation,
                    result = "unchanged",
                    "container detach requested for unknown membership"
                );
            }
            MembershipOutcome::Applied { .. }
            | MembershipOutcome::Unchanged { .. }
            | MembershipOutcome::Conflict { .. } => {
                return Err(Status::internal("unexpected membership outcome"));
            }
        }

        let mut registry = self.registry.write().await;
        if let Some((zone_id, cgroup_id, transition)) =
            registry.remove_container(&req.container_id, None)
        {
            let mut ebpf = self.ebpf.lock().await;
            if let Err(error) = ebpf.remove_zone_member(cgroup_id) {
                tracing::warn!(cgroup_id, %error, "failed to remove zone member from BPF map");
                let mut health = self.health.write().await;
                health.record_membership_update(MembershipUpdateResult::Error);
                health.record_bpf_map_error(
                    BpfMapOperation::Delete,
                    format!(
                        "BPF membership remove failed for container '{}': {error}",
                        req.container_id
                    ),
                );
            }

            match transition {
                ZoneTransition::DrainingComplete => {
                    tracing::info!(zone_id, "draining zone emptied; cleaning up BPF maps");
                    let _ = ebpf.remove_zone_policy(zone_id);
                    let _ = ebpf.remove_zone_comms(zone_id);
                    let _ = ebpf.remove_zone_inodes(zone_id);
                    if let Err(error) = registry.unregister_zone_by_id(zone_id) {
                        tracing::warn!(zone_id, %error, "failed to unregister drained zone");
                    }
                }
                ZoneTransition::WentToPending => {
                    tracing::info!(zone_id, "zone has no active containers");
                }
                ZoneTransition::StillActive => {}
            }

            let mut health = self.health.write().await;
            health.containers_active = registry.container_count();
            health.zones_loaded = registry.zone_count();
            health.record_membership_update(MembershipUpdateResult::Applied);

            tracing::info!(
                event = "syva.membership.detach",
                component = "syva-core",
                container_id = %req.container_id,
                cgroup_id,
                generation = req.generation,
                result = "applied",
                "container detached via gRPC"
            );
        }

        Ok(Response::new(DetachContainerResponse {
            ok: true,
            message: String::new(),
        }))
    }

    async fn allow_comm(
        &self,
        request: Request<AllowCommRequest>,
    ) -> Result<Response<AllowCommResponse>, Status> {
        let req = request.into_inner();
        if req.zone_a.is_empty() || req.zone_b.is_empty() {
            return Err(Status::invalid_argument(
                "both zone_a and zone_b are required",
            ));
        }
        if req.zone_a == req.zone_b {
            tracing::debug!(
                zone = req.zone_a,
                "same-zone AllowComm is an idempotent no-op"
            );
            return Ok(Response::new(AllowCommResponse { ok: true }));
        }
        // Resolve unknown zones to NotFound here so the ingest error below can
        // only be a BPF/core failure, which is Internal (and degraded security)
        // rather than a client mistake.
        self.ensure_zones_registered(&req.zone_a, &req.zone_b)
            .await?;

        if let Err(error) =
            ingest::allow_comm_local(&self.registry, &self.ebpf, &req.zone_a, &req.zone_b).await
        {
            self.health.write().await.record_bpf_map_error(
                BpfMapOperation::Update,
                format!(
                    "BPF allowed comms update failed for zones '{}' and '{}': {error}",
                    req.zone_a, req.zone_b
                ),
            );
            return Err(Status::internal(format!(
                "failed to set allowed comms: {error}"
            )));
        }

        tracing::info!(
            zone_a = req.zone_a,
            zone_b = req.zone_b,
            "cross-zone comm allowed via gRPC"
        );
        Ok(Response::new(AllowCommResponse { ok: true }))
    }

    async fn deny_comm(
        &self,
        request: Request<DenyCommRequest>,
    ) -> Result<Response<DenyCommResponse>, Status> {
        let req = request.into_inner();
        if req.zone_a.is_empty() || req.zone_b.is_empty() {
            return Err(Status::invalid_argument(
                "both zone_a and zone_b are required",
            ));
        }
        // Same split as allow_comm: unknown zones are NotFound, a failing ingest
        // is an Internal BPF/core error.
        self.ensure_zones_registered(&req.zone_a, &req.zone_b)
            .await?;

        if let Err(error) =
            ingest::deny_comm_local(&self.registry, &self.ebpf, &req.zone_a, &req.zone_b).await
        {
            self.health.write().await.record_bpf_map_error(
                BpfMapOperation::Delete,
                format!(
                    "BPF allowed comms delete failed for zones '{}' and '{}': {error}",
                    req.zone_a, req.zone_b
                ),
            );
            return Err(Status::internal(format!(
                "failed to remove comms between '{}' and '{}': {error}",
                req.zone_a, req.zone_b
            )));
        }

        tracing::info!(
            zone_a = req.zone_a,
            zone_b = req.zone_b,
            "cross-zone comm denied via gRPC"
        );
        Ok(Response::new(DenyCommResponse { ok: true }))
    }

    async fn list_comms(
        &self,
        request: Request<ListCommsRequest>,
    ) -> Result<Response<ListCommsResponse>, Status> {
        let req = request.into_inner();
        let filter = if req.zone_name.is_empty() {
            None
        } else {
            Some(req.zone_name.as_str())
        };

        let registry = self.registry.read().await;
        if let Some(zone) = filter {
            if registry.zone_id(zone).is_none() {
                return Err(Status::not_found(format!("zone '{zone}' not registered")));
            }
        }

        let pairs = registry
            .list_allowed_comms(filter)
            .map(|(zone_a, zone_b)| CommPair {
                zone_a: zone_a.to_string(),
                zone_b: zone_b.to_string(),
            })
            .collect();
        Ok(Response::new(ListCommsResponse { pairs }))
    }

    async fn register_host_path(
        &self,
        request: Request<RegisterHostPathRequest>,
    ) -> Result<Response<RegisterHostPathResponse>, Status> {
        let req = request.into_inner();
        if req.zone_name.is_empty() {
            return Err(Status::invalid_argument("zone_name is required"));
        }
        if req.path.is_empty() {
            return Err(Status::invalid_argument("path is required"));
        }

        let registry = self.registry.read().await;
        let zone_id = registry
            .zone_id(&req.zone_name)
            .ok_or_else(|| Status::not_found(format!("zone '{}' not registered", req.zone_name)))?;
        drop(registry);

        let mut ebpf = self.ebpf.lock().await;
        let count_result = if req.recursive {
            ebpf.populate_inode_zone_map(zone_id, std::slice::from_ref(&req.path))
        } else {
            ebpf.register_single_inode(zone_id, &req.path)
        };
        let count = match count_result {
            Ok(count) => count,
            Err(error) => {
                self.health.write().await.record_bpf_map_error(
                    BpfMapOperation::Update,
                    format!(
                        "BPF inode map update failed for zone '{}' path '{}': {error}",
                        req.zone_name, req.path
                    ),
                );
                return Err(Status::internal(format!(
                    "failed to register host path: {error}"
                )));
            }
        };

        tracing::info!(
            zone = req.zone_name,
            path = req.path,
            inodes = count,
            "host path registered via gRPC"
        );

        Ok(Response::new(RegisterHostPathResponse {
            inodes_registered: count as u32,
        }))
    }

    async fn status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let (attached, uptime_secs) = {
            let health = self.health.read().await;
            (health.attached, self.start_time.elapsed().as_secs())
        };
        let mut hooks = Vec::new();
        let ebpf = self.ebpf.lock().await;
        match ebpf.read_counters() {
            Ok(counters) => {
                for (idx, (_, totals)) in counters.iter().enumerate() {
                    hooks.push(HookStatus {
                        hook: HOOK_NAMES
                            .get(idx)
                            .copied()
                            .unwrap_or("unknown")
                            .to_string(),
                        allow: totals.allow,
                        deny: totals.deny,
                        error: totals.error,
                        lost: totals.lost,
                    });
                }
            }
            Err(error) => {
                tracing::warn!(
                    event = "syva.health.degraded",
                    component = "syva-core",
                    reason = "bpf_map_read_error",
                    previous_state = "healthy",
                    new_state = "degraded",
                    %error,
                    "failed to read counters for status RPC"
                );
                self.health
                    .write()
                    .await
                    .mark_counter_read_failed(format!("BPF counter read failed: {error}"));
            }
        }
        let registry = self.registry.read().await;

        Ok(Response::new(StatusResponse {
            attached,
            zones_active: registry.zone_count() as u32,
            containers_active: registry.container_count() as u32,
            uptime_secs,
            hooks,
            max_zones: syva_ebpf_common::MAX_ZONES,
        }))
    }

    type WatchEventsStream = ReceiverStream<Result<DenyEvent, Status>>;

    async fn watch_events(
        &self,
        request: Request<WatchEventsRequest>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        let req = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(256);

        let mut ebpf = self.ebpf.lock().await;
        let ring_buf = ebpf
            .take_event_ring_buf()
            .ok_or_else(|| Status::unavailable("event ring buffer already taken"))?;
        drop(ebpf);

        tokio::spawn(async move {
            let mut ring_buf = ring_buf;
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));

            loop {
                interval.tick().await;

                let events: Vec<EnforcementEvent> = tokio::task::block_in_place(|| {
                    let mut out = Vec::new();
                    while let Some(item) = ring_buf.next() {
                        if item.len() < std::mem::size_of::<EnforcementEvent>() {
                            continue;
                        }
                        let event = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const EnforcementEvent)
                        };
                        out.push(event);
                        if out.len() >= 1000 {
                            break;
                        }
                    }
                    out
                });

                let had_events = !events.is_empty();
                for event in events {
                    // Deny, audit would-deny, and cgroup-escape events all reach
                    // watchers. A per-event decision label on DenyEvent is part
                    // of the structured-reason proto follow-up (issue #67).
                    if !matches!(
                        event.decision,
                        DECISION_DENY | DECISION_WOULD_DENY | DECISION_ESCAPE
                    ) {
                        continue;
                    }
                    let deny_event = DenyEvent {
                        timestamp_ns: event.timestamp_ns,
                        hook: crate::events::hook_label(event.hook).to_string(),
                        zone_id: event.caller_zone,
                        target_zone_id: event.target_zone,
                        pid: event.pid,
                        comm: String::new(),
                        inode: 0,
                        context: event.context.to_string(),
                    };

                    if tx.send(Ok(deny_event)).await.is_err() {
                        return;
                    }
                }

                if !req.follow && !had_events {
                    return;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[allow(clippy::result_large_err)]
fn proto_policy_to_core_input(
    proto_policy: syva_proto::syva_core::ZonePolicy,
) -> Result<CoreZonePolicyInput, Status> {
    Ok(CoreZonePolicyInput {
        host_paths: proto_policy.host_paths,
        allowed_zones: proto_policy.allowed_zones,
        allow_ptrace: proto_policy.allow_ptrace,
        zone_type: parse_proto_zone_type(proto_policy.zone_type)?,
    })
}

#[allow(clippy::result_large_err)]
fn parse_proto_zone_type(value: i32) -> Result<ZoneType, Status> {
    match value {
        0 => Ok(ZoneType::NonGlobal),
        1 => Ok(ZoneType::Privileged),
        other => Err(Status::invalid_argument(format!(
            "unsupported zone_type: {other}"
        ))),
    }
}

fn attach_request_to_observation(req: &AttachContainerRequest) -> MembershipObservation {
    let pod = if req.pod_namespace.is_empty() && req.pod_name.is_empty() && req.pod_uid.is_empty() {
        None
    } else {
        Some(PodIdentity {
            namespace: req.pod_namespace.clone(),
            name: req.pod_name.clone(),
            uid: req.pod_uid.clone(),
        })
    };

    MembershipObservation {
        container_id: req.container_id.clone(),
        pod,
        cgroup_id: req.cgroup_id,
        zone_name: req.zone_name.clone(),
        source: MembershipSource::from_label(&req.source),
        generation: req.generation,
        observed_at: std::time::SystemTime::now(),
    }
}

async fn acquire_container_update(
    active_updates: &Arc<StdMutex<HashSet<String>>>,
    container_id: &str,
) -> Result<ContainerUpdateGuard, Status> {
    acquire_container_update_with_timeout(
        active_updates,
        container_id,
        CONTAINER_UPDATE_WAIT_TIMEOUT,
    )
    .await
}

async fn acquire_container_update_with_timeout(
    active_updates: &Arc<StdMutex<HashSet<String>>>,
    container_id: &str,
    timeout: Duration,
) -> Result<ContainerUpdateGuard, Status> {
    let deadline = Instant::now() + timeout;
    loop {
        {
            let mut active = active_updates
                .lock()
                .map_err(|_| Status::internal("container update lock poisoned"))?;
            if active.insert(container_id.to_string()) {
                return Ok(ContainerUpdateGuard {
                    active_updates: active_updates.clone(),
                    container_id: container_id.to_string(),
                });
            }
        }

        if Instant::now() >= deadline {
            return Err(Status::deadline_exceeded(format!(
                "timed out waiting for active update on container '{container_id}'"
            )));
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

struct ContainerUpdateGuard {
    active_updates: Arc<StdMutex<HashSet<String>>>,
    container_id: String,
}

impl Drop for ContainerUpdateGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active_updates.lock() {
            active.remove(&self.container_id);
        }
    }
}

#[allow(clippy::result_large_err)]
fn validate_zone_name(zone_name: &str) -> Result<(), Status> {
    if zone_name.is_empty() {
        return Err(Status::invalid_argument("zone_name is required"));
    }
    if is_path_like_zone_name(zone_name) {
        return Err(Status::invalid_argument(
            "zone_name must be a logical identifier, not a filesystem path",
        ));
    }
    Ok(())
}

fn is_path_like_zone_name(zone_name: &str) -> bool {
    zone_name.contains('/') || zone_name.contains('\\') || zone_name.split('.').any(str::is_empty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn container_update_timeout_returns_deadline_exceeded() {
        let active = Arc::new(StdMutex::new(HashSet::from(["container-a".to_string()])));

        let error = match acquire_container_update_with_timeout(
            &active,
            "container-a",
            Duration::from_millis(1),
        )
        .await
        {
            Ok(_) => panic!("active container update should time out"),
            Err(error) => error,
        };

        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        assert!(active.lock().unwrap().contains("container-a"));
    }

    #[test]
    fn path_like_zone_names_are_rejected() {
        assert!(validate_zone_name("../etc/passwd").is_err());
        assert!(validate_zone_name("foo/bar").is_err());
        assert!(validate_zone_name("frontend").is_ok());
    }
}
