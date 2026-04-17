//! gRPC service implementation for syva-core.
//!
//! Bridges between the proto API and internal ZoneRegistry + EnforceEbpf.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{Mutex, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use syva_ebpf_common::{EnforcementEvent, DECISION_DENY};

use syva_proto::syva_core::syva_core_server::SyvaCore;
use syva_proto::syva_core::{
    AllowCommRequest, AllowCommResponse,
    AttachContainerRequest, AttachContainerResponse,
    CommPair,
    DenyCommRequest, DenyCommResponse,
    DenyEvent,
    DetachContainerRequest, DetachContainerResponse,
    ListCommsRequest, ListCommsResponse,
    ListZonesRequest, ListZonesResponse,
    RegisterHostPathRequest, RegisterHostPathResponse,
    RegisterZoneRequest, RegisterZoneResponse,
    RemoveZoneRequest, RemoveZoneResponse,
    StatusRequest, StatusResponse, HookStatus,
    WatchEventsRequest, ZoneSummary,
};

use crate::ebpf::EnforceEbpf;
use crate::events::HOOK_NAMES;
use crate::health::{HookCounters, SharedHealth};
use crate::types::ZoneType;
use crate::zone::{ZoneRegistry, ZoneState, ZoneTransition};

/// Validate container IDs: hex digits, dashes, underscores only, max 128 chars.
fn is_valid_container_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-' || b == b'_')
}

/// The gRPC service implementation.
pub struct SyvaCoreService {
    pub registry: Arc<RwLock<ZoneRegistry>>,
    pub ebpf: Arc<Mutex<EnforceEbpf>>,
    pub health: SharedHealth,
    pub start_time: Instant,
}

#[tonic::async_trait]
impl SyvaCore for SyvaCoreService {
    async fn register_zone(
        &self,
        request: Request<RegisterZoneRequest>,
    ) -> Result<Response<RegisterZoneResponse>, Status> {
        let req = request.into_inner();
        let zone_name = req.zone_name;

        if zone_name.is_empty() {
            return Err(Status::invalid_argument("zone_name is required"));
        }

        let mut registry = self.registry.write().await;
        let zone_id = registry.register_zone(&zone_name)
            .map_err(|e| Status::internal(format!("failed to register zone: {e}")))?;

        // If a policy was provided, set it in BPF maps.
        if let Some(proto_policy) = req.policy {
            let mut ebpf = self.ebpf.lock().await;

            // Convert proto policy to internal ZonePolicy for BPF map population.
            let allow_ptrace = proto_policy.allow_ptrace;
            let zone_type = match proto_policy.zone_type {
                1 => ZoneType::Privileged,
                _ => ZoneType::NonGlobal,
            };

            // Build a minimal internal ZonePolicy for set_zone_policy.
            let mut policy = crate::types::ZonePolicy::default();
            if allow_ptrace {
                policy.capabilities.allowed.push("CAP_SYS_PTRACE".to_string());
            }
            policy.filesystem.host_paths = proto_policy.host_paths.clone();
            policy.network.allowed_zones = proto_policy.allowed_zones;

            ebpf.set_zone_policy(zone_id, &policy)
                .map_err(|e| Status::internal(format!("failed to set zone policy: {e}")))?;

            // Populate inode map for host_paths.
            if !proto_policy.host_paths.is_empty() {
                match ebpf.populate_inode_zone_map(zone_id, &proto_policy.host_paths) {
                    Ok(n) => {
                        tracing::info!(zone = zone_name, zone_id, inodes = n, "inode map populated");
                    }
                    Err(e) => {
                        tracing::warn!(zone = zone_name, %e, "inode map population failed");
                    }
                }
            }

            drop(ebpf);
        }

        // Update health state.
        {
            let mut h = self.health.write().await;
            h.zones_loaded = registry.zone_count();
        }

        tracing::info!(zone = zone_name, zone_id, "zone registered via gRPC");
        Ok(Response::new(RegisterZoneResponse { zone_id }))
    }

    async fn remove_zone(
        &self,
        request: Request<RemoveZoneRequest>,
    ) -> Result<Response<RemoveZoneResponse>, Status> {
        let req = request.into_inner();
        let zone_name = req.zone_name;

        if zone_name.is_empty() {
            return Err(Status::invalid_argument("zone_name is required"));
        }

        let mut registry = self.registry.write().await;

        if req.drain {
            // Mark as draining — enforcement continues for existing containers.
            registry.mark_draining(&zone_name)
                .map_err(|e| Status::not_found(format!("{e}")))?;

            // If refcount is already 0, clean up immediately.
            let refcount = registry.refcount(&zone_name);
            if refcount == 0 {
                let zone_id = registry.unregister_zone(&zone_name)
                    .map_err(|e| Status::internal(format!("{e}")))?;

                let mut ebpf = self.ebpf.lock().await;
                let _ = ebpf.remove_zone_policy(zone_id);
                let _ = ebpf.remove_zone_comms(zone_id);
                let _ = ebpf.remove_zone_inodes(zone_id);

                tracing::info!(zone = zone_name, zone_id, "zone drained and removed");
            } else {
                tracing::info!(zone = zone_name, refcount, "zone marked as draining");
            }

            let mut h = self.health.write().await;
            h.zones_loaded = registry.zone_count();

            Ok(Response::new(RemoveZoneResponse {
                ok: true,
                message: String::new(),
            }))
        } else {
            // Immediate removal — reject if containers are attached.
            let refcount = registry.refcount(&zone_name);
            if refcount > 0 {
                return Ok(Response::new(RemoveZoneResponse {
                    ok: false,
                    message: format!(
                        "zone '{}' has {} active containers — use drain=true or detach them first",
                        zone_name, refcount
                    ),
                }));
            }

            let zone_id = registry.unregister_zone(&zone_name)
                .map_err(|e| Status::not_found(format!("{e}")))?;

            let mut ebpf = self.ebpf.lock().await;
            let _ = ebpf.remove_zone_policy(zone_id);
            let _ = ebpf.remove_zone_comms(zone_id);
            let _ = ebpf.remove_zone_inodes(zone_id);

            let mut h = self.health.write().await;
            h.zones_loaded = registry.zone_count();

            tracing::info!(zone = zone_name, zone_id, "zone removed via gRPC");
            Ok(Response::new(RemoveZoneResponse {
                ok: true,
                message: String::new(),
            }))
        }
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

        if req.zone_name.is_empty() {
            return Err(Status::invalid_argument("zone_name is required"));
        }

        if req.cgroup_id == 0 {
            return Err(Status::invalid_argument("cgroup_id must be non-zero"));
        }

        let mut registry = self.registry.write().await;
        let zone_id = match registry.add_container(&req.container_id, &req.zone_name, req.cgroup_id) {
            Ok(id) => id,
            Err(e) => {
                return Ok(Response::new(AttachContainerResponse {
                    ok: false,
                    message: format!("{e}"),
                }));
            }
        };

        let mut ebpf = self.ebpf.lock().await;
        if let Err(e) = ebpf.add_zone_member(req.cgroup_id, zone_id, ZoneType::NonGlobal) {
            // Rollback registry state.
            registry.remove_container(&req.container_id, None);
            return Err(Status::internal(format!("BPF add_zone_member failed: {e}")));
        }

        let mut h = self.health.write().await;
        h.containers_active = registry.container_count();

        tracing::info!(
            container = req.container_id,
            zone = req.zone_name,
            zone_id,
            cgroup_id = req.cgroup_id,
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

        let mut registry = self.registry.write().await;
        let result = registry.remove_container(&req.container_id, None);

        if let Some((zone_id, cgroup_id, transition)) = result {
            let mut ebpf = self.ebpf.lock().await;
            if let Err(e) = ebpf.remove_zone_member(cgroup_id) {
                tracing::warn!(cgroup_id, %e, "failed to remove zone member from BPF map");
            }

            match transition {
                ZoneTransition::DrainingComplete => {
                    tracing::info!(zone_id, "draining zone emptied — cleaning up BPF maps");
                    let _ = ebpf.remove_zone_policy(zone_id);
                    let _ = ebpf.remove_zone_comms(zone_id);
                    let _ = ebpf.remove_zone_inodes(zone_id);
                    if let Err(e) = registry.unregister_zone_by_id(zone_id) {
                        tracing::warn!(zone_id, %e, "failed to unregister drained zone");
                    }
                }
                ZoneTransition::WentToPending => {
                    tracing::info!(zone_id, "zone has no active containers (Pending)");
                }
                ZoneTransition::StillActive => {}
            }

            let mut h = self.health.write().await;
            h.containers_active = registry.container_count();
            h.zones_loaded = registry.zone_count();

            tracing::info!(container = req.container_id, "container detached via gRPC");
        }

        Ok(Response::new(DetachContainerResponse { ok: true }))
    }

    async fn allow_comm(
        &self,
        request: Request<AllowCommRequest>,
    ) -> Result<Response<AllowCommResponse>, Status> {
        let req = request.into_inner();

        if req.zone_a.is_empty() || req.zone_b.is_empty() {
            return Err(Status::invalid_argument("both zone_a and zone_b are required"));
        }

        // Resolve IDs under a read-lock, then release it before awaiting the
        // eBPF update — holding a write-lock across the BPF syscall would
        // block unrelated registry readers/writers for no gain. The
        // subsequent write-lock is held just long enough to record the
        // mirror entry. If a zone is unregistered in the window, the BPF
        // entry will be cleared by remove_zone_comms, and the mirror
        // re-check below skips the stale record.
        let (zone_a_id, zone_b_id) = {
            let registry = self.registry.read().await;
            let a = registry.zone_id(&req.zone_a)
                .ok_or_else(|| Status::not_found(format!("zone '{}' not registered", req.zone_a)))?;
            let b = registry.zone_id(&req.zone_b)
                .ok_or_else(|| Status::not_found(format!("zone '{}' not registered", req.zone_b)))?;
            (a, b)
        };

        {
            let mut ebpf = self.ebpf.lock().await;
            ebpf.set_zone_allowed_comms(zone_a_id, zone_b_id)
                .map_err(|e| Status::internal(format!("failed to set allowed comms: {e}")))?;
        }

        {
            let mut registry = self.registry.write().await;
            if registry.zone_id(&req.zone_a).is_some() && registry.zone_id(&req.zone_b).is_some() {
                registry.record_allow_comm(&req.zone_a, &req.zone_b);
            }
        }

        tracing::info!(zone_a = req.zone_a, zone_b = req.zone_b, "cross-zone comm allowed via gRPC");
        Ok(Response::new(AllowCommResponse { ok: true }))
    }

    async fn deny_comm(
        &self,
        request: Request<DenyCommRequest>,
    ) -> Result<Response<DenyCommResponse>, Status> {
        let req = request.into_inner();

        if req.zone_a.is_empty() || req.zone_b.is_empty() {
            return Err(Status::invalid_argument("both zone_a and zone_b are required"));
        }

        // Same locking shape as allow_comm — resolve IDs under a read-lock,
        // release before the eBPF await, take a brief write-lock for the
        // mirror update afterwards.
        let (zone_a_id, zone_b_id) = {
            let registry = self.registry.read().await;
            let a = registry.zone_id(&req.zone_a)
                .ok_or_else(|| Status::not_found(format!("zone '{}' not registered", req.zone_a)))?;
            let b = registry.zone_id(&req.zone_b)
                .ok_or_else(|| Status::not_found(format!("zone '{}' not registered", req.zone_b)))?;
            (a, b)
        };

        {
            // Remove only the requested pair in both directions, preserving
            // any unrelated comm entries involving either zone.
            let mut ebpf = self.ebpf.lock().await;
            ebpf.remove_zone_comm_pair(zone_a_id, zone_b_id)
                .map_err(|e| Status::internal(format!(
                    "failed to remove comms between '{}' and '{}': {e}", req.zone_a, req.zone_b
                )))?;
        }

        {
            // record_deny_comm is a HashSet remove — safe even if the zone
            // was unregistered meanwhile (already wiped by unregister_zone).
            let mut registry = self.registry.write().await;
            registry.record_deny_comm(&req.zone_a, &req.zone_b);
        }

        tracing::info!(zone_a = req.zone_a, zone_b = req.zone_b, "cross-zone comm denied via gRPC");
        Ok(Response::new(DenyCommResponse { ok: true }))
    }

    async fn list_zones(
        &self,
        _request: Request<ListZonesRequest>,
    ) -> Result<Response<ListZonesResponse>, Status> {
        let registry = self.registry.read().await;
        let zones = registry.zones_summary()
            .map(|(name, zone_id, state, refcount)| ZoneSummary {
                name: name.to_string(),
                zone_id,
                state: match state {
                    ZoneState::Pending => "pending",
                    ZoneState::Active => "active",
                    ZoneState::Draining => "draining",
                }.to_string(),
                containers_active: refcount as u32,
            })
            .collect();
        Ok(Response::new(ListZonesResponse { zones }))
    }

    async fn list_comms(
        &self,
        request: Request<ListCommsRequest>,
    ) -> Result<Response<ListCommsResponse>, Status> {
        let req = request.into_inner();
        let filter = if req.zone_name.is_empty() { None } else { Some(req.zone_name.as_str()) };

        let registry = self.registry.read().await;

        // Reject an explicit filter that points to an unknown zone — returning
        // an empty list would hide typos.
        if let Some(z) = filter {
            if registry.zone_id(z).is_none() {
                return Err(Status::not_found(format!("zone '{z}' not registered")));
            }
        }

        let pairs = registry.list_allowed_comms(filter)
            .map(|(a, b)| CommPair { zone_a: a.to_string(), zone_b: b.to_string() })
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
        let zone_id = registry.zone_id(&req.zone_name)
            .ok_or_else(|| Status::not_found(format!("zone '{}' not registered", req.zone_name)))?;
        drop(registry);

        let mut ebpf = self.ebpf.lock().await;
        let count = if req.recursive {
            let paths = vec![req.path.clone()];
            ebpf.populate_inode_zone_map(zone_id, &paths)
                .map_err(|e| Status::internal(format!("failed to populate inode map: {e}")))?
        } else {
            // Single inode registration — stat the path and add its inode directly.
            ebpf.register_single_inode(zone_id, &req.path)
                .map_err(|e| Status::internal(format!("failed to register inode: {e}")))?
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
        let health = self.health.read().await;
        let registry = self.registry.read().await;

        let uptime_secs = self.start_time.elapsed().as_secs();

        let mut hooks = Vec::new();

        // Use stable HOOK_NAMES (file_open, bprm_check, etc.) rather than
        // raw BPF program names (syva_file_open, etc.) for API consistency.
        let ebpf = self.ebpf.lock().await;
        match ebpf.read_counters() {
            Ok(counters) => {
                for (idx, (_, totals)) in counters.iter().enumerate() {
                    let hook_name = HOOK_NAMES.get(idx)
                        .copied()
                        .unwrap_or("unknown")
                        .to_string();
                    hooks.push(HookStatus {
                        hook: hook_name,
                        allow: totals.allow,
                        deny: totals.deny,
                        error: totals.error,
                        lost: totals.lost,
                    });
                }
            }
            Err(e) => {
                tracing::debug!(%e, "failed to read counters for status RPC");
            }
        }

        Ok(Response::new(StatusResponse {
            attached: health.attached,
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
        let ring_buf = ebpf.take_event_ring_buf()
            .ok_or_else(|| Status::unavailable("event ring buffer already taken"))?;
        drop(ebpf);

        let follow = req.follow;

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
                        let event: EnforcementEvent = unsafe {
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
                    if event.decision != DECISION_DENY {
                        continue;
                    }
                    let hook = HOOK_NAMES.get(event.hook as usize)
                        .copied()
                        .unwrap_or("unknown")
                        .to_string();

                    let deny_event = DenyEvent {
                        timestamp_ns: event.timestamp_ns,
                        hook,
                        zone_id: event.caller_zone,
                        target_zone_id: event.target_zone,
                        pid: event.pid,
                        comm: String::new(),
                        inode: 0,
                        context: event.context.to_string(),
                    };

                    if tx.send(Ok(deny_event)).await.is_err() {
                        return; // Client disconnected.
                    }
                }

                if !follow && !had_events {
                    return; // One-shot mode: drain and exit.
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_container_ids() {
        assert!(is_valid_container_id("abc123"));
        assert!(is_valid_container_id("abc-def_123"));
        assert!(is_valid_container_id("a"));
    }

    #[test]
    fn invalid_container_ids() {
        assert!(!is_valid_container_id(""));
        assert!(!is_valid_container_id("abc/def"));
        assert!(!is_valid_container_id("abc def"));
        assert!(!is_valid_container_id(&"a".repeat(129)));
    }

    #[test]
    fn max_length_container_id() {
        assert!(is_valid_container_id(&"a".repeat(128)));
        assert!(!is_valid_container_id(&"a".repeat(129)));
    }
}
