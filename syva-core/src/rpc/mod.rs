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
    DenyCommRequest, DenyCommResponse,
    DenyEvent,
    DetachContainerRequest, DetachContainerResponse,
    RegisterHostPathRequest, RegisterHostPathResponse,
    RegisterZoneRequest, RegisterZoneResponse,
    RemoveZoneRequest, RemoveZoneResponse,
    StatusRequest, StatusResponse, HookStatus,
    WatchEventsRequest,
};

use crate::ebpf::EnforceEbpf;
use crate::events::HOOK_NAMES;
use crate::health::{HookCounters, SharedHealth};
use crate::types::ZoneType;
use crate::zone::{ZoneRegistry, ZoneTransition};

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

        let registry = self.registry.read().await;
        let zone_a_id = registry.zone_id(&req.zone_a)
            .ok_or_else(|| Status::not_found(format!("zone '{}' not registered", req.zone_a)))?;
        let zone_b_id = registry.zone_id(&req.zone_b)
            .ok_or_else(|| Status::not_found(format!("zone '{}' not registered", req.zone_b)))?;
        drop(registry);

        let mut ebpf = self.ebpf.lock().await;
        ebpf.set_zone_allowed_comms(zone_a_id, zone_b_id)
            .map_err(|e| Status::internal(format!("failed to set allowed comms: {e}")))?;

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

        let registry = self.registry.read().await;
        let zone_a_id = registry.zone_id(&req.zone_a)
            .ok_or_else(|| Status::not_found(format!("zone '{}' not registered", req.zone_a)))?;
        let zone_b_id = registry.zone_id(&req.zone_b)
            .ok_or_else(|| Status::not_found(format!("zone '{}' not registered", req.zone_b)))?;
        drop(registry);

        // Remove comms for both zones involved. This removes all comms for each
        // zone, which is broader than removing just the pair. A more targeted
        // approach would require a remove_zone_comm_pair method in ebpf.rs.
        let mut ebpf = self.ebpf.lock().await;
        ebpf.remove_zone_comms(zone_a_id)
            .map_err(|e| Status::internal(format!("failed to remove comms for zone_a: {e}")))?;
        ebpf.remove_zone_comms(zone_b_id)
            .map_err(|e| Status::internal(format!("failed to remove comms for zone_b: {e}")))?;

        tracing::info!(zone_a = req.zone_a, zone_b = req.zone_b, "cross-zone comm denied via gRPC");
        Ok(Response::new(DenyCommResponse { ok: true }))
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
        let paths = vec![req.path.clone()];
        let count = ebpf.populate_inode_zone_map(zone_id, &paths)
            .map_err(|e| Status::internal(format!("failed to populate inode map: {e}")))?;

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

        // Try to read live counters from BPF maps.
        let ebpf = self.ebpf.lock().await;
        match ebpf.read_counters() {
            Ok(counters) => {
                for (name, totals) in &counters {
                    hooks.push(HookStatus {
                        hook: name.clone(),
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
