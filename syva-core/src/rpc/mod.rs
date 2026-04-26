//! gRPC service implementation for syva-core.

use std::sync::Arc;
use std::time::Instant;

use syva_ebpf_common::{EnforcementEvent, DECISION_DENY};
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
use crate::health::SharedHealth;
use crate::ingest::{self, CoreZonePolicyInput};
use crate::types::ZoneType;
use crate::zone::{ZoneRegistry, ZoneState, ZoneTransition};

pub(crate) struct SyvaCoreService {
    pub(crate) registry: Arc<RwLock<ZoneRegistry>>,
    pub(crate) ebpf: Arc<Mutex<EnforceEbpf>>,
    pub(crate) health: SharedHealth,
    pub(crate) start_time: Instant,
}

#[tonic::async_trait]
impl SyvaCore for SyvaCoreService {
    async fn register_zone(
        &self,
        request: Request<RegisterZoneRequest>,
    ) -> Result<Response<RegisterZoneResponse>, Status> {
        let req = request.into_inner();
        if req.zone_name.is_empty() {
            return Err(Status::invalid_argument("zone_name is required"));
        }

        let policy = req.policy.map(|proto_policy| CoreZonePolicyInput {
            host_paths: proto_policy.host_paths,
            allowed_zones: proto_policy.allowed_zones,
            allow_ptrace: proto_policy.allow_ptrace,
            zone_type: match proto_policy.zone_type {
                1 => ZoneType::Privileged,
                _ => ZoneType::NonGlobal,
            },
        });

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
        if req.zone_name.is_empty() {
            return Err(Status::invalid_argument("zone_name is required"));
        }

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
        if req.zone_name.is_empty() {
            return Err(Status::invalid_argument("zone_name is required"));
        }
        if req.cgroup_id == 0 {
            return Err(Status::invalid_argument("cgroup_id must be non-zero"));
        }

        let mut registry = self.registry.write().await;
        let zone_id = match registry.add_container(&req.container_id, &req.zone_name, req.cgroup_id)
        {
            Ok(id) => id,
            Err(error) => {
                return Ok(Response::new(AttachContainerResponse {
                    ok: false,
                    message: format!("{error}"),
                }));
            }
        };

        let mut ebpf = self.ebpf.lock().await;
        if let Err(error) = ebpf.add_zone_member(req.cgroup_id, zone_id, ZoneType::NonGlobal) {
            registry.remove_container(&req.container_id, None);
            return Err(Status::internal(format!(
                "BPF add_zone_member failed: {error}"
            )));
        }

        let mut health = self.health.write().await;
        health.containers_active = registry.container_count();

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
        if let Some((zone_id, cgroup_id, transition)) =
            registry.remove_container(&req.container_id, None)
        {
            let mut ebpf = self.ebpf.lock().await;
            if let Err(error) = ebpf.remove_zone_member(cgroup_id) {
                tracing::warn!(cgroup_id, %error, "failed to remove zone member from BPF map");
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
            return Err(Status::invalid_argument(
                "both zone_a and zone_b are required",
            ));
        }

        ingest::allow_comm_local(&self.registry, &self.ebpf, &req.zone_a, &req.zone_b)
            .await
            .map_err(|error| Status::internal(format!("failed to set allowed comms: {error}")))?;

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

        ingest::deny_comm_local(&self.registry, &self.ebpf, &req.zone_a, &req.zone_b)
            .await
            .map_err(|error| {
                Status::internal(format!(
                    "failed to remove comms between '{}' and '{}': {error}",
                    req.zone_a, req.zone_b
                ))
            })?;

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
        let count = if req.recursive {
            ebpf.populate_inode_zone_map(zone_id, std::slice::from_ref(&req.path))
                .map_err(|error| {
                    Status::internal(format!("failed to populate inode map: {error}"))
                })?
        } else {
            ebpf.register_single_inode(zone_id, &req.path)
                .map_err(|error| Status::internal(format!("failed to register inode: {error}")))?
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
                tracing::debug!(%error, "failed to read counters for status RPC");
            }
        }

        Ok(Response::new(StatusResponse {
            attached: health.attached,
            zones_active: registry.zone_count() as u32,
            containers_active: registry.container_count() as u32,
            uptime_secs: self.start_time.elapsed().as_secs(),
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
                    if event.decision != DECISION_DENY {
                        continue;
                    }
                    let deny_event = DenyEvent {
                        timestamp_ns: event.timestamp_ns,
                        hook: HOOK_NAMES
                            .get(event.hook as usize)
                            .copied()
                            .unwrap_or("unknown")
                            .to_string(),
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
