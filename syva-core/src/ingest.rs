use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};

use crate::ebpf::EnforceEbpf;
use crate::health::SharedHealth;
use crate::types::ZoneType;
use crate::zone::ZoneRegistry;

#[derive(Debug, Clone)]
pub(crate) struct CoreZonePolicyInput {
    pub host_paths: Vec<String>,
    pub allowed_zones: Vec<String>,
    pub allow_ptrace: bool,
    pub zone_type: ZoneType,
}

#[derive(Debug, Clone)]
pub(crate) struct RemoveZoneResult {
    pub ok: bool,
    pub message: String,
    pub fully_removed: bool,
}

pub(crate) async fn register_zone_local(
    registry: &Arc<RwLock<ZoneRegistry>>,
    ebpf: &Arc<Mutex<EnforceEbpf>>,
    health: &SharedHealth,
    zone_name: &str,
    policy: Option<CoreZonePolicyInput>,
) -> anyhow::Result<u32> {
    let (zone_id, zones_loaded, was_new) = {
        let mut registry = registry.write().await;
        let was_new = registry.zone_id(zone_name).is_none();
        registry.register_zone(zone_name)?;
        let zone_id = registry.revive_draining(zone_name)?;
        if let Some(policy) = policy.as_ref() {
            registry.set_zone_type(zone_name, policy.zone_type)?;
        }
        let zones_loaded = registry.zone_count();
        (zone_id, zones_loaded, was_new)
    };

    if let Some(policy) = policy {
        let mut internal_policy = crate::types::ZonePolicy::default();
        if policy.allow_ptrace {
            internal_policy
                .capabilities
                .allowed
                .push("CAP_SYS_PTRACE".to_string());
        }
        internal_policy.filesystem.host_paths = policy.host_paths.clone();
        internal_policy.network.allowed_zones = policy.allowed_zones;

        {
            let mut ebpf = ebpf.lock().await;
            if let Err(error) = ebpf.set_zone_policy(zone_id, &internal_policy) {
                if was_new {
                    let mut registry = registry.write().await;
                    let _ = registry.unregister_zone(zone_name);
                    health.write().await.zones_loaded = registry.zone_count();
                }
                return Err(error);
            }

            if !policy.host_paths.is_empty() {
                match ebpf.populate_inode_zone_map(zone_id, &policy.host_paths) {
                    Ok(inodes) => {
                        tracing::info!(zone = zone_name, zone_id, inodes, "inode map populated");
                    }
                    Err(error) => {
                        tracing::warn!(zone = zone_name, %error, "inode map population failed");
                    }
                }
            }
        }
    }

    health.write().await.zones_loaded = zones_loaded;
    Ok(zone_id)
}

pub(crate) async fn remove_zone_local(
    registry: &Arc<RwLock<ZoneRegistry>>,
    ebpf: &Arc<Mutex<EnforceEbpf>>,
    health: &SharedHealth,
    zone_name: &str,
    drain: bool,
) -> anyhow::Result<RemoveZoneResult> {
    let (cleanup_zone_id, zones_loaded, outcome) = {
        let mut registry = registry.write().await;

        if drain {
            registry.mark_draining(zone_name)?;
            let refcount = registry.refcount(zone_name);
            if refcount > 0 {
                let zones_loaded = registry.zone_count();
                (
                    None,
                    zones_loaded,
                    RemoveZoneResult {
                        ok: true,
                        message: String::new(),
                        fully_removed: false,
                    },
                )
            } else {
                let zone_id = registry.unregister_zone(zone_name)?;
                let zones_loaded = registry.zone_count();
                (
                    Some(zone_id),
                    zones_loaded,
                    RemoveZoneResult {
                        ok: true,
                        message: String::new(),
                        fully_removed: true,
                    },
                )
            }
        } else {
            let refcount = registry.refcount(zone_name);
            if refcount > 0 {
                (
                    None,
                    registry.zone_count(),
                    RemoveZoneResult {
                        ok: false,
                        message: format!(
                            "zone '{}' has {} active containers — use drain=true or detach them first",
                            zone_name, refcount
                        ),
                        fully_removed: false,
                    },
                )
            } else {
                let zone_id = registry.unregister_zone(zone_name)?;
                let zones_loaded = registry.zone_count();
                (
                    Some(zone_id),
                    zones_loaded,
                    RemoveZoneResult {
                        ok: true,
                        message: String::new(),
                        fully_removed: true,
                    },
                )
            }
        }
    };

    if let Some(zone_id) = cleanup_zone_id {
        let mut ebpf = ebpf.lock().await;
        let _ = ebpf.remove_zone_policy(zone_id);
        let _ = ebpf.remove_zone_comms(zone_id);
        let _ = ebpf.remove_zone_inodes(zone_id);
        tracing::info!(zone = zone_name, zone_id, "zone removed");
    } else if outcome.ok && drain {
        tracing::info!(zone = zone_name, "zone marked as draining");
    }

    health.write().await.zones_loaded = zones_loaded;
    Ok(outcome)
}

pub(crate) async fn allow_comm_local(
    registry: &Arc<RwLock<ZoneRegistry>>,
    ebpf: &Arc<Mutex<EnforceEbpf>>,
    zone_a: &str,
    zone_b: &str,
) -> anyhow::Result<()> {
    let (zone_a_id, zone_b_id) = {
        let registry = registry.read().await;
        let zone_a_id = registry
            .zone_id(zone_a)
            .ok_or_else(|| anyhow::anyhow!("zone '{}' not registered", zone_a))?;
        let zone_b_id = registry
            .zone_id(zone_b)
            .ok_or_else(|| anyhow::anyhow!("zone '{}' not registered", zone_b))?;
        (zone_a_id, zone_b_id)
    };

    {
        let mut ebpf = ebpf.lock().await;
        ebpf.set_zone_allowed_comms(zone_a_id, zone_b_id)?;
    }

    {
        let mut registry = registry.write().await;
        if registry.zone_id(zone_a).is_some() && registry.zone_id(zone_b).is_some() {
            registry.record_allow_comm(zone_a, zone_b);
        }
    }

    tracing::info!(zone_a, zone_b, "cross-zone comm allowed");
    Ok(())
}

pub(crate) async fn deny_comm_local(
    registry: &Arc<RwLock<ZoneRegistry>>,
    ebpf: &Arc<Mutex<EnforceEbpf>>,
    zone_a: &str,
    zone_b: &str,
) -> anyhow::Result<()> {
    let (zone_a_id, zone_b_id) = {
        let registry = registry.read().await;
        let zone_a_id = registry
            .zone_id(zone_a)
            .ok_or_else(|| anyhow::anyhow!("zone '{}' not registered", zone_a))?;
        let zone_b_id = registry
            .zone_id(zone_b)
            .ok_or_else(|| anyhow::anyhow!("zone '{}' not registered", zone_b))?;
        (zone_a_id, zone_b_id)
    };

    {
        let mut ebpf = ebpf.lock().await;
        ebpf.remove_zone_comm_pair(zone_a_id, zone_b_id)?;
    }

    {
        let mut registry = registry.write().await;
        registry.record_deny_comm(zone_a, zone_b);
    }

    tracing::info!(zone_a, zone_b, "cross-zone comm denied");
    Ok(())
}
