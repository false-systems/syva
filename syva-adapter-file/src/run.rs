use crate::policy::{load_policies_from_dir, FilePolicy};
use crate::translate::{policy_to_core_register, policy_to_core_update};
use anyhow::{Context, Result};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::Duration;
use syva_core_client::syva_core::{
    AllowCommRequest, DenyCommRequest, ListCommsRequest, ListZonesRequest, RegisterHostPathRequest,
    RemoveZoneRequest,
};
use tracing::{debug, info, warn};

pub struct Config {
    pub policy_dir: PathBuf,
    pub core_socket: PathBuf,
    pub reconcile_interval: Duration,
}

pub async fn run(config: Config) -> Result<()> {
    let mut core =
        syva_core_client::connect_unix_socket_with_retry(config.core_socket.clone()).await;
    let mut last_applied = HashMap::new();

    info!(
        policy_dir = %config.policy_dir.display(),
        socket = %config.core_socket.display(),
        "syva-file starting"
    );
    warn!(
        "workload membership watcher is not wired in syva-file yet; zones, host paths, and communication policy are reconciled, but containers must be attached through syva.core.v1 AttachContainer"
    );

    let mut ticker = tokio::time::interval(config.reconcile_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match reconcile_once_core(&mut core, &config, &mut last_applied).await {
                    Ok(stats) if stats.changed > 0 => {
                        info!(
                            created = stats.created,
                            updated = stats.updated,
                            deleted = stats.deleted,
                            "reconcile done"
                        );
                    }
                    Ok(_) => debug!("reconcile done, no changes"),
                    Err(error) => warn!("reconcile failed: {error:#}"),
                }
            }
            result = tokio::signal::ctrl_c() => {
                result.context("wait for ctrl-c")?;
                info!("received shutdown signal");
                return Ok(());
            }
        }
    }
}

#[derive(Default)]
struct ReconcileStats {
    created: usize,
    updated: usize,
    deleted: usize,
    changed: usize,
}

async fn reconcile_once_core(
    core: &mut syva_core_client::SyvaCoreClient,
    config: &Config,
    last_applied: &mut HashMap<String, serde_json::Value>,
) -> Result<ReconcileStats> {
    let on_disk = load_policies_from_dir(&config.policy_dir)
        .with_context(|| format!("load policies from {}", config.policy_dir.display()))?;
    let in_core = core
        .list_zones(ListZonesRequest {})
        .await?
        .into_inner()
        .zones;
    let diff = crate::diff::diff_against_core(&on_disk, &in_core, last_applied);

    let mut stats = ReconcileStats::default();

    for name in diff.create {
        let Some(policy) = on_disk.get(&name) else {
            continue;
        };
        apply_core_register(core, &name, policy, true).await?;
        last_applied.insert(name.clone(), serde_json::to_value(policy)?);
        stats.created += 1;
        stats.changed += 1;
        info!(zone = %name, "zone registered in local core");
    }

    for name in diff.update {
        let Some(policy) = on_disk.get(&name) else {
            continue;
        };
        apply_core_register(core, &name, policy, false).await?;
        last_applied.insert(name.clone(), serde_json::to_value(policy)?);
        stats.updated += 1;
        stats.changed += 1;
        debug!(zone = %name, "zone refreshed in local core");
    }

    for name in diff.remove {
        core.remove_zone(RemoveZoneRequest {
            zone_name: name.clone(),
            drain: true,
        })
        .await?;
        last_applied.remove(&name);
        stats.deleted += 1;
        stats.changed += 1;
        info!(zone = %name, "zone removal requested in local core");
    }

    reconcile_core_comms(core, &on_disk).await?;

    Ok(stats)
}

async fn apply_core_register(
    core: &mut syva_core_client::SyvaCoreClient,
    name: &str,
    policy: &FilePolicy,
    create: bool,
) -> Result<()> {
    let request = if create {
        policy_to_core_register(name, policy)
    } else {
        policy_to_core_update(name, policy)
    };
    if !create {
        let removed = core
            .remove_zone(RemoveZoneRequest {
                zone_name: name.to_string(),
                drain: false,
            })
            .await?
            .into_inner();
        if !removed.ok {
            anyhow::bail!(
                "cannot update local-core zone '{name}' authoritatively: {}",
                removed.message
            );
        }
    }
    core.register_zone(request).await?;

    for path in &policy.policy.filesystem.host_paths {
        core.register_host_path(RegisterHostPathRequest {
            zone_name: name.to_string(),
            path: path.clone(),
            recursive: true,
        })
        .await?;
    }

    Ok(())
}

async fn reconcile_core_comms(
    core: &mut syva_core_client::SyvaCoreClient,
    policies: &HashMap<String, FilePolicy>,
) -> Result<()> {
    let desired = desired_mutual_comm_pairs(policies);
    let current = core
        .list_comms(ListCommsRequest {
            zone_name: String::new(),
        })
        .await?
        .into_inner()
        .pairs
        .into_iter()
        .map(|pair| canonical_pair(&pair.zone_a, &pair.zone_b))
        .collect::<BTreeSet<_>>();

    for (zone_a, zone_b) in desired.difference(&current) {
        core.allow_comm(AllowCommRequest {
            zone_a: zone_a.clone(),
            zone_b: zone_b.clone(),
        })
        .await?;
    }

    for (zone_a, zone_b) in current.difference(&desired) {
        if policies.contains_key(zone_a) && policies.contains_key(zone_b) {
            core.deny_comm(DenyCommRequest {
                zone_a: zone_a.clone(),
                zone_b: zone_b.clone(),
            })
            .await?;
        }
    }

    Ok(())
}

fn desired_mutual_comm_pairs(policies: &HashMap<String, FilePolicy>) -> BTreeSet<(String, String)> {
    let mut pairs = BTreeSet::new();
    for (zone, policy) in policies {
        for peer in &policy.policy.network.allowed_zones {
            let Some(peer_policy) = policies.get(peer) else {
                continue;
            };
            if peer_policy
                .policy
                .network
                .allowed_zones
                .iter()
                .any(|candidate| candidate == zone)
            {
                pairs.insert(canonical_pair(zone, peer));
            }
        }
    }
    pairs
}

fn canonical_pair(zone_a: &str, zone_b: &str) -> (String, String) {
    if zone_a <= zone_b {
        (zone_a.to_string(), zone_b.to_string())
    } else {
        (zone_b.to_string(), zone_a.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(allowed_zones: &[&str]) -> FilePolicy {
        let mut policy = crate::types::ZonePolicy::default();
        policy.network.allowed_zones = allowed_zones
            .iter()
            .map(|zone| (*zone).to_string())
            .collect();
        FilePolicy {
            display_name: None,
            selector: None,
            policy,
        }
    }

    #[test]
    fn derives_only_mutual_comm_pairs() {
        let policies = HashMap::from([
            ("web".to_string(), policy(&["api", "db"])),
            ("api".to_string(), policy(&["web"])),
            ("db".to_string(), policy(&[])),
        ]);

        assert_eq!(
            desired_mutual_comm_pairs(&policies),
            BTreeSet::from([("api".to_string(), "web".to_string())])
        );
    }
}
