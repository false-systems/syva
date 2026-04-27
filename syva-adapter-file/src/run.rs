use crate::policy::{load_policies_from_dir, FilePolicy};
use crate::translate::{
    policy_to_core_register, policy_to_core_update, policy_to_create_args, policy_to_update_args,
};
use anyhow::{Context, Result};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::Duration;
use syva_core_client::syva_core::{
    AllowCommRequest, DenyCommRequest, ListCommsRequest, ListZonesRequest, RegisterHostPathRequest,
    RemoveZoneRequest,
};
use syva_cp_client::{CpClient, CpClientConfig, DeleteZoneArgs, ZoneSnapshot};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub struct Config {
    pub policy_dir: PathBuf,
    pub cp_endpoint: Option<String>,
    pub core_socket: Option<PathBuf>,
    pub team_id: Option<Uuid>,
    pub reconcile_interval: Duration,
}

pub async fn run(config: Config) -> Result<()> {
    match (&config.cp_endpoint, &config.core_socket) {
        (Some(_), Some(_)) => {
            anyhow::bail!("--cp-endpoint and --core-socket are mutually exclusive")
        }
        (None, None) => anyhow::bail!("exactly one of --cp-endpoint or --core-socket is required"),
        (Some(_), None) if config.team_id.is_none() => {
            anyhow::bail!("--team-id is required when using --cp-endpoint")
        }
        _ => {}
    }

    match (&config.cp_endpoint, &config.core_socket) {
        (Some(endpoint), None) => run_cp_mode(endpoint, &config).await,
        (None, Some(socket_path)) => run_core_mode(socket_path.clone(), &config).await,
        _ => unreachable!("validated above"),
    }
}

async fn run_cp_mode(endpoint: &str, config: &Config) -> Result<()> {
    let cp = connect_with_retry(endpoint).await;
    let team_id = config.team_id.context("missing team_id")?;

    info!(
        policy_dir = %config.policy_dir.display(),
        team_id = %team_id,
        "syva-file starting"
    );
    info!(
        "container watcher and container membership reconciliation are deferred until ContainerService is implemented"
    );

    let mut ticker = tokio::time::interval(config.reconcile_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match reconcile_once_cp(&cp, config, team_id).await {
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

async fn run_core_mode(socket_path: PathBuf, config: &Config) -> Result<()> {
    let mut core = syva_core_client::connect_unix_socket_with_retry(socket_path.clone()).await;
    let mut last_applied = HashMap::new();

    info!(
        policy_dir = %config.policy_dir.display(),
        socket = %socket_path.display(),
        "syva-file starting in local-core mode"
    );
    info!(
        "container watcher and container membership reconciliation are deferred until ContainerService is implemented"
    );

    let mut ticker = tokio::time::interval(config.reconcile_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match reconcile_once_core(&mut core, config, &mut last_applied).await {
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

async fn connect_with_retry(endpoint: &str) -> CpClient {
    let mut backoff = Duration::from_millis(250);
    let max_backoff = Duration::from_secs(30);

    loop {
        match CpClient::connect(CpClientConfig {
            endpoint: endpoint.to_string(),
            ..Default::default()
        })
        .await
        {
            Ok(client) => return client,
            Err(error) => {
                warn!(
                    endpoint,
                    error = %error,
                    backoff_ms = backoff.as_millis(),
                    "could not connect to syva-cp; retrying"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

async fn reconcile_once_cp(
    cp: &CpClient,
    config: &Config,
    team_id: Uuid,
) -> Result<ReconcileStats> {
    let on_disk = load_policies_from_dir(&config.policy_dir)
        .with_context(|| format!("load policies from {}", config.policy_dir.display()))?;

    let in_cp = cp.list_zones(team_id, None, 500).await?;
    let in_cp_by_name: HashMap<String, ZoneSnapshot> = in_cp
        .into_iter()
        .map(|zone| (zone.name.clone(), zone))
        .collect();

    let mut stats = ReconcileStats::default();

    for (name, policy) in &on_disk {
        match cp.get_zone_by_name(team_id, name).await? {
            None => match cp
                .create_zone(policy_to_create_args(team_id, name, policy)?)
                .await
            {
                Ok(output) => {
                    stats.created += 1;
                    stats.changed += 1;
                    info!(zone = %name, zone_id = %output.zone_id, "zone created");
                }
                Err(error) => warn!(zone = %name, error = %error, "create_zone failed"),
            },
            Some(snapshot) => match policy_to_update_args(&snapshot, policy)? {
                Some(args) => match update_zone_with_refresh(cp, team_id, name, policy, args).await
                {
                    Ok(output) => {
                        stats.updated += 1;
                        stats.changed += 1;
                        info!(
                            zone = %name,
                            zone_id = %output.zone_id,
                            version = output.version,
                            "zone updated"
                        );
                    }
                    Err(error) => warn!(zone = %name, error = %error, "update_zone failed"),
                },
                None => debug!(zone = %name, "zone unchanged"),
            },
        }
    }

    for (name, snapshot) in &in_cp_by_name {
        if on_disk.contains_key(name) || snapshot.status == "deleted" {
            continue;
        }

        match cp
            .delete_zone(DeleteZoneArgs {
                zone_id: snapshot.zone_id,
                if_version: snapshot.version,
                drain: true,
            })
            .await
        {
            Ok(()) => {
                stats.deleted += 1;
                stats.changed += 1;
                info!(zone = %name, "zone deletion requested (drain)");
            }
            Err(error) if is_retryable_conflict(&error) => {
                match cp.get_zone_by_name(team_id, name).await? {
                    Some(refreshed) if refreshed.status != "deleted" => {
                        match cp
                            .delete_zone(DeleteZoneArgs {
                                zone_id: refreshed.zone_id,
                                if_version: refreshed.version,
                                drain: true,
                            })
                            .await
                        {
                            Ok(()) => {
                                stats.deleted += 1;
                                stats.changed += 1;
                                info!(zone = %name, "zone deletion requested (drain) after refresh");
                            }
                            Err(retry_error) => {
                                warn!(zone = %name, error = %retry_error, "delete_zone failed after refresh");
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(error) => warn!(zone = %name, error = %error, "delete_zone failed"),
        }
    }

    Ok(stats)
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

async fn update_zone_with_refresh(
    cp: &CpClient,
    team_id: Uuid,
    name: &str,
    policy: &FilePolicy,
    args: syva_cp_client::UpdateZoneArgs,
) -> Result<syva_cp_client::UpdatedZone> {
    match cp.update_zone(args).await {
        Ok(output) => Ok(output),
        Err(error) if is_retryable_conflict(&error) => {
            let Some(refreshed) = cp.get_zone_by_name(team_id, name).await? else {
                return Err(anyhow::anyhow!("zone disappeared during update retry"));
            };
            let Some(retry_args) = policy_to_update_args(&refreshed, policy)? else {
                return Ok(syva_cp_client::UpdatedZone {
                    zone_id: refreshed.zone_id,
                    version: refreshed.version,
                    new_policy_id: refreshed.current_policy_id,
                    new_policy_version: None,
                });
            };
            cp.update_zone(retry_args).await.map_err(Into::into)
        }
        Err(error) => Err(error.into()),
    }
}

fn is_retryable_conflict(error: &syva_cp_client::CpClientError) -> bool {
    match error {
        syva_cp_client::CpClientError::Grpc(status) => matches!(
            status.code(),
            tonic::Code::AlreadyExists | tonic::Code::Aborted | tonic::Code::FailedPrecondition
        ),
        _ => false,
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
