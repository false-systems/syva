use crate::policy::{load_policies_from_dir, FilePolicy};
use crate::translate::{
    policy_to_core_register, policy_to_core_update, policy_to_create_args, policy_to_update_args,
};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use syva_core_client::syva_core::{
    AllowCommRequest, ListZonesRequest, RegisterHostPathRequest, RemoveZoneRequest,
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
                match reconcile_once_core(&mut core, config).await {
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
) -> Result<ReconcileStats> {
    let on_disk = load_policies_from_dir(&config.policy_dir)
        .with_context(|| format!("load policies from {}", config.policy_dir.display()))?;
    let in_core = core
        .list_zones(ListZonesRequest {})
        .await?
        .into_inner()
        .zones;
    let diff = crate::diff::diff_against_core(&on_disk, &in_core);

    let mut stats = ReconcileStats::default();

    for name in diff.create {
        let Some(policy) = on_disk.get(&name) else {
            continue;
        };
        apply_core_register(core, &name, policy, true).await?;
        stats.created += 1;
        stats.changed += 1;
        info!(zone = %name, "zone registered in local core");
    }

    for name in diff.update {
        let Some(policy) = on_disk.get(&name) else {
            continue;
        };
        apply_core_register(core, &name, policy, false).await?;
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
        stats.deleted += 1;
        stats.changed += 1;
        info!(zone = %name, "zone removal requested in local core");
    }

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
    core.register_zone(request).await?;

    for allowed_zone in &policy.policy.network.allowed_zones {
        if let Err(error) = core
            .allow_comm(AllowCommRequest {
                zone_a: name.to_string(),
                zone_b: allowed_zone.clone(),
            })
            .await
        {
            warn!(zone = %name, peer = %allowed_zone, error = %error, "allow_comm failed");
        }
    }

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
