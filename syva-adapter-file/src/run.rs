use crate::policy::load_policies_from_dir;
use crate::translate::{policy_to_create_args, policy_to_update_args};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use syva_cp_client::{CpClient, CpClientConfig, DeleteZoneArgs, ZoneSnapshot};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub struct Config {
    pub policy_dir: PathBuf,
    pub cp_endpoint: String,
    pub team_id: Uuid,
    pub reconcile_interval: Duration,
}

pub async fn run(config: Config) -> Result<()> {
    let cp = connect_with_retry(&config.cp_endpoint).await;

    info!(
        policy_dir = %config.policy_dir.display(),
        team_id = %config.team_id,
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
                match reconcile_once(&cp, &config).await {
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

async fn reconcile_once(cp: &CpClient, config: &Config) -> Result<ReconcileStats> {
    let on_disk = load_policies_from_dir(&config.policy_dir)
        .with_context(|| format!("load policies from {}", config.policy_dir.display()))?;

    let in_cp = cp.list_zones(config.team_id, None, 500).await?;
    let in_cp_by_name: HashMap<String, ZoneSnapshot> =
        in_cp.into_iter().map(|zone| (zone.name.clone(), zone)).collect();

    let mut stats = ReconcileStats::default();

    for (name, policy) in &on_disk {
        match cp.get_zone_by_name(config.team_id, name).await? {
            None => match cp.create_zone(policy_to_create_args(config.team_id, name, policy)?).await
            {
                Ok(output) => {
                    stats.created += 1;
                    stats.changed += 1;
                    info!(zone = %name, zone_id = %output.zone_id, "zone created");
                }
                Err(error) => warn!(zone = %name, error = %error, "create_zone failed"),
            },
            Some(snapshot) => match policy_to_update_args(&snapshot, policy)? {
                Some(args) => match cp.update_zone(args).await {
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
            Err(error) => warn!(zone = %name, error = %error, "delete_zone failed"),
        }
    }

    Ok(stats)
}
