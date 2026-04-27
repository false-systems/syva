use crate::crd::SyvaZonePolicy;
use crate::mapper::{spec_to_core_register, spec_to_create_args, spec_to_update_args};
use anyhow::{Context, Result};
use futures::StreamExt;
use kube::runtime::watcher::{watcher, Config as WatcherConfig, Event};
use kube::{Api, Client as KubeClient};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;
use syva_core_client::syva_core::{
    AllowCommRequest, DenyCommRequest, ListCommsRequest, ListZonesRequest, RemoveZoneRequest,
};
use syva_cp_client::{CpClient, CpClientConfig, DeleteZoneArgs, ZoneSnapshot};
use tracing::{info, warn};
use uuid::Uuid;

pub struct Config {
    pub namespace: String,
    pub cp_endpoint: Option<String>,
    pub core_socket: Option<PathBuf>,
    pub team_id: Option<Uuid>,
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

    let kube = KubeClient::try_default().await?;
    let crds: Api<SyvaZonePolicy> = Api::namespaced(kube.clone(), &config.namespace);

    match (config.cp_endpoint.clone(), config.core_socket.clone()) {
        (Some(endpoint), None) => run_cp_mode(config, crds, &endpoint).await,
        (None, Some(socket_path)) => run_core_mode(config, crds, socket_path).await,
        _ => unreachable!("validated above"),
    }
}

async fn run_cp_mode(config: Config, crds: Api<SyvaZonePolicy>, endpoint: &str) -> Result<()> {
    let cp = connect_with_retry(endpoint).await;
    let team_id = config.team_id.context("missing team_id")?;

    info!(namespace = %config.namespace, team_id = %team_id, "syva-k8s starting");
    info!(
        "pod annotation and container membership reconciliation are deferred until ContainerService is implemented"
    );

    initial_reconcile(&cp, &crds, team_id).await?;

    let mut stream = watcher(crds, WatcherConfig::default()).boxed();
    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::Apply(crd)) => {
                if let Err(error) = handle_apply(&cp, team_id, &crd).await {
                    warn!(name = ?crd.metadata.name, error = %error, "apply failed");
                }
            }
            Ok(Event::Delete(crd)) => {
                if let Err(error) = handle_delete(&cp, team_id, &crd).await {
                    warn!(name = ?crd.metadata.name, error = %error, "delete failed");
                }
            }
            Ok(Event::Init) | Ok(Event::InitDone) | Ok(Event::InitApply(_)) => {}
            Err(error) => warn!("watcher error: {error}"),
        }
    }

    Ok(())
}

async fn run_core_mode(
    config: Config,
    crds: Api<SyvaZonePolicy>,
    socket_path: PathBuf,
) -> Result<()> {
    let mut core = syva_core_client::connect_unix_socket_with_retry(socket_path.clone()).await;

    info!(
        namespace = %config.namespace,
        socket = %socket_path.display(),
        "syva-k8s starting in local-core mode"
    );
    info!(
        "pod annotation and container membership reconciliation are deferred until ContainerService is implemented"
    );

    initial_reconcile_core(&mut core, &crds).await?;

    let mut stream = watcher(crds.clone(), WatcherConfig::default()).boxed();
    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::Apply(crd)) => {
                if let Err(error) = handle_apply_core(&mut core, &crd).await {
                    warn!(name = ?crd.metadata.name, error = %error, "apply failed");
                } else if let Err(error) = reconcile_core_comms(&mut core, &crds).await {
                    warn!(error = %error, "communication reconcile failed");
                }
            }
            Ok(Event::Delete(crd)) => {
                if let Err(error) = handle_delete_core(&mut core, &crd).await {
                    warn!(name = ?crd.metadata.name, error = %error, "delete failed");
                } else if let Err(error) = reconcile_core_comms(&mut core, &crds).await {
                    warn!(error = %error, "communication reconcile failed");
                }
            }
            Ok(Event::Init) | Ok(Event::InitDone) | Ok(Event::InitApply(_)) => {}
            Err(error) => warn!("watcher error: {error}"),
        }
    }

    Ok(())
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

async fn initial_reconcile(cp: &CpClient, crds: &Api<SyvaZonePolicy>, team_id: Uuid) -> Result<()> {
    let crd_list = crds.list(&Default::default()).await?;
    let in_cp = cp.list_zones(team_id, None, 500).await?;
    let in_cp_by_name: HashMap<String, ZoneSnapshot> = in_cp
        .into_iter()
        .map(|zone| (zone.name.clone(), zone))
        .collect();

    let mut crd_names = HashSet::new();
    for crd in &crd_list {
        let Some(name) = crd.metadata.name.clone() else {
            continue;
        };
        crd_names.insert(name.clone());

        match cp.get_zone_by_name(team_id, &name).await? {
            None => {
                let args = spec_to_create_args(team_id, &name, crd)?;
                match cp.create_zone(args).await {
                    Ok(_) => info!(zone = %name, "zone created from CRD (initial)"),
                    Err(error) => warn!(zone = %name, error = %error, "initial create failed"),
                }
            }
            Some(snapshot) => {
                if let Some(args) = spec_to_update_args(&snapshot, crd)? {
                    match update_zone_with_refresh(cp, team_id, &name, crd, args).await {
                        Ok(_) => info!(zone = %name, "zone updated from CRD (initial)"),
                        Err(error) => warn!(zone = %name, error = %error, "initial update failed"),
                    }
                }
            }
        }
    }

    for (name, snapshot) in &in_cp_by_name {
        if crd_names.contains(name) || snapshot.status == "deleted" {
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
            Ok(()) => info!(zone = %name, "zone deleted (no matching CRD)"),
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
                                info!(zone = %name, "zone deleted (no matching CRD) after refresh")
                            }
                            Err(retry_error) => {
                                warn!(zone = %name, error = %retry_error, "initial delete failed after refresh")
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(error) => warn!(zone = %name, error = %error, "initial delete failed"),
        }
    }

    Ok(())
}

async fn initial_reconcile_core(
    core: &mut syva_core_client::SyvaCoreClient,
    crds: &Api<SyvaZonePolicy>,
) -> Result<()> {
    let crd_list = crds.list(&Default::default()).await?;
    let in_core = core
        .list_zones(ListZonesRequest {})
        .await?
        .into_inner()
        .zones;
    let in_core_by_name: HashSet<String> = in_core.into_iter().map(|zone| zone.name).collect();

    let mut crd_names = HashSet::new();
    for crd in &crd_list {
        let Some(name) = crd.metadata.name.clone() else {
            continue;
        };
        crd_names.insert(name.clone());
        core.register_zone(spec_to_core_register(&name, crd))
            .await?;
        info!(zone = %name, "zone registered from CRD (initial)");
    }

    for name in in_core_by_name.difference(&crd_names) {
        core.remove_zone(RemoveZoneRequest {
            zone_name: name.clone(),
            drain: true,
        })
        .await?;
        info!(zone = %name, "zone removed from local core (no matching CRD)");
    }

    reconcile_core_comms(core, crds).await?;

    Ok(())
}

async fn handle_apply(cp: &CpClient, team_id: Uuid, crd: &SyvaZonePolicy) -> Result<()> {
    let name = crd
        .metadata
        .name
        .clone()
        .context("CRD missing metadata.name")?;

    match cp.get_zone_by_name(team_id, &name).await? {
        None => {
            cp.create_zone(spec_to_create_args(team_id, &name, crd)?)
                .await?;
            info!(zone = %name, "zone created from CRD");
        }
        Some(snapshot) => {
            if let Some(args) = spec_to_update_args(&snapshot, crd)? {
                update_zone_with_refresh(cp, team_id, &name, crd, args).await?;
                info!(zone = %name, "zone updated from CRD");
            }
        }
    }

    Ok(())
}

async fn handle_delete(cp: &CpClient, team_id: Uuid, crd: &SyvaZonePolicy) -> Result<()> {
    let name = crd
        .metadata
        .name
        .clone()
        .context("CRD missing metadata.name")?;

    let Some(snapshot) = cp.get_zone_by_name(team_id, &name).await? else {
        return Ok(());
    };

    match cp
        .delete_zone(DeleteZoneArgs {
            zone_id: snapshot.zone_id,
            if_version: snapshot.version,
            drain: true,
        })
        .await
    {
        Ok(()) => {}
        Err(error) if is_retryable_conflict(&error) => {
            let Some(refreshed) = cp.get_zone_by_name(team_id, &name).await? else {
                return Ok(());
            };
            cp.delete_zone(DeleteZoneArgs {
                zone_id: refreshed.zone_id,
                if_version: refreshed.version,
                drain: true,
            })
            .await?;
        }
        Err(error) => return Err(error.into()),
    }
    info!(zone = %name, "zone deleted (CRD removed)");
    Ok(())
}

pub(crate) async fn handle_apply_core(
    core: &mut syva_core_client::SyvaCoreClient,
    crd: &SyvaZonePolicy,
) -> Result<()> {
    let name = crd
        .metadata
        .name
        .clone()
        .context("CRD missing metadata.name")?;

    core.register_zone(spec_to_core_register(&name, crd))
        .await?;
    info!(zone = %name, "zone registered from CRD");
    Ok(())
}

pub(crate) async fn handle_delete_core(
    core: &mut syva_core_client::SyvaCoreClient,
    crd: &SyvaZonePolicy,
) -> Result<()> {
    let name = crd
        .metadata
        .name
        .clone()
        .context("CRD missing metadata.name")?;

    core.remove_zone(RemoveZoneRequest {
        zone_name: name.clone(),
        drain: true,
    })
    .await?;
    info!(zone = %name, "zone deleted (CRD removed)");
    Ok(())
}

async fn reconcile_core_comms(
    core: &mut syva_core_client::SyvaCoreClient,
    crds: &Api<SyvaZonePolicy>,
) -> Result<()> {
    let crd_list = crds.list(&Default::default()).await?;
    let policies = crd_list
        .iter()
        .filter_map(|crd| crd.metadata.name.as_ref().map(|name| (name.clone(), crd)))
        .collect::<HashMap<_, _>>();
    let desired = desired_mutual_comm_pairs(&policies);
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

fn desired_mutual_comm_pairs(
    policies: &HashMap<String, &SyvaZonePolicy>,
) -> BTreeSet<(String, String)> {
    let mut pairs = BTreeSet::new();
    for (zone, policy) in policies {
        let Some(network) = policy.spec.network.as_ref() else {
            continue;
        };
        for peer in &network.allowed_zones {
            let Some(peer_policy) = policies.get(peer) else {
                continue;
            };
            let mutual = peer_policy
                .spec
                .network
                .as_ref()
                .map(|network| {
                    network
                        .allowed_zones
                        .iter()
                        .any(|candidate| candidate == zone)
                })
                .unwrap_or(false);
            if mutual {
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
    crd: &SyvaZonePolicy,
    args: syva_cp_client::UpdateZoneArgs,
) -> Result<syva_cp_client::UpdatedZone> {
    match cp.update_zone(args).await {
        Ok(output) => Ok(output),
        Err(error) if is_retryable_conflict(&error) => {
            let Some(refreshed) = cp.get_zone_by_name(team_id, name).await? else {
                anyhow::bail!("zone disappeared during update retry");
            };
            let Some(retry_args) = spec_to_update_args(&refreshed, crd)? else {
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
    use crate::crd::{NetworkSpec, SyvaZonePolicySpec};

    fn crd(name: &str, allowed_zones: &[&str]) -> SyvaZonePolicy {
        SyvaZonePolicy::new(
            name,
            SyvaZonePolicySpec {
                filesystem: None,
                network: Some(NetworkSpec {
                    allowed_zones: allowed_zones
                        .iter()
                        .map(|zone| (*zone).to_string())
                        .collect(),
                }),
                process: None,
                selector: None,
                zone_type: None,
            },
        )
    }

    #[test]
    fn derives_only_mutual_comm_pairs() {
        let web = crd("web", &["api", "db"]);
        let api = crd("api", &["web"]);
        let db = crd("db", &[]);
        let policies = HashMap::from([
            ("web".to_string(), &web),
            ("api".to_string(), &api),
            ("db".to_string(), &db),
        ]);

        assert_eq!(
            desired_mutual_comm_pairs(&policies),
            BTreeSet::from([("api".to_string(), "web".to_string())])
        );
    }
}
