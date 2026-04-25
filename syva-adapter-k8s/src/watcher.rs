use crate::crd::SyvaZonePolicy;
use crate::mapper::{spec_to_create_args, spec_to_update_args};
use anyhow::{Context, Result};
use futures::StreamExt;
use kube::runtime::watcher::{watcher, Config as WatcherConfig, Event};
use kube::{Api, Client as KubeClient};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use syva_cp_client::{CpClient, CpClientConfig, DeleteZoneArgs, ZoneSnapshot};
use tracing::{info, warn};
use uuid::Uuid;

pub struct Config {
    pub namespace: String,
    pub cp_endpoint: String,
    pub team_id: Uuid,
}

pub async fn run(config: Config) -> Result<()> {
    let cp = connect_with_retry(&config.cp_endpoint).await;

    let kube = KubeClient::try_default().await?;
    let crds: Api<SyvaZonePolicy> = Api::namespaced(kube.clone(), &config.namespace);

    info!(
        namespace = %config.namespace,
        team_id = %config.team_id,
        "syva-k8s starting"
    );
    info!(
        "pod annotation and container membership reconciliation are deferred until ContainerService is implemented"
    );

    initial_reconcile(&cp, &crds, config.team_id).await?;

    let mut stream = watcher(crds, WatcherConfig::default()).boxed();
    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::Apply(crd)) => {
                if let Err(error) = handle_apply(&cp, config.team_id, &crd).await {
                    warn!(name = ?crd.metadata.name, error = %error, "apply failed");
                }
            }
            Ok(Event::Delete(crd)) => {
                if let Err(error) = handle_delete(&cp, config.team_id, &crd).await {
                    warn!(name = ?crd.metadata.name, error = %error, "delete failed");
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

async fn initial_reconcile(
    cp: &CpClient,
    crds: &Api<SyvaZonePolicy>,
    team_id: Uuid,
) -> Result<()> {
    let crd_list = crds.list(&Default::default()).await?;
    let in_cp = cp.list_zones(team_id, None, 500).await?;
    let in_cp_by_name: HashMap<String, ZoneSnapshot> =
        in_cp.into_iter().map(|zone| (zone.name.clone(), zone)).collect();

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
                    match cp.update_zone(args).await {
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
            Err(error) => warn!(zone = %name, error = %error, "initial delete failed"),
        }
    }

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
                cp.update_zone(args).await?;
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

    cp.delete_zone(DeleteZoneArgs {
        zone_id: snapshot.zone_id,
        if_version: snapshot.version,
        drain: true,
    })
    .await?;
    info!(zone = %name, "zone deleted (CRD removed)");
    Ok(())
}
