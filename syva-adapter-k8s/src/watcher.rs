use crate::crd::SyvaZonePolicy;
use crate::mapper::spec_to_core_register;
use anyhow::{Context, Result};
use futures::StreamExt;
use kube::runtime::watcher::{watcher, Config as WatcherConfig, Event};
use kube::{Api, Client as KubeClient};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use syva_core_client::syva_core::{
    AllowCommRequest, DenyCommRequest, ListCommsRequest, ListZonesRequest, RemoveZoneRequest,
};
use tracing::{info, warn};

pub struct Config {
    pub namespace: String,
    pub core_socket: PathBuf,
}

pub async fn run(config: Config) -> Result<()> {
    let kube = KubeClient::try_default().await?;
    let crds: Api<SyvaZonePolicy> = Api::namespaced(kube.clone(), &config.namespace);
    run_core_mode(config, crds).await
}

async fn run_core_mode(config: Config, crds: Api<SyvaZonePolicy>) -> Result<()> {
    let mut core =
        syva_core_client::connect_unix_socket_with_retry(config.core_socket.clone()).await;

    info!(
        namespace = %config.namespace,
        socket = %config.core_socket.display(),
        "syva-k8s starting"
    );
    warn!(
        "pod/container membership watcher is not wired in syva-k8s yet; SyvaZonePolicy CRDs are reconciled, but pods must be attached through syva.core.v1 AttachContainer"
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
