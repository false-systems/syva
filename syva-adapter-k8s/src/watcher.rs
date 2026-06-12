use crate::crd::SyvaZonePolicy;
use crate::ip_zone::{apply_ip_zone_intents, IpZoneReconciler};
use crate::mapper::spec_to_core_register;
use crate::membership::{apply_intents, MembershipReconciler, ResolverConfig};
use crate::metrics::{spawn_metrics_server, Metrics};
use anyhow::{Context, Result};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::runtime::watcher::{watcher, Config as WatcherConfig, Event};
use kube::{Api, Client as KubeClient};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use syva_core_client::syva_core::{
    AllowCommRequest, DenyCommRequest, ListCommsRequest, ListZonesRequest, RemoveZoneRequest,
};
use tracing::{info, warn};

pub struct Config {
    pub namespace: String,
    pub core_socket: PathBuf,
    pub node_name: String,
    pub host_proc: PathBuf,
    pub host_cgroup: PathBuf,
    pub metrics_listen: SocketAddr,
}

pub async fn run(config: Config) -> Result<()> {
    let kube = KubeClient::try_default().await?;
    let crds: Api<SyvaZonePolicy> = Api::namespaced(kube.clone(), &config.namespace);
    run_core_mode(config, kube, crds).await
}

async fn run_core_mode(config: Config, kube: KubeClient, crds: Api<SyvaZonePolicy>) -> Result<()> {
    let mut core =
        syva_core_client::connect_unix_socket_with_retry(config.core_socket.clone()).await;
    let metrics = Metrics::default();
    spawn_metrics_server(config.metrics_listen, metrics.clone()).await?;

    info!(
        namespace = %config.namespace,
        node = %config.node_name,
        socket = %config.core_socket.display(),
        metrics = %config.metrics_listen,
        "syva-k8s starting"
    );

    initial_reconcile_core(&mut core, &crds).await?;
    let pod_api: Api<Pod> = Api::all(kube.clone());
    let mut pod_task = tokio::spawn(run_pod_membership_watcher(
        config.core_socket.clone(),
        pod_api.clone(),
        config.node_name.clone(),
        ResolverConfig {
            host_proc: config.host_proc.clone(),
            host_cgroup: config.host_cgroup.clone(),
        },
        metrics.clone(),
    ));
    let mut ip_zone_task = tokio::spawn(run_pod_ip_zone_watcher(
        config.core_socket.clone(),
        pod_api,
        metrics.clone(),
    ));

    let crd_loop = async {
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
        anyhow::bail!("SyvaZonePolicy watch stream ended unexpectedly");
    };

    // Membership watching IS the enforcement feed. If that task dies, this
    // adapter must die with it so the DaemonSet restarts both, instead of
    // keeping a half-alive adapter that silently stops attaching pods.
    let result = tokio::select! {
        result = crd_loop => result,
        joined = &mut pod_task => match joined {
            Ok(Ok(())) => Err(anyhow::anyhow!("pod membership watcher exited unexpectedly")),
            Ok(Err(error)) => Err(error.context("pod membership watcher failed")),
            Err(join_error) => {
                Err(anyhow::anyhow!(join_error).context("pod membership watcher panicked"))
            }
        },
        joined = &mut ip_zone_task => match joined {
            Ok(Ok(())) => Err(anyhow::anyhow!("pod IP-zone watcher exited unexpectedly")),
            Ok(Err(error)) => Err(error.context("pod IP-zone watcher failed")),
            Err(join_error) => {
                Err(anyhow::anyhow!(join_error).context("pod IP-zone watcher panicked"))
            }
        },
    };
    pod_task.abort();
    ip_zone_task.abort();
    result
}

async fn run_pod_membership_watcher(
    core_socket: PathBuf,
    pods: Api<Pod>,
    node_name: String,
    resolver: ResolverConfig,
    metrics: Metrics,
) -> Result<()> {
    let mut core = syva_core_client::connect_unix_socket_with_retry(core_socket).await;
    let mut reconciler = MembershipReconciler::new(node_name.clone(), resolver, metrics.clone());
    info!(
        node = %node_name,
        annotation = crate::membership::ZONE_ANNOTATION,
        "syva-k8s pod membership watcher starting"
    );

    // The watcher's Init/InitApply replay covers the initial pod listing; the
    // field selector keeps the watch node-local instead of cluster-wide.
    let watch_config = WatcherConfig::default().fields(&format!("spec.nodeName={node_name}"));
    let mut stream = watcher(pods, watch_config).boxed();
    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::Apply(pod)) | Ok(Event::InitApply(pod)) => {
                let mut intents = reconciler.pending_detach_intents();
                let (new_intents, errors) = reconciler.reconcile_pod_intents(&pod);
                intents.extend(new_intents);
                for error in errors {
                    warn!(?error, "pod membership reconcile error");
                }
                let outcomes = apply_intents(&mut core, &metrics, &pod, intents).await;
                reconciler.absorb_outcomes(&outcomes);
            }
            Ok(Event::Delete(pod)) => {
                let mut intents = reconciler.pending_detach_intents();
                intents.extend(reconciler.delete_pod_intents(&pod));
                let outcomes = apply_intents(&mut core, &metrics, &pod, intents).await;
                reconciler.absorb_outcomes(&outcomes);
            }
            Ok(Event::Init) | Ok(Event::InitDone) => {}
            Err(error) => {
                metrics.record_error("pod_watch");
                warn!(%error, "pod watcher error");
            }
        }
    }
    anyhow::bail!("pod watch stream ended unexpectedly");
}

async fn run_pod_ip_zone_watcher(
    core_socket: PathBuf,
    pods: Api<Pod>,
    metrics: Metrics,
) -> Result<()> {
    let mut core = syva_core_client::connect_unix_socket_with_retry(core_socket).await;
    let mut reconciler = IpZoneReconciler::new();
    info!(
        annotation = crate::membership::ZONE_ANNOTATION,
        "syva-k8s cluster-wide pod IP-zone watcher starting"
    );

    // Cluster-wide by design: a pod on this node may connect to a pod IP on
    // another node, so every node needs the same eventual IP-to-zone view.
    let mut stream = watcher(pods, WatcherConfig::default()).boxed();
    let mut retry = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            event = stream.next() => match event {
                Some(Ok(Event::Apply(pod)) | Ok(Event::InitApply(pod))) => {
                    let mut intents = reconciler.pending_intents();
                    intents.extend(reconciler.reconcile_pod(&pod));
                    let outcomes = apply_ip_zone_intents(&mut core, &metrics, intents).await;
                    reconciler.absorb_outcomes(&outcomes);
                }
                Some(Ok(Event::Delete(pod))) => {
                    let mut intents = reconciler.pending_intents();
                    intents.extend(reconciler.delete_pod(&pod));
                    let outcomes = apply_ip_zone_intents(&mut core, &metrics, intents).await;
                    reconciler.absorb_outcomes(&outcomes);
                }
                Some(Ok(Event::Init) | Ok(Event::InitDone)) => {}
                Some(Err(error)) => {
                    metrics.record_error("pod_ip_zone_watch");
                    warn!(%error, "pod IP-zone watcher error");
                }
                None => anyhow::bail!("pod IP-zone watch stream ended unexpectedly"),
            },
            _ = retry.tick() => {
                let intents = reconciler.pending_intents();
                let outcomes = apply_ip_zone_intents(&mut core, &metrics, intents).await;
                reconciler.absorb_outcomes(&outcomes);
            }
        }
    }
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
                    mode: None,
                    allowed_egress: vec![],
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
