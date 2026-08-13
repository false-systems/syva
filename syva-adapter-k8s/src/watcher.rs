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
    ActivateGenerationRequest, AllowCommRequest, DenyCommRequest, ListCommsRequest,
    ListZonesRequest, RemoveZoneRequest, StatusRequest,
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
    let metrics = Metrics::default();
    spawn_metrics_server(config.metrics_listen, metrics.clone()).await?;

    info!(
        namespace = %config.namespace,
        node = %config.node_name,
        socket = %config.core_socket.display(),
        metrics = %config.metrics_listen,
        "syva-k8s starting"
    );

    loop {
        run_generation(&config, kube.clone(), crds.clone(), metrics.clone()).await?;
        info!("core staging generation changed; replaying authoritative snapshot");
    }
}

async fn run_generation(
    config: &Config,
    kube: KubeClient,
    crds: Api<SyvaZonePolicy>,
    metrics: Metrics,
) -> Result<()> {
    let mut core =
        syva_core_client::connect_unix_socket_with_retry(config.core_socket.clone()).await;
    let staging_generation = core
        .status(StatusRequest {})
        .await?
        .into_inner()
        .staging_generation;

    // Membership and IP mappings cannot reference zones until this completes.
    initial_reconcile_core(&mut core, &crds).await?;

    let pods: Api<Pod> = Api::all(kube);
    let (crd_ready_tx, crd_ready_rx) = tokio::sync::oneshot::channel();
    let (membership_ready_tx, membership_ready_rx) = tokio::sync::oneshot::channel();
    let (ip_ready_tx, ip_ready_rx) = tokio::sync::oneshot::channel();

    let mut crd_task = tokio::spawn(run_crd_watcher(
        config.core_socket.clone(),
        crds,
        crd_ready_tx,
    ));
    let mut pod_task = tokio::spawn(run_pod_membership_watcher(
        config.core_socket.clone(),
        pods.clone(),
        config.node_name.clone(),
        ResolverConfig {
            host_proc: config.host_proc.clone(),
            host_cgroup: config.host_cgroup.clone(),
        },
        metrics.clone(),
        membership_ready_tx,
    ));
    let mut ip_task = tokio::spawn(run_pod_ip_zone_watcher(
        config.core_socket.clone(),
        pods,
        metrics,
        ip_ready_tx,
    ));

    tokio::time::timeout(Duration::from_secs(120), async {
        crd_ready_rx.await.context("CRD initial replay ended")?;
        membership_ready_rx
            .await
            .context("membership initial replay ended")?;
        ip_ready_rx.await.context("IP-zone initial replay ended")?;
        anyhow::Ok(())
    })
    .await
    .context("authoritative replay timed out")??;

    if staging_generation != 0 {
        core.activate_generation(ActivateGenerationRequest {
            generation: staging_generation,
        })
        .await?;
        info!(
            generation = staging_generation,
            "Kubernetes snapshot activated"
        );
    }

    let mut poll = tokio::time::interval(Duration::from_secs(5));
    let result = loop {
        tokio::select! {
            _ = poll.tick() => match core.status(StatusRequest {}).await {
                Ok(response) => {
                    let generation = response.into_inner().staging_generation;
                    if generation != 0 && generation != staging_generation {
                        break Ok(());
                    }
                }
                Err(error) => warn!(%error, "core status unavailable; waiting for reconnect"),
            },
            joined = &mut crd_task => break join_watcher("CRD", joined),
            joined = &mut pod_task => break join_watcher("pod membership", joined),
            joined = &mut ip_task => break join_watcher("pod IP-zone", joined),
        }
    };
    crd_task.abort();
    pod_task.abort();
    ip_task.abort();
    result
}

fn join_watcher(name: &str, joined: Result<Result<()>, tokio::task::JoinError>) -> Result<()> {
    match joined {
        Ok(Ok(())) => anyhow::bail!("{name} watcher exited unexpectedly"),
        Ok(Err(error)) => Err(error.context(format!("{name} watcher failed"))),
        Err(error) => Err(anyhow::anyhow!(error).context(format!("{name} watcher panicked"))),
    }
}

async fn run_crd_watcher(
    core_socket: PathBuf,
    crds: Api<SyvaZonePolicy>,
    ready: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    let mut core = syva_core_client::connect_unix_socket_with_retry(core_socket).await;
    let mut ready = Some(ready);
    let mut stream = watcher(crds.clone(), WatcherConfig::default()).boxed();
    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::Apply(crd)) | Ok(Event::InitApply(crd)) => {
                handle_apply_core(&mut core, &crd).await?;
                reconcile_core_comms(&mut core, &crds).await?;
            }
            Ok(Event::Delete(crd)) => {
                handle_delete_core(&mut core, &crd).await?;
                reconcile_core_comms(&mut core, &crds).await?;
            }
            Ok(Event::InitDone) => {
                initial_reconcile_core(&mut core, &crds).await?;
                if let Some(ready) = ready.take() {
                    let _ = ready.send(());
                }
            }
            Ok(Event::Init) => {}
            Err(error) => warn!(%error, "CRD watcher error"),
        }
    }
    anyhow::bail!("SyvaZonePolicy watch stream ended unexpectedly")
}

async fn run_pod_membership_watcher(
    core_socket: PathBuf,
    pods: Api<Pod>,
    node_name: String,
    resolver: ResolverConfig,
    metrics: Metrics,
    ready: tokio::sync::oneshot::Sender<()>,
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
    let mut retry = tokio::time::interval(Duration::from_secs(5));
    let mut ready = Some(ready);
    let mut init_done = false;
    let mut unresolved = HashMap::<String, Pod>::new();
    loop {
        tokio::select! {
            event = stream.next() => match event {
            Some(Ok(Event::Apply(pod)) | Ok(Event::InitApply(pod))) => {
                let mut intents = reconciler.pending_intents();
                let (new_intents, errors) = reconciler.reconcile_pod_intents(&pod);
                intents.extend(new_intents);
                let key = pod.metadata.uid.clone().unwrap_or_default();
                if errors.is_empty() {
                    unresolved.remove(&key);
                } else {
                    unresolved.insert(key, pod);
                }
                for error in errors {
                    warn!(?error, "pod membership reconcile error");
                }
                let outcomes = apply_intents(&mut core, &metrics, intents).await;
                reconciler.absorb_outcomes(&outcomes);
            }
            Some(Ok(Event::Delete(pod))) => {
                unresolved.remove(&pod.metadata.uid.clone().unwrap_or_default());
                let mut intents = reconciler.pending_intents();
                intents.extend(reconciler.delete_pod_intents(&pod));
                let outcomes = apply_intents(&mut core, &metrics, intents).await;
                reconciler.absorb_outcomes(&outcomes);
            }
            Some(Ok(Event::InitDone)) => init_done = true,
            Some(Ok(Event::Init)) => {}
            Some(Err(error)) => {
                metrics.record_error("pod_watch");
                warn!(%error, "pod watcher error");
            }
            None => anyhow::bail!("pod watch stream ended unexpectedly"),
        },
            _ = retry.tick() => {
                let mut intents = reconciler.pending_intents();
                for pod in unresolved.values().cloned().collect::<Vec<_>>() {
                    let key = pod.metadata.uid.clone().unwrap_or_default();
                    let (new_intents, errors) = reconciler.reconcile_pod_intents(&pod);
                    intents.extend(new_intents);
                    if errors.is_empty() {
                        unresolved.remove(&key);
                    }
                    for error in errors {
                        warn!(?error, "pod membership retry error");
                    }
                }
                let outcomes = apply_intents(&mut core, &metrics, intents).await;
                reconciler.absorb_outcomes(&outcomes);
            }
        }
        if init_done && unresolved.is_empty() && !reconciler.has_pending() {
            if let Some(ready) = ready.take() {
                let _ = ready.send(());
            }
        }
    }
}

async fn run_pod_ip_zone_watcher(
    core_socket: PathBuf,
    pods: Api<Pod>,
    metrics: Metrics,
    ready: tokio::sync::oneshot::Sender<()>,
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
    let mut ready = Some(ready);
    let mut init_done = false;
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
                Some(Ok(Event::InitDone)) => init_done = true,
                Some(Ok(Event::Init)) => {}
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
        if init_done && !reconciler.has_pending() {
            if let Some(ready) = ready.take() {
                let _ = ready.send(());
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
