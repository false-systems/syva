use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::runtime::watcher::Event;
use kube::{runtime::watcher, Api, Client};
use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use syva_proto::syva_core::*;
use tokio::sync::Mutex;
use tonic::transport::Channel;

use crate::crd::SyvaZonePolicy;
use crate::mapper;

/// Watch SyvaZonePolicy CRDs and sync to core.
pub async fn watch_zone_policies(
    client: Arc<Mutex<SyvaCoreClient<Channel>>>,
    kube: Client,
    namespace: Option<&str>,
) -> anyhow::Result<()> {
    let policies: Api<SyvaZonePolicy> = match namespace {
        Some(ns) => Api::namespaced(kube, ns),
        None => Api::all(kube),
    };

    let mut stream = watcher::watcher(policies, watcher::Config::default()).boxed();

    // Per-zone snapshot of the allowed_zones set most recently applied to core.
    // Used on the next Apply to detect peers that were retracted from the CRD
    // so we can emit DenyComm — without this, CRD edits could only *widen* the
    // cross-zone allow set, never shrink it.
    let mut last_allowed: HashMap<String, HashSet<String>> = HashMap::new();

    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::Apply(policy)) => {
                let name = policy.metadata.name.clone().unwrap_or_default();
                let proto_policy = mapper::spec_to_proto_policy(&policy.spec);

                let new_allowed: HashSet<String> = policy
                    .spec
                    .network
                    .as_ref()
                    .map(|n| n.allowed_zones.iter().cloned().collect())
                    .unwrap_or_default();
                let prev_allowed = last_allowed.get(&name).cloned().unwrap_or_default();

                let mut client = client.lock().await;

                let registered = match client
                    .register_zone(RegisterZoneRequest {
                        zone_name: name.clone(),
                        policy: Some(proto_policy),
                    })
                    .await
                {
                    Ok(resp) => {
                        let zone_id = resp.into_inner().zone_id;
                        tracing::info!(zone = name, zone_id, "registered zone from CRD");
                        true
                    }
                    Err(e) => {
                        tracing::error!(zone = name, %e, "failed to register zone");
                        false
                    }
                };

                if !registered {
                    // Skip the rest of the apply pipeline — the zone isn't
                    // on core, so registering host paths / comms against it
                    // will just fail. Crucially, leave `last_allowed`
                    // untouched so the next Apply can retry any pending
                    // retractions/grants against the correct prior snapshot.
                    drop(client);
                    continue;
                }

                // Register host paths
                if let Some(fs) = &policy.spec.filesystem {
                    for path in &fs.host_paths {
                        if let Err(e) = client
                            .register_host_path(RegisterHostPathRequest {
                                zone_name: name.clone(),
                                path: path.clone(),
                                recursive: true,
                            })
                            .await
                        {
                            tracing::warn!(zone = name, path = path.as_str(), %e, "failed to register host path");
                        }
                    }
                }

                // Track which retractions/grants were actually applied so
                // `last_allowed` stays in sync with core state. A failed
                // DenyComm stays in `prev_allowed` for the next Apply to
                // retry; a failed AllowComm means the peer isn't in the
                // applied set yet.
                let mut applied_allowed: HashSet<String> = prev_allowed.clone();

                // Retract peers that were in the previous allowed set but are
                // no longer listed. DenyComm clears both directions on core,
                // so the counterparty's CRD doesn't need to have already
                // dropped us for this to be safe.
                for peer in prev_allowed.difference(&new_allowed) {
                    match client
                        .deny_comm(DenyCommRequest {
                            zone_a: name.clone(),
                            zone_b: peer.clone(),
                        })
                        .await
                    {
                        Ok(_) => {
                            applied_allowed.remove(peer);
                            tracing::info!(zone = name, peer = peer.as_str(), "CRD retracted allowed peer — comm denied");
                        }
                        Err(e) => {
                            tracing::warn!(zone = name, peer = peer.as_str(), %e, "failed to deny comm after CRD retraction");
                        }
                    }
                }

                // (Re-)grant currently listed peers. Idempotent on the core side.
                for peer in &new_allowed {
                    match client
                        .allow_comm(AllowCommRequest {
                            zone_a: name.clone(),
                            zone_b: peer.clone(),
                        })
                        .await
                    {
                        Ok(_) => {
                            applied_allowed.insert(peer.clone());
                        }
                        Err(e) => {
                            tracing::warn!(zone = name, peer = peer.as_str(), %e, "failed to allow comm");
                        }
                    }
                }

                drop(client);
                // Only store what actually took effect. Next Apply will see
                // any failed grants/retractions as still-pending diffs.
                last_allowed.insert(name, applied_allowed);
            }
            Ok(Event::Delete(policy)) => {
                let name = policy.metadata.name.unwrap_or_default();
                let mut client = client.lock().await;
                match client
                    .remove_zone(RemoveZoneRequest {
                        zone_name: name.clone(),
                        drain: true,
                    })
                    .await
                {
                    Ok(_) => tracing::info!(zone = name, "removed zone (CRD deleted)"),
                    Err(e) => tracing::error!(zone = name, %e, "failed to remove zone"),
                }
                drop(client);
                last_allowed.remove(&name);
            }
            Ok(_) => {} // InitApply, InitDone
            Err(e) => {
                tracing::error!(%e, "CRD watcher error");
            }
        }
    }

    Ok(())
}

/// Watch Pods for syva.dev/zone annotation.
pub async fn watch_pods(
    client: Arc<Mutex<SyvaCoreClient<Channel>>>,
    kube: Client,
    namespace: Option<&str>,
) -> anyhow::Result<()> {
    let pods: Api<Pod> = match namespace {
        Some(ns) => Api::namespaced(kube, ns),
        None => Api::all(kube),
    };

    let mut stream = watcher::watcher(pods, watcher::Config::default()).boxed();

    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::Apply(pod)) => {
                if let Some(zone_name) = mapper::zone_name_from_pod(&pod) {
                    let ns = pod.metadata.namespace.clone().unwrap_or_default();
                    let pod_name = pod.metadata.name.clone().unwrap_or_default();
                    let container_id = pod.metadata.uid.clone().unwrap_or_default();
                    if container_id.is_empty() {
                        tracing::warn!(
                            namespace = ns,
                            pod = pod_name,
                            zone = zone_name,
                            "skipping zoned pod: missing metadata.uid"
                        );
                        continue;
                    }

                    // Resolve cgroup_id from pod's container statuses.
                    // Returns 0 if containerStatuses is missing (pod not yet scheduled/started)
                    // or if the scope path isn't one we know how to locate. Kubelet will
                    // re-emit an Apply once status is populated; we rely on that rather
                    // than retrying here.
                    let cgroup_id = cgroup_id_from_pod(&pod);
                    if cgroup_id == 0 {
                        tracing::warn!(
                            namespace = ns,
                            pod = pod_name,
                            zone = zone_name,
                            "skipping zoned pod: could not resolve cgroup_id (containerStatuses missing or unknown scope path)"
                        );
                        continue;
                    }

                    let mut client = client.lock().await;
                    match client
                        .attach_container(AttachContainerRequest {
                            container_id: container_id.clone(),
                            zone_name: zone_name.clone(),
                            cgroup_id,
                        })
                        .await
                    {
                        Ok(_) => {
                            tracing::info!(container = container_id, zone = zone_name, "attached container")
                        }
                        Err(e) => {
                            tracing::warn!(container = container_id, %e, "failed to attach container")
                        }
                    }
                }
            }
            Ok(Event::Delete(pod)) => {
                let container_id = pod.metadata.uid.unwrap_or_default();
                if container_id.is_empty() {
                    continue;
                }

                let mut client = client.lock().await;
                let _ = client
                    .detach_container(DetachContainerRequest { container_id })
                    .await;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!(%e, "pod watcher error");
            }
        }
    }

    Ok(())
}

/// Resolve cgroup_id from a Pod's containerStatuses.
fn cgroup_id_from_pod(pod: &Pod) -> u64 {
    // Get first container's PID from container status
    let statuses = pod
        .status
        .as_ref()
        .and_then(|s| s.container_statuses.as_ref());

    if let Some(statuses) = statuses {
        for status in statuses {
            if let Some(container_id) = &status.container_id {
                // Container ID format: containerd://abc123...
                let id = container_id.split("://").last().unwrap_or("");
                if !id.is_empty() {
                    return resolve_cgroup_id_from_containerd(id);
                }
            }
        }
    }
    0
}

fn resolve_cgroup_id_from_containerd(container_id: &str) -> u64 {
    use std::os::unix::fs::MetadataExt;

    let candidates = [
        format!("/sys/fs/cgroup/system.slice/containerd-{container_id}.scope"),
        format!("/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod{container_id}.scope"),
    ];

    for path in &candidates {
        if let Ok(meta) = std::fs::metadata(path) {
            return meta.ino();
        }
    }
    0
}
