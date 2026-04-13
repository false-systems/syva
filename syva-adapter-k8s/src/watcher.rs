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

    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::Apply(policy)) => {
                let name = policy.metadata.name.clone().unwrap_or_default();
                let proto_policy = mapper::spec_to_proto_policy(&policy.spec);

                let mut client = client.lock().await;

                match client
                    .register_zone(RegisterZoneRequest {
                        zone_name: name.clone(),
                        policy: Some(proto_policy),
                    })
                    .await
                {
                    Ok(resp) => {
                        let zone_id = resp.into_inner().zone_id;
                        tracing::info!(zone = name, zone_id, "registered zone from CRD");
                    }
                    Err(e) => {
                        tracing::error!(zone = name, %e, "failed to register zone");
                    }
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

                // Set up comms
                if let Some(net) = &policy.spec.network {
                    for peer in &net.allowed_zones {
                        if let Err(e) = client
                            .allow_comm(AllowCommRequest {
                                zone_a: name.clone(),
                                zone_b: peer.clone(),
                            })
                            .await
                        {
                            tracing::warn!(zone = name, peer = peer.as_str(), %e, "failed to allow comm");
                        }
                    }
                }
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
                    let container_id = pod.metadata.uid.clone().unwrap_or_default();
                    if container_id.is_empty() {
                        continue;
                    }

                    // Resolve cgroup_id from pod's container statuses
                    let cgroup_id = cgroup_id_from_pod(&pod);
                    if cgroup_id == 0 {
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
