use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::{ContainerStatus, Pod};
use kube::ResourceExt;
use syva_core_client::syva_core::{AttachContainerRequest, DetachContainerRequest};

use crate::metrics::Metrics;

pub(crate) const ZONE_ANNOTATION: &str = "syva.false.systems/zone";

#[derive(Debug, Clone)]
pub(crate) struct ResolverConfig {
    pub(crate) host_proc: PathBuf,
    pub(crate) host_cgroup: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesiredMembership {
    container_id: String,
    zone: String,
    cgroup_id: u64,
    pod_namespace: String,
    pod_name: String,
    pod_uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AppliedMembership {
    zone: String,
    cgroup_id: u64,
    pod_namespace: String,
    pod_name: String,
    pod_uid: String,
    generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MembershipIntent {
    Attach {
        container_id: String,
        zone: String,
        cgroup_id: u64,
        generation: u64,
    },
    Detach {
        container_id: String,
        generation: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PodReconcileError {
    CgroupResolution {
        container_id: String,
        message: String,
    },
}

pub(crate) struct MembershipReconciler {
    node_name: String,
    resolver: ResolverConfig,
    metrics: Metrics,
    applied: BTreeMap<String, AppliedMembership>,
    pod_containers: BTreeMap<String, BTreeSet<String>>,
    next_generation: u64,
}

impl MembershipReconciler {
    pub(crate) fn new(node_name: String, resolver: ResolverConfig, metrics: Metrics) -> Self {
        Self {
            node_name,
            resolver,
            metrics,
            applied: BTreeMap::new(),
            pod_containers: BTreeMap::new(),
            next_generation: 1,
        }
    }

    pub(crate) fn reconcile_pod_intents(
        &mut self,
        pod: &Pod,
    ) -> (Vec<MembershipIntent>, Vec<PodReconcileError>) {
        let pod_key = pod_key(pod);
        let previous = self
            .pod_containers
            .get(&pod_key)
            .cloned()
            .unwrap_or_default();

        if !is_pod_on_node(pod, &self.node_name) {
            return (self.detach_previous(&pod_key, &previous), Vec::new());
        }

        let Some(zone) = pod_zone(pod) else {
            return (self.detach_previous(&pod_key, &previous), Vec::new());
        };

        let Some(status) = pod.status.as_ref() else {
            return (self.detach_previous(&pod_key, &previous), Vec::new());
        };
        if status.phase.as_deref() != Some("Running") {
            return (self.detach_previous(&pod_key, &previous), Vec::new());
        }

        let mut desired = BTreeMap::new();
        let mut unresolved = BTreeSet::new();
        let mut errors = Vec::new();
        for container in status.container_statuses.as_deref().unwrap_or_default() {
            match desired_membership(pod, container, zone, &self.resolver) {
                Ok(Some(membership)) => {
                    desired.insert(membership.container_id.clone(), membership);
                }
                Ok(None) => {}
                Err(error) => {
                    unresolved.insert(error.container_id().to_string());
                    errors.push(error);
                    self.metrics.record_error("cgroup_resolution");
                }
            }
        }

        let desired_ids = desired.keys().cloned().collect::<BTreeSet<_>>();
        let mut retained_ids = desired_ids.clone();
        retained_ids.extend(unresolved);
        let mut intents = Vec::new();
        for container_id in previous.difference(&retained_ids) {
            if let Some(intent) = self.detach_intent(container_id) {
                intents.push(intent);
            }
        }

        for (container_id, wanted) in desired {
            let unchanged = self.applied.get(&container_id).is_some_and(|current| {
                current.zone == wanted.zone
                    && current.cgroup_id == wanted.cgroup_id
                    && current.pod_uid == wanted.pod_uid
            });
            if unchanged {
                continue;
            }

            if self.applied.contains_key(&container_id) {
                if let Some(intent) = self.detach_intent(&container_id) {
                    intents.push(intent);
                }
            }

            let generation = self.next_generation();
            self.applied.insert(
                container_id.clone(),
                AppliedMembership {
                    zone: wanted.zone.clone(),
                    cgroup_id: wanted.cgroup_id,
                    pod_namespace: wanted.pod_namespace,
                    pod_name: wanted.pod_name,
                    pod_uid: wanted.pod_uid,
                    generation,
                },
            );
            intents.push(MembershipIntent::Attach {
                container_id,
                zone: wanted.zone,
                cgroup_id: wanted.cgroup_id,
                generation,
            });
        }

        if retained_ids.is_empty() {
            self.pod_containers.remove(&pod_key);
        } else {
            self.pod_containers.insert(pod_key, retained_ids);
        }
        self.metrics.set_active_memberships(self.applied.len());
        (intents, errors)
    }

    pub(crate) fn delete_pod_intents(&mut self, pod: &Pod) -> Vec<MembershipIntent> {
        let pod_key = pod_key(pod);
        let previous = self.pod_containers.remove(&pod_key).unwrap_or_default();
        let intents = self.detach_previous(&pod_key, &previous);
        self.metrics.set_active_memberships(self.applied.len());
        intents
    }

    fn detach_previous(
        &mut self,
        pod_key: &str,
        previous: &BTreeSet<String>,
    ) -> Vec<MembershipIntent> {
        let intents = previous
            .iter()
            .filter_map(|container_id| self.detach_intent(container_id))
            .collect::<Vec<_>>();
        self.pod_containers.remove(pod_key);
        self.metrics.set_active_memberships(self.applied.len());
        intents
    }

    fn detach_intent(&mut self, container_id: &str) -> Option<MembershipIntent> {
        self.applied.remove(container_id)?;
        let generation = self.next_generation();
        Some(MembershipIntent::Detach {
            container_id: container_id.to_string(),
            generation,
        })
    }

    fn next_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);
        generation
    }
}

impl PodReconcileError {
    fn container_id(&self) -> &str {
        match self {
            Self::CgroupResolution { container_id, .. } => container_id,
        }
    }
}

pub(crate) async fn apply_intents(
    core: &mut syva_core_client::SyvaCoreClient,
    metrics: &Metrics,
    pod: &Pod,
    intents: Vec<MembershipIntent>,
) {
    for intent in intents {
        match intent {
            MembershipIntent::Attach {
                container_id,
                zone,
                cgroup_id,
                generation,
            } => {
                let response = core
                    .attach_container(AttachContainerRequest {
                        container_id: container_id.clone(),
                        zone_name: zone.clone(),
                        cgroup_id,
                        pod_namespace: pod.namespace().unwrap_or_default(),
                        pod_name: pod.name_any(),
                        pod_uid: pod.uid().unwrap_or_default(),
                        source: "syva-k8s".to_string(),
                        generation,
                    })
                    .await;
                match response {
                    Ok(response) => {
                        let body = response.into_inner();
                        let result = if body.ok {
                            "applied"
                        } else if body.message.contains("stale") {
                            "stale"
                        } else {
                            "rejected"
                        };
                        metrics.record_attach(result);
                        tracing::info!(
                            event = "syva.k8s.membership.attach",
                            container_id = %container_id,
                            zone = %zone,
                            cgroup_id,
                            generation,
                            result,
                            reason = %body.message,
                            "pod container membership attach reconciled"
                        );
                    }
                    Err(error) => {
                        metrics.record_attach("error");
                        metrics.record_error("attach_rpc");
                        tracing::warn!(
                            event = "syva.k8s.membership.attach",
                            container_id = %container_id,
                            zone = %zone,
                            cgroup_id,
                            generation,
                            result = "error",
                            %error,
                            "pod container membership attach failed"
                        );
                    }
                }
            }
            MembershipIntent::Detach {
                container_id,
                generation,
            } => {
                let response = core
                    .detach_container(DetachContainerRequest {
                        container_id: container_id.clone(),
                        source: "syva-k8s".to_string(),
                        generation,
                    })
                    .await;
                match response {
                    Ok(response) => {
                        let body = response.into_inner();
                        let result = if body.ok {
                            "applied"
                        } else if body.message.contains("stale") {
                            "stale"
                        } else {
                            "rejected"
                        };
                        metrics.record_detach(result);
                        tracing::info!(
                            event = "syva.k8s.membership.detach",
                            container_id = %container_id,
                            generation,
                            result,
                            reason = %body.message,
                            "pod container membership detach reconciled"
                        );
                    }
                    Err(error) => {
                        metrics.record_detach("error");
                        metrics.record_error("detach_rpc");
                        tracing::warn!(
                            event = "syva.k8s.membership.detach",
                            container_id = %container_id,
                            generation,
                            result = "error",
                            %error,
                            "pod container membership detach failed"
                        );
                    }
                }
            }
        }
    }
}

fn desired_membership(
    pod: &Pod,
    container: &ContainerStatus,
    zone: &str,
    resolver: &ResolverConfig,
) -> Result<Option<DesiredMembership>, PodReconcileError> {
    let Some(raw_container_id) = container.container_id.as_deref() else {
        return Ok(None);
    };
    let container_id = normalize_container_id(raw_container_id).map_err(|message| {
        PodReconcileError::CgroupResolution {
            container_id: raw_container_id.to_string(),
            message,
        }
    })?;
    let cgroup_id = resolve_container_cgroup_id(&container_id, resolver).map_err(|error| {
        PodReconcileError::CgroupResolution {
            container_id: container_id.clone(),
            message: error.to_string(),
        }
    })?;

    Ok(Some(DesiredMembership {
        container_id,
        zone: zone.to_string(),
        cgroup_id,
        pod_namespace: pod.namespace().unwrap_or_default(),
        pod_name: pod.name_any(),
        pod_uid: pod.uid().unwrap_or_default(),
    }))
}

fn is_pod_on_node(pod: &Pod, node_name: &str) -> bool {
    pod.spec.as_ref().and_then(|spec| spec.node_name.as_deref()) == Some(node_name)
}

fn pod_zone(pod: &Pod) -> Option<&str> {
    pod.annotations()
        .get(ZONE_ANNOTATION)
        .map(String::as_str)
        .map(str::trim)
        .filter(|zone| !zone.is_empty())
}

fn pod_key(pod: &Pod) -> String {
    pod.uid()
        .unwrap_or_else(|| format!("{}/{}", pod.namespace().unwrap_or_default(), pod.name_any()))
}

fn normalize_container_id(raw: &str) -> Result<String, String> {
    let id = raw
        .rsplit_once("://")
        .map(|(_, id)| id)
        .unwrap_or(raw)
        .trim();
    if id.is_empty() {
        return Err("container_id is empty".to_string());
    }
    if id.len() > 128 {
        return Err("container_id exceeds 128 chars".to_string());
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() || byte == b'-' || byte == b'_')
    {
        return Err("container_id contains unsupported characters".to_string());
    }
    Ok(id.to_string())
}

fn resolve_container_cgroup_id(container_id: &str, resolver: &ResolverConfig) -> Result<u64> {
    let pid = find_container_pid(container_id, &resolver.host_proc)
        .with_context(|| format!("could not find host pid for container '{container_id}'"))?;
    let cgroup_rel = read_cgroup_v2_path(pid, &resolver.host_proc)
        .with_context(|| format!("could not read cgroup v2 path for pid {pid}"))?;
    let cgroup_path = resolver
        .host_cgroup
        .join(cgroup_rel.trim_start_matches('/'));
    let metadata = std::fs::metadata(&cgroup_path)
        .with_context(|| format!("could not stat host cgroup {}", cgroup_path.display()))?;
    Ok(metadata.ino())
}

fn find_container_pid(container_id: &str, host_proc: &Path) -> Result<u32> {
    let short = &container_id[..usize::min(container_id.len(), 12)];
    for entry in std::fs::read_dir(host_proc)
        .with_context(|| format!("could not read {}", host_proc.display()))?
    {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let cgroup = std::fs::read_to_string(entry.path().join("cgroup")).unwrap_or_default();
        let mountinfo = std::fs::read_to_string(entry.path().join("mountinfo")).unwrap_or_default();
        if cgroup.contains(container_id)
            || cgroup.contains(short)
            || mountinfo.contains(container_id)
            || mountinfo.contains(short)
        {
            return Ok(pid);
        }
    }
    anyhow::bail!("no process references container id {container_id}");
}

fn read_cgroup_v2_path(pid: u32, host_proc: &Path) -> Result<String> {
    let cgroup = std::fs::read_to_string(host_proc.join(pid.to_string()).join("cgroup"))?;
    cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::trim)
        .map(str::to_string)
        .filter(|path| !path.is_empty())
        .context("no cgroup-v2 line found")
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{ContainerStatus, PodSpec, PodStatus};
    use kube::api::ObjectMeta;
    use std::collections::BTreeMap;
    use std::fs;
    use tempfile::TempDir;

    fn pod(node: &str, zone: Option<&str>, phase: &str, container_id: Option<&str>) -> Pod {
        let mut annotations = BTreeMap::new();
        if let Some(zone) = zone {
            annotations.insert(ZONE_ANNOTATION.to_string(), zone.to_string());
        }
        Pod {
            metadata: ObjectMeta {
                name: Some("pod-a".to_string()),
                namespace: Some("default".to_string()),
                uid: Some("uid-a".to_string()),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: Some(PodSpec {
                node_name: Some(node.to_string()),
                ..Default::default()
            }),
            status: Some(PodStatus {
                phase: Some(phase.to_string()),
                container_statuses: Some(vec![ContainerStatus {
                    name: "app".to_string(),
                    container_id: container_id.map(str::to_string),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        }
    }

    fn resolver_for(container_id: &str) -> (TempDir, ResolverConfig) {
        let temp = TempDir::new().unwrap();
        let proc = temp.path().join("proc");
        let cgroup_root = temp.path().join("cgroup");
        let pid_dir = proc.join("1234");
        let rel = format!("kubepods.slice/{container_id}.scope");
        let cgroup_dir = cgroup_root.join(&rel);
        fs::create_dir_all(&pid_dir).unwrap();
        fs::create_dir_all(&cgroup_dir).unwrap();
        fs::write(pid_dir.join("cgroup"), format!("0::/{rel}\n")).unwrap();
        fs::write(
            pid_dir.join("mountinfo"),
            format!("overlay / {container_id}\n"),
        )
        .unwrap();
        (
            temp,
            ResolverConfig {
                host_proc: proc,
                host_cgroup: cgroup_root,
            },
        )
    }

    fn reconciler(resolver: ResolverConfig) -> MembershipReconciler {
        MembershipReconciler::new("node-a".to_string(), resolver, Metrics::default())
    }

    #[test]
    fn pod_without_annotation_ignored() {
        let (_temp, resolver) = resolver_for("abcdef123456");
        let mut r = reconciler(resolver);
        let (intents, errors) = r.reconcile_pod_intents(&pod(
            "node-a",
            None,
            "Running",
            Some("containerd://abcdef123456"),
        ));
        assert!(intents.is_empty());
        assert!(errors.is_empty());
    }

    #[test]
    fn pod_with_annotation_creates_attach_intent() {
        let (_temp, resolver) = resolver_for("abcdef123456");
        let mut r = reconciler(resolver);
        let (intents, errors) = r.reconcile_pod_intents(&pod(
            "node-a",
            Some("zone-a"),
            "Running",
            Some("containerd://abcdef123456"),
        ));
        assert!(errors.is_empty());
        assert!(matches!(
            intents.as_slice(),
            [MembershipIntent::Attach { container_id, zone, cgroup_id, generation }]
                if container_id == "abcdef123456" && zone == "zone-a" && *cgroup_id != 0 && *generation == 1
        ));
    }

    #[test]
    fn pod_deletion_creates_detach_intent() {
        let (_temp, resolver) = resolver_for("abcdef123456");
        let mut r = reconciler(resolver);
        let p = pod(
            "node-a",
            Some("zone-a"),
            "Running",
            Some("containerd://abcdef123456"),
        );
        let _ = r.reconcile_pod_intents(&p);
        let intents = r.delete_pod_intents(&p);
        assert!(matches!(
            intents.as_slice(),
            [MembershipIntent::Detach { container_id, generation }]
                if container_id == "abcdef123456" && *generation == 2
        ));
    }

    #[test]
    fn zone_annotation_change_detaches_old_and_attaches_new() {
        let (_temp, resolver) = resolver_for("abcdef123456");
        let mut r = reconciler(resolver);
        let _ = r.reconcile_pod_intents(&pod(
            "node-a",
            Some("zone-a"),
            "Running",
            Some("containerd://abcdef123456"),
        ));
        let (intents, errors) = r.reconcile_pod_intents(&pod(
            "node-a",
            Some("zone-b"),
            "Running",
            Some("containerd://abcdef123456"),
        ));
        assert!(errors.is_empty());
        assert!(matches!(
            intents.as_slice(),
            [
                MembershipIntent::Detach { container_id: detach_id, generation: detach_gen },
                MembershipIntent::Attach { container_id: attach_id, zone, generation: attach_gen, .. }
            ] if detach_id == "abcdef123456"
                && *detach_gen == 2
                && attach_id == "abcdef123456"
                && zone == "zone-b"
                && *attach_gen == 3
        ));
    }

    #[test]
    fn duplicate_event_is_idempotent() {
        let (_temp, resolver) = resolver_for("abcdef123456");
        let mut r = reconciler(resolver);
        let p = pod(
            "node-a",
            Some("zone-a"),
            "Running",
            Some("containerd://abcdef123456"),
        );
        let _ = r.reconcile_pod_intents(&p);
        let (intents, errors) = r.reconcile_pod_intents(&p);
        assert!(intents.is_empty());
        assert!(errors.is_empty());
    }

    #[test]
    fn detach_generation_is_newer_than_attach_generation() {
        let (_temp, resolver) = resolver_for("abcdef123456");
        let mut r = reconciler(resolver);
        let p = pod(
            "node-a",
            Some("zone-a"),
            "Running",
            Some("containerd://abcdef123456"),
        );
        let (attach, _) = r.reconcile_pod_intents(&p);
        let detach = r.delete_pod_intents(&p);
        let attach_generation = match &attach[0] {
            MembershipIntent::Attach { generation, .. } => *generation,
            _ => panic!("expected attach"),
        };
        let detach_generation = match &detach[0] {
            MembershipIntent::Detach { generation, .. } => *generation,
            _ => panic!("expected detach"),
        };
        assert!(detach_generation > attach_generation);
    }

    #[test]
    fn cgroup_resolution_failure_reports_error() {
        let temp = TempDir::new().unwrap();
        let mut r = reconciler(ResolverConfig {
            host_proc: temp.path().join("missing-proc"),
            host_cgroup: temp.path().join("missing-cgroup"),
        });
        let (intents, errors) = r.reconcile_pod_intents(&pod(
            "node-a",
            Some("zone-a"),
            "Running",
            Some("containerd://abcdef123456"),
        ));
        assert!(intents.is_empty());
        assert!(matches!(
            errors.as_slice(),
            [PodReconcileError::CgroupResolution { container_id, .. }]
                if container_id == "abcdef123456"
        ));
    }

    #[test]
    fn cgroup_resolution_failure_does_not_detach_existing_membership() {
        let (temp, resolver) = resolver_for("abcdef123456");
        let mut r = reconciler(resolver);
        let p = pod(
            "node-a",
            Some("zone-a"),
            "Running",
            Some("containerd://abcdef123456"),
        );
        let (initial, initial_errors) = r.reconcile_pod_intents(&p);
        assert_eq!(initial.len(), 1);
        assert!(initial_errors.is_empty());

        r.resolver.host_proc = temp.path().join("missing-proc");
        let (intents, errors) = r.reconcile_pod_intents(&p);
        assert!(intents.is_empty());
        assert!(matches!(
            errors.as_slice(),
            [PodReconcileError::CgroupResolution { container_id, .. }]
                if container_id == "abcdef123456"
        ));
    }
}
