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

/// Result of applying one intent against the core. `ok` is true only when the
/// core confirmed the state change (or already held it); RPC errors, stale, and
/// conflict responses are all `ok == false` so the reconciler retries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IntentOutcome {
    pub(crate) intent: MembershipIntent,
    pub(crate) ok: bool,
}

pub(crate) struct MembershipReconciler {
    node_name: String,
    resolver: ResolverConfig,
    metrics: Metrics,
    applied: BTreeMap<String, AppliedMembership>,
    pod_containers: BTreeMap<String, BTreeSet<String>>,
    pending_detaches: BTreeMap<String, u64>,
    next_generation: u64,
}

impl MembershipReconciler {
    pub(crate) fn new(node_name: String, resolver: ResolverConfig, metrics: Metrics) -> Self {
        Self::with_start_generation(node_name, resolver, metrics, time_seeded_generation())
    }

    fn with_start_generation(
        node_name: String,
        resolver: ResolverConfig,
        metrics: Metrics,
        start_generation: u64,
    ) -> Self {
        Self {
            node_name,
            resolver,
            metrics,
            applied: BTreeMap::new(),
            pod_containers: BTreeMap::new(),
            pending_detaches: BTreeMap::new(),
            next_generation: start_generation.max(1),
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
        self.pending_detaches
            .insert(container_id.to_string(), generation);
        Some(MembershipIntent::Detach {
            container_id: container_id.to_string(),
            generation,
        })
    }

    /// Detaches the core has not yet confirmed. Re-emit these with every event
    /// batch until the core acknowledges them, so a failed detach RPC cannot
    /// leave a membership enforced forever.
    pub(crate) fn pending_detach_intents(&self) -> Vec<MembershipIntent> {
        self.pending_detaches
            .iter()
            .map(|(container_id, generation)| MembershipIntent::Detach {
                container_id: container_id.clone(),
                generation: *generation,
            })
            .collect()
    }

    /// Feed apply results back into reconciler state. A failed attach is rolled
    /// back so the next pod event regenerates it instead of being suppressed by
    /// the idempotency check; a confirmed detach leaves the retry queue.
    pub(crate) fn absorb_outcomes(&mut self, outcomes: &[IntentOutcome]) {
        for outcome in outcomes {
            match &outcome.intent {
                MembershipIntent::Attach {
                    container_id,
                    generation,
                    ..
                } if !outcome.ok
                    && self
                        .applied
                        .get(container_id)
                        .is_some_and(|current| current.generation == *generation) =>
                {
                    self.applied.remove(container_id);
                }
                MembershipIntent::Detach {
                    container_id,
                    generation,
                } if outcome.ok
                    && self
                        .pending_detaches
                        .get(container_id)
                        .is_some_and(|pending| pending == generation) =>
                {
                    self.pending_detaches.remove(container_id);
                }
                _ => {}
            }
        }
        self.metrics.set_active_memberships(self.applied.len());
    }

    fn next_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);
        generation
    }
}

/// The core refuses non-zero generations lower than the stored one, so the
/// counter must stay monotonic across adapter restarts. Seeding from the clock
/// (microseconds) keeps every new process ahead of any generation a previous
/// instance could have issued.
fn time_seeded_generation() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_micros() as u64)
        .unwrap_or(1)
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
) -> Vec<IntentOutcome> {
    let mut outcomes = Vec::with_capacity(intents.len());
    for intent in intents {
        let ok = match &intent {
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
                        cgroup_id: *cgroup_id,
                        pod_namespace: pod.namespace().unwrap_or_default(),
                        pod_name: pod.name_any(),
                        pod_uid: pod.uid().unwrap_or_default(),
                        source: "syva-k8s".to_string(),
                        generation: *generation,
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
                            cgroup_id = *cgroup_id,
                            generation = *generation,
                            result,
                            reason = %body.message,
                            "pod container membership attach reconciled"
                        );
                        body.ok
                    }
                    Err(error) => {
                        metrics.record_attach("error");
                        metrics.record_error("attach_rpc");
                        tracing::warn!(
                            event = "syva.k8s.membership.attach",
                            container_id = %container_id,
                            zone = %zone,
                            cgroup_id = *cgroup_id,
                            generation = *generation,
                            result = "error",
                            %error,
                            "pod container membership attach failed"
                        );
                        false
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
                        generation: *generation,
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
                            generation = *generation,
                            result,
                            reason = %body.message,
                            "pod container membership detach reconciled"
                        );
                        body.ok
                    }
                    Err(error) => {
                        metrics.record_detach("error");
                        metrics.record_error("detach_rpc");
                        tracing::warn!(
                            event = "syva.k8s.membership.detach",
                            container_id = %container_id,
                            generation = *generation,
                            result = "error",
                            %error,
                            "pod container membership detach failed"
                        );
                        false
                    }
                }
            }
        };
        outcomes.push(IntentOutcome { intent, ok });
    }
    outcomes
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

/// Shortest container ID accepted by the resolver. Runtime IDs are 64 hex
/// chars; anything shorter than the 12-char short form would substring-match
/// unrelated cgroup paths during PID resolution.
const MIN_CONTAINER_ID_LEN: usize = 12;

fn normalize_container_id(raw: &str) -> Result<String, String> {
    let id = raw
        .rsplit_once("://")
        .map(|(_, id)| id)
        .unwrap_or(raw)
        .trim();
    if id.is_empty() {
        return Err("container_id is empty".to_string());
    }
    if id.len() < MIN_CONTAINER_ID_LEN {
        return Err(format!(
            "container_id is shorter than {MIN_CONTAINER_ID_LEN} chars"
        ));
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
    let scope_rel = scope_cgroup_rel(&cgroup_rel, container_id);
    let cgroup_path = resolver.host_cgroup.join(scope_rel.trim_start_matches('/'));
    let metadata = std::fs::metadata(&cgroup_path)
        .with_context(|| format!("could not stat host cgroup {}", cgroup_path.display()))?;
    Ok(metadata.ino())
}

/// Truncate a cgroup-v2 path at the component naming the container scope. The
/// matched PID may live in a sub-cgroup the workload created; enforcement is
/// keyed by `bpf_get_current_cgroup_id()` of the container scope, so a nested
/// path would attach the wrong cgroup and miss sibling processes.
fn scope_cgroup_rel(cgroup_rel: &str, container_id: &str) -> String {
    let short = &container_id[..usize::min(container_id.len(), MIN_CONTAINER_ID_LEN)];
    let mut scope = String::new();
    for component in cgroup_rel.split('/').filter(|part| !part.is_empty()) {
        scope.push('/');
        scope.push_str(component);
        if component.contains(container_id) || component.contains(short) {
            return scope;
        }
    }
    cgroup_rel.to_string()
}

fn find_container_pid(container_id: &str, host_proc: &Path) -> Result<u32> {
    let short = &container_id[..usize::min(container_id.len(), MIN_CONTAINER_ID_LEN)];
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
        if cgroup.contains(container_id) || cgroup.contains(short) {
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
        MembershipReconciler::with_start_generation(
            "node-a".to_string(),
            resolver,
            Metrics::default(),
            1,
        )
    }

    fn intent_generation(intent: &MembershipIntent) -> u64 {
        match intent {
            MembershipIntent::Attach { generation, .. }
            | MembershipIntent::Detach { generation, .. } => *generation,
        }
    }

    #[test]
    fn find_container_pid_ignores_mountinfo_only_matches() {
        let temp = TempDir::new().unwrap();
        let proc = temp.path().join("proc");
        let noisy_pid = proc.join("1");
        let real_pid = proc.join("7022");
        let container_id = "abcdef1234567890";
        fs::create_dir_all(&noisy_pid).unwrap();
        fs::create_dir_all(&real_pid).unwrap();
        fs::write(noisy_pid.join("cgroup"), "0::/init.scope\n").unwrap();
        fs::write(
            noisy_pid.join("mountinfo"),
            format!("/run/containerd/{container_id}/rootfs\n"),
        )
        .unwrap();
        fs::write(
            real_pid.join("cgroup"),
            format!("0::/kubepods.slice/cri-containerd-{container_id}.scope\n"),
        )
        .unwrap();

        let pid = find_container_pid(container_id, &proc).unwrap();

        assert_eq!(pid, 7022);
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
    fn failed_attach_is_rolled_back_and_retried_on_next_event() {
        let (_temp, resolver) = resolver_for("abcdef123456");
        let mut r = reconciler(resolver);
        let p = pod(
            "node-a",
            Some("zone-a"),
            "Running",
            Some("containerd://abcdef123456"),
        );
        let (intents, _) = r.reconcile_pod_intents(&p);
        assert_eq!(intents.len(), 1);
        let first_generation = intent_generation(&intents[0]);

        r.absorb_outcomes(&[IntentOutcome {
            intent: intents[0].clone(),
            ok: false,
        }]);

        let (retried, errors) = r.reconcile_pod_intents(&p);
        assert!(errors.is_empty());
        assert!(matches!(
            retried.as_slice(),
            [MembershipIntent::Attach { container_id, generation, .. }]
                if container_id == "abcdef123456" && *generation > first_generation
        ));
    }

    #[test]
    fn confirmed_attach_is_not_retried() {
        let (_temp, resolver) = resolver_for("abcdef123456");
        let mut r = reconciler(resolver);
        let p = pod(
            "node-a",
            Some("zone-a"),
            "Running",
            Some("containerd://abcdef123456"),
        );
        let (intents, _) = r.reconcile_pod_intents(&p);
        r.absorb_outcomes(&[IntentOutcome {
            intent: intents[0].clone(),
            ok: true,
        }]);

        let (retried, errors) = r.reconcile_pod_intents(&p);
        assert!(retried.is_empty());
        assert!(errors.is_empty());
    }

    #[test]
    fn failed_detach_stays_pending_until_core_confirms() {
        let (_temp, resolver) = resolver_for("abcdef123456");
        let mut r = reconciler(resolver);
        let p = pod(
            "node-a",
            Some("zone-a"),
            "Running",
            Some("containerd://abcdef123456"),
        );
        let _ = r.reconcile_pod_intents(&p);
        let detach = r.delete_pod_intents(&p);
        assert_eq!(detach.len(), 1);

        r.absorb_outcomes(&[IntentOutcome {
            intent: detach[0].clone(),
            ok: false,
        }]);
        assert_eq!(r.pending_detach_intents(), detach);

        r.absorb_outcomes(&[IntentOutcome {
            intent: detach[0].clone(),
            ok: true,
        }]);
        assert!(r.pending_detach_intents().is_empty());
    }

    #[test]
    fn restarted_reconciler_issues_generations_above_prior_instance() {
        let (_temp, resolver) = resolver_for("abcdef123456");
        let p = pod(
            "node-a",
            Some("zone-a"),
            "Running",
            Some("containerd://abcdef123456"),
        );

        let mut first =
            MembershipReconciler::new("node-a".to_string(), resolver.clone(), Metrics::default());
        let (first_intents, _) = first.reconcile_pod_intents(&p);
        let first_generation = intent_generation(&first_intents[0]);

        std::thread::sleep(std::time::Duration::from_millis(2));

        let mut restarted =
            MembershipReconciler::new("node-a".to_string(), resolver, Metrics::default());
        let (restarted_intents, _) = restarted.reconcile_pod_intents(&p);
        let restarted_generation = intent_generation(&restarted_intents[0]);

        assert!(
            restarted_generation > first_generation,
            "restart must not rewind generations: {restarted_generation} <= {first_generation}"
        );
    }

    #[test]
    fn normalize_container_id_rejects_short_ids() {
        assert!(normalize_container_id("containerd://abc").is_err());
        assert!(normalize_container_id("abcdef123456").is_ok());
    }

    #[test]
    fn nested_subcgroup_resolves_to_container_scope_inode() {
        let temp = TempDir::new().unwrap();
        let proc = temp.path().join("proc");
        let cgroup_root = temp.path().join("cgroup");
        let container_id = "abcdef1234567890";
        let scope_rel = format!("kubepods.slice/cri-containerd-{container_id}.scope");
        let nested_rel = format!("{scope_rel}/payload-workers");
        let pid_dir = proc.join("4321");
        fs::create_dir_all(&pid_dir).unwrap();
        fs::create_dir_all(cgroup_root.join(&nested_rel)).unwrap();
        fs::write(pid_dir.join("cgroup"), format!("0::/{nested_rel}\n")).unwrap();
        let resolver = ResolverConfig {
            host_proc: proc,
            host_cgroup: cgroup_root.clone(),
        };

        let resolved = resolve_container_cgroup_id(container_id, &resolver).unwrap();

        let scope_ino = fs::metadata(cgroup_root.join(&scope_rel)).unwrap().ino();
        let nested_ino = fs::metadata(cgroup_root.join(&nested_rel)).unwrap().ino();
        assert_eq!(resolved, scope_ino);
        assert_ne!(resolved, nested_ino);
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
