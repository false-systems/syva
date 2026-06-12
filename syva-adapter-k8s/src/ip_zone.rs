use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use k8s_openapi::api::core::v1::Pod;
use kube::ResourceExt;
use syva_core_client::syva_core::{RemoveIpZoneRequest, SetIpZoneRequest};

use crate::membership::ZONE_ANNOTATION;
use crate::metrics::Metrics;

#[derive(Debug, Clone, PartialEq, Eq)]
struct AppliedIpZone {
    ip: Ipv4Addr,
    zone: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IpZoneIntent {
    Set { ip: Ipv4Addr, zone: String },
    Remove { ip: Ipv4Addr },
}

pub(crate) struct IpZoneReconciler {
    applied_by_uid: BTreeMap<String, AppliedIpZone>,
    pending: BTreeMap<String, IpZoneIntent>,
}

impl IpZoneReconciler {
    pub(crate) fn new() -> Self {
        Self {
            applied_by_uid: BTreeMap::new(),
            pending: BTreeMap::new(),
        }
    }

    pub(crate) fn reconcile_pod(&mut self, pod: &Pod) -> Vec<IpZoneIntent> {
        let uid = pod_key(pod);
        let previous = self.applied_by_uid.get(&uid).cloned();
        let desired = desired_ip_zone(pod);

        if previous.as_ref() == desired.as_ref() {
            return Vec::new();
        }

        // Update tracked state first so the reuse check below sees the
        // post-event world (including this pod keeping the same IP).
        match desired.clone() {
            Some(desired) => {
                self.applied_by_uid.insert(uid, desired);
            }
            None => {
                self.applied_by_uid.remove(&uid);
            }
        }

        let mut intents = Vec::new();
        if let Some(previous) = previous {
            // Pod IPs are reused: if event ordering delivered the new owner's
            // Set before this pod released the IP, a blind Remove would kill
            // the live mapping. Only remove an IP no tracked pod still claims.
            if !self.ip_claimed(previous.ip) {
                self.drop_pending_for(previous.ip);
                intents.push(IpZoneIntent::Remove { ip: previous.ip });
            }
        }
        if let Some(desired) = desired {
            intents.push(IpZoneIntent::Set {
                ip: desired.ip,
                zone: desired.zone,
            });
        }
        intents
    }

    pub(crate) fn delete_pod(&mut self, pod: &Pod) -> Vec<IpZoneIntent> {
        let uid = pod_key(pod);
        let Some(applied) = self.applied_by_uid.remove(&uid) else {
            return Vec::new();
        };
        if self.ip_claimed(applied.ip) {
            // The IP was already reused by another pod; its mapping stands.
            return Vec::new();
        }
        self.drop_pending_for(applied.ip);
        vec![IpZoneIntent::Remove { ip: applied.ip }]
    }

    pub(crate) fn pending_intents(&mut self) -> Vec<IpZoneIntent> {
        // A queued retry-Remove whose IP a live pod now claims is stale by
        // definition — replaying it would delete the new owner's mapping.
        let claimed_removes: Vec<String> = self
            .pending
            .iter()
            .filter(
                |(_, intent)| matches!(intent, IpZoneIntent::Remove { ip } if self.ip_claimed(*ip)),
            )
            .map(|(key, _)| key.clone())
            .collect();
        for key in claimed_removes {
            self.pending.remove(&key);
        }
        self.pending.values().cloned().collect()
    }

    /// True when any tracked pod currently claims `ip`.
    fn ip_claimed(&self, ip: Ipv4Addr) -> bool {
        self.applied_by_uid.values().any(|applied| applied.ip == ip)
    }

    /// Drop any queued retry for `ip` — the intent we are about to emit
    /// supersedes it (pending is keyed by IP, not by owner).
    fn drop_pending_for(&mut self, ip: Ipv4Addr) {
        self.pending.remove(&ip.to_string());
    }

    pub(crate) fn absorb_outcomes(&mut self, outcomes: &[IpZoneOutcome]) {
        for outcome in outcomes {
            let key = intent_key(&outcome.intent);
            if outcome.ok {
                self.pending.remove(&key);
            } else {
                self.pending.insert(key, outcome.intent.clone());
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IpZoneOutcome {
    intent: IpZoneIntent,
    ok: bool,
}

pub(crate) async fn apply_ip_zone_intents(
    core: &mut syva_core_client::SyvaCoreClient,
    metrics: &Metrics,
    intents: Vec<IpZoneIntent>,
) -> Vec<IpZoneOutcome> {
    let mut outcomes = Vec::with_capacity(intents.len());
    for intent in intents {
        let ok = match &intent {
            IpZoneIntent::Set { ip, zone } => {
                let result = core
                    .set_ip_zone(SetIpZoneRequest {
                        ip: ip.to_string(),
                        zone_name: zone.clone(),
                    })
                    .await;
                if let Err(error) = result {
                    metrics.record_error("ip_zone_set_rpc");
                    tracing::warn!(%ip, zone = %zone, %error, "pod IP-zone set failed");
                    false
                } else {
                    tracing::info!(%ip, zone = %zone, "pod IP-zone set reconciled");
                    true
                }
            }
            IpZoneIntent::Remove { ip } => {
                let result = core
                    .remove_ip_zone(RemoveIpZoneRequest { ip: ip.to_string() })
                    .await;
                if let Err(error) = result {
                    metrics.record_error("ip_zone_remove_rpc");
                    tracing::warn!(%ip, %error, "pod IP-zone remove failed");
                    false
                } else {
                    tracing::info!(%ip, "pod IP-zone remove reconciled");
                    true
                }
            }
        };
        outcomes.push(IpZoneOutcome { intent, ok });
    }
    outcomes
}

fn desired_ip_zone(pod: &Pod) -> Option<AppliedIpZone> {
    if pod.spec.as_ref().and_then(|spec| spec.host_network) == Some(true) {
        return None;
    }
    let zone = pod
        .annotations()
        .get(ZONE_ANNOTATION)
        .map(String::as_str)
        .map(str::trim)
        .filter(|zone| !zone.is_empty())?;
    let ip = pod.status.as_ref()?.pod_ip.as_deref()?;
    let ip = ip.parse::<IpAddr>().ok()?;
    let IpAddr::V4(ip) = ip else {
        return None;
    };
    Some(AppliedIpZone {
        ip,
        zone: zone.to_string(),
    })
}

fn pod_key(pod: &Pod) -> String {
    pod.uid()
        .unwrap_or_else(|| format!("{}/{}", pod.namespace().unwrap_or_default(), pod.name_any()))
}

fn intent_key(intent: &IpZoneIntent) -> String {
    match intent {
        IpZoneIntent::Set { ip, .. } | IpZoneIntent::Remove { ip } => ip.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{PodSpec, PodStatus};
    use kube::api::ObjectMeta;
    use std::collections::BTreeMap;

    fn pod(uid: &str, zone: Option<&str>, ip: Option<&str>, host_network: bool) -> Pod {
        let mut annotations = BTreeMap::new();
        if let Some(zone) = zone {
            annotations.insert(ZONE_ANNOTATION.to_string(), zone.to_string());
        }
        Pod {
            metadata: ObjectMeta {
                name: Some("pod-a".to_string()),
                namespace: Some("default".to_string()),
                uid: Some(uid.to_string()),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: Some(PodSpec {
                host_network: Some(host_network),
                ..Default::default()
            }),
            status: Some(PodStatus {
                pod_ip: ip.map(str::to_string),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn add_change_and_remove_are_keyed_by_uid() {
        let mut reconciler = IpZoneReconciler::new();
        let first = pod("uid-a", Some("zone-a"), Some("10.123.0.2"), false);
        assert_eq!(
            reconciler.reconcile_pod(&first),
            vec![IpZoneIntent::Set {
                ip: "10.123.0.2".parse().unwrap(),
                zone: "zone-a".to_string(),
            }]
        );

        let changed = pod("uid-a", Some("zone-b"), Some("10.123.0.3"), false);
        assert_eq!(
            reconciler.reconcile_pod(&changed),
            vec![
                IpZoneIntent::Remove {
                    ip: "10.123.0.2".parse().unwrap(),
                },
                IpZoneIntent::Set {
                    ip: "10.123.0.3".parse().unwrap(),
                    zone: "zone-b".to_string(),
                },
            ]
        );

        assert_eq!(
            reconciler.delete_pod(&changed),
            vec![IpZoneIntent::Remove {
                ip: "10.123.0.3".parse().unwrap(),
            }]
        );
    }

    #[test]
    fn host_network_unannotated_and_ipv6_pods_are_not_mapped() {
        let mut reconciler = IpZoneReconciler::new();
        assert!(reconciler
            .reconcile_pod(&pod("uid-a", Some("zone-a"), Some("10.123.0.2"), true))
            .is_empty());
        assert!(reconciler
            .reconcile_pod(&pod("uid-b", None, Some("10.123.0.2"), false))
            .is_empty());
        assert!(reconciler
            .reconcile_pod(&pod("uid-c", Some("zone-a"), Some("fd7a::1"), false))
            .is_empty());
    }

    #[test]
    fn duplicate_event_is_idempotent() {
        let mut reconciler = IpZoneReconciler::new();
        let p = pod("uid-a", Some("zone-a"), Some("10.123.0.2"), false);
        assert_eq!(reconciler.reconcile_pod(&p).len(), 1);
        assert!(reconciler.reconcile_pod(&p).is_empty());
    }

    #[test]
    fn late_delete_does_not_remove_reused_ip() {
        let mut reconciler = IpZoneReconciler::new();
        let old_owner = pod("uid-a", Some("zone-a"), Some("10.123.0.2"), false);
        reconciler.reconcile_pod(&old_owner);

        // The IP is reused by a new pod before the old pod's delete event
        // arrives — its Set lands first.
        let new_owner = pod("uid-b", Some("zone-b"), Some("10.123.0.2"), false);
        assert_eq!(
            reconciler.reconcile_pod(&new_owner),
            vec![IpZoneIntent::Set {
                ip: "10.123.0.2".parse().unwrap(),
                zone: "zone-b".to_string(),
            }]
        );

        // The late delete must NOT emit a Remove for the now-live mapping.
        assert!(reconciler.delete_pod(&old_owner).is_empty());
    }

    #[test]
    fn ip_change_does_not_remove_reused_old_ip() {
        let mut reconciler = IpZoneReconciler::new();
        reconciler.reconcile_pod(&pod("uid-a", Some("zone-a"), Some("10.123.0.2"), false));
        // Another pod claims the old IP before uid-a's change event arrives.
        reconciler.reconcile_pod(&pod("uid-b", Some("zone-b"), Some("10.123.0.2"), false));

        // uid-a moves to a new IP: only the Set may be emitted.
        assert_eq!(
            reconciler.reconcile_pod(&pod("uid-a", Some("zone-a"), Some("10.123.0.9"), false)),
            vec![IpZoneIntent::Set {
                ip: "10.123.0.9".parse().unwrap(),
                zone: "zone-a".to_string(),
            }]
        );
    }

    #[test]
    fn same_ip_zone_change_emits_set_only() {
        let mut reconciler = IpZoneReconciler::new();
        reconciler.reconcile_pod(&pod("uid-a", Some("zone-a"), Some("10.123.0.2"), false));
        // Same IP, new zone: the Set overwrites in place; no Remove window.
        assert_eq!(
            reconciler.reconcile_pod(&pod("uid-a", Some("zone-b"), Some("10.123.0.2"), false)),
            vec![IpZoneIntent::Set {
                ip: "10.123.0.2".parse().unwrap(),
                zone: "zone-b".to_string(),
            }]
        );
    }

    #[test]
    fn stale_pending_remove_is_pruned_when_ip_is_reclaimed() {
        let mut reconciler = IpZoneReconciler::new();
        // A Remove RPC failed and sits in the retry queue.
        reconciler.absorb_outcomes(&[IpZoneOutcome {
            intent: IpZoneIntent::Remove {
                ip: "10.123.0.2".parse().unwrap(),
            },
            ok: false,
        }]);
        // A new pod claims the IP before the retry fires.
        reconciler.reconcile_pod(&pod("uid-b", Some("zone-b"), Some("10.123.0.2"), false));
        // The queued Remove must not be replayed (and is dropped).
        assert!(reconciler.pending_intents().is_empty());
    }

    #[test]
    fn failed_intent_is_replayed_until_success() {
        let mut reconciler = IpZoneReconciler::new();
        let intent = IpZoneIntent::Set {
            ip: "10.123.0.2".parse().unwrap(),
            zone: "zone-a".to_string(),
        };
        reconciler.absorb_outcomes(&[IpZoneOutcome {
            intent: intent.clone(),
            ok: false,
        }]);
        assert_eq!(reconciler.pending_intents(), vec![intent.clone()]);

        reconciler.absorb_outcomes(&[IpZoneOutcome { intent, ok: true }]);
        assert!(reconciler.pending_intents().is_empty());
    }
}
