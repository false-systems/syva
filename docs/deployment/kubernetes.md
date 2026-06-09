# Kubernetes Deployment

Syva's Kubernetes path is node-local. The DaemonSet runs `syva-core` and
`syva-k8s` on each node; the adapter talks to the local Unix socket and does not
introduce a remote control plane.

## Zone Policy

`syva-k8s` watches `SyvaZonePolicy` CRDs and reconciles them into the local
`syva.core.v1` API:

- `RegisterZone`
- `RemoveZone`
- `AllowComm`
- `DenyComm`

The CRD remains the source of truth for zone policy. Selectors are not sent to
`syva-core`; they are Kubernetes adapter concerns.

## Pod Membership

The first supported assignment model is an explicit pod annotation:

```yaml
metadata:
  annotations:
    syva.false.systems/zone: zone-a
```

For pods scheduled to the adapter's local node, `syva-k8s` watches running
containers and calls:

```text
AttachContainer(container_id, zone_name, cgroup_id, source="syva-k8s", generation=N)
```

When the pod is deleted, moves away from the node, stops running, or loses or
changes its annotation, the adapter calls:

```text
DetachContainer(container_id, source="syva-k8s", generation=N+1)
```

Pods without the annotation are ignored.

## Cgroup Resolution

The adapter does not fake cgroup IDs. It attaches a container only when it can
resolve:

1. the runtime container ID from pod `status.containerStatuses[].containerID`,
2. a host process for that container by scanning host `/proc`,
3. the cgroup-v2 path from `/proc/<pid>/cgroup`, and
4. the host cgroup inode from `/sys/fs/cgroup/<path>`.

The DaemonSet mounts host `/proc` at `/host/proc` and host cgroup v2 at
`/sys/fs/cgroup`. Configure alternative paths with:

```sh
syva-k8s \
  --host-proc /host/proc \
  --host-cgroup /sys/fs/cgroup
```

If resolution fails, the adapter does not attach the container. It logs a
structured warning and increments:

```text
syva_k8s_reconcile_errors_total{reason="cgroup_resolution"}
```

The initial resolver is intentionally simple and targets runtimes whose host
cgroup or mountinfo paths include the Kubernetes runtime container ID, including
common containerd/CRI and Docker-style cgroup layouts. Runtime-specific
resolvers for CRI-O or unusual distributions should be added behind the same
resolver boundary.

## Metrics

`syva-k8s` exposes Prometheus text metrics on `--metrics-listen`, default
`0.0.0.0:9092`:

```text
syva_k8s_membership_attach_total{result}
syva_k8s_membership_detach_total{result}
syva_k8s_memberships_active
syva_k8s_reconcile_errors_total{reason}
```

`result` is one of `applied`, `rejected`, `stale`, or `error`.

## Current Proof Level

Implemented:

- annotation-based pod membership assignment,
- local-node pod filtering,
- running-container attach,
- deletion/annotation-change detach,
- generation-aware AttachContainer/DetachContainer calls,
- adapter membership metrics.

Not yet proven by a full Kubernetes end-to-end gate:

- deploying a Kubernetes pod annotated with a Syva zone,
- proving that pod can read its own zone file,
- proving it is blocked from another zone's file with `EPERM`,
- asserting `file_open deny_delta=1` for that Kubernetes workload.

Until `verify-k8s-membership` exists and passes in a privileged Kubernetes
environment, Kubernetes adapter integration should be described as implemented
but not release-proven end to end.

Still out of scope:

- cgroup movement / zone escape protection,
- a remote control plane,
- REST expansion,
- UI,
- new BPF hook semantics.
