# Kubernetes Deployment

Syva's Kubernetes path is node-local. The DaemonSet runs `syva-core` and
`syva-k8s` on each node; the adapter talks to the local Unix socket and does not
introduce a remote control plane.

## Quickstart

```sh
kubectl apply -f deploy/k8s/
```

That applies the `SyvaZonePolicy` CRD, the `syva-system` namespace + RBAC, and
the DaemonSet (core + adapter per node). Then declare zones and annotate
workloads:

```sh
kubectl apply -f - <<'EOF'
apiVersion: syva.dev/v1alpha1
kind: SyvaZonePolicy
metadata:
  name: payments
  namespace: default
spec: {}
EOF

kubectl annotate pod my-pod syva.false.systems/zone=payments
```

Watch denials with names, process, path/destination, and reasons:

```sh
kubectl exec -n syva-system ds/syva -c syva-core -- \
  syvactl events --follow
```

The core's socket is also on each node at `/run/syva/syva-core.sock`, so
node-local `syvactl` works directly, and `sudo -E make verify-deployment`
proves the deployed DaemonSet blocks a real container. A file-adapter variant
(TOML policy instead of CRDs) lives at `deploy/k8s/variants/daemonset-file.yaml`.

## Container Images

Released images are published to GHCR for `linux/amd64` and `linux/arm64` by
the `release-images` workflow (`.github/workflows/release-images.yml`), which
runs on version tags and on manual dispatch:

```text
ghcr.io/false-systems/syva-core:<version>
ghcr.io/false-systems/syva-adapter-k8s:<version>
```

The `syva-core` image bundles the release eBPF object at
`/usr/lib/syva/syva-ebpf` (the first path object discovery checks) plus
`syvactl`; the adapter image contains `syva-k8s`.

Builds are two-step: the root `Dockerfile` compiles inside the published
toolchain image `ghcr.io/false-systems/syva-builder` (stable Rust, nightly +
`rust-src`, `bpf-linker`, `protoc`; defined in `docker/builder.Dockerfile`,
published by the `builder-image` workflow) and copies the artifacts into slim
runtime images. To build locally:

```sh
docker build --target syva-core        -t syva-core:dev .
docker build --target syva-adapter-k8s -t syva-adapter-k8s:dev .
```

To rebuild against a locally built toolchain image instead of the published
one, pass `--build-arg BUILDER_IMAGE=<your-builder-ref>`.

Node prerequisites are unchanged by the packaging: a BPF-LSM-enabled kernel
(`bpf` in `/sys/kernel/security/lsm`), cgroup v2, BTF at
`/sys/kernel/btf/vmlinux`, and a containerd-style runtime layout. Images do not
relax any of the privileged requirements in the DaemonSet.

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

Reconciliation is generation-aware and outcome-checked:

- Generations are seeded from the clock at adapter start, so a restarted
  adapter keeps issuing generations above anything a previous instance sent and
  the core's stale-generation fencing keeps working across restarts.
- An attach the core did not confirm (RPC error, stale, or conflict) is rolled
  back in the adapter and retried on the next pod event instead of being
  treated as applied.
- A detach the core did not confirm stays in a pending queue and is re-sent
  with every subsequent event batch until the core acknowledges it.
- The pod watch is scoped to the local node with a `spec.nodeName` field
  selector. If the pod membership watcher itself fails, the adapter exits so
  the DaemonSet restarts it; it never keeps running with membership
  reconciliation silently disabled.

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
cgroup-v2 process paths include the Kubernetes runtime container ID, including
the k3s/containerd layout proven by `verify-k8s-membership`. It does not use
mountinfo-only matches for PID selection because host mount tables can reference
container rootfs paths from unrelated processes. Container IDs shorter than 12
characters are rejected before any `/proc` scan, and the resolved cgroup path is
truncated at the path component naming the container scope, so a process the
workload moved into a nested sub-cgroup still resolves to the container scope
cgroup that enforcement keys on. Runtime-specific resolvers for CRI-O, Docker
variants, or unusual distributions should be added behind the same resolver
boundary.

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

## End-to-End Verification

Implemented:

- annotation-based pod membership assignment,
- local-node pod filtering,
- running-container attach,
- deletion/annotation-change detach,
- generation-aware AttachContainer/DetachContainer calls,
- adapter membership metrics.

The privileged Kubernetes proof is:

```sh
sudo -E make verify-k8s-membership
```

The target expects an existing single-node Kubernetes cluster reachable by
`kubectl` on the same Linux host or VM that runs the command. k3s is the
preferred environment for the current proof because it is the simplest
single-node Lima setup; kind or another local cluster can work only if the pod
runtime's host cgroups are visible under the host `/proc` and `/sys/fs/cgroup`.

At the beginning of the run, the target prints the declared contract:

```text
=== syva k8s membership integration contract ===
PASS: annotated pod in zone-a can read its own zone-a file.
BLOCK: annotated pod in zone-a cannot read protected zone-b file.
ASSIGNMENT: syva.false.systems/zone=zone-a
HOOK: file_open
EXPECTED DENIAL: EPERM / Operation not permitted
EXPECTED KERNEL EVIDENCE: file_open deny_delta=1
```

It then starts a local `syva-core`, starts `syva-k8s` against the current
cluster, registers `syva-it-zone-a` and `syva-it-zone-b`, creates a uniquely
named namespace and annotated pod, waits for the adapter to attach the pod's
container, and proves:

- deploying a Kubernetes pod annotated with a Syva zone,
- proving that pod can read its own zone file,
- proving it is blocked from another zone's file with `EPERM`,
- asserting `file_open deny_delta=1` for that Kubernetes workload.

The output includes the pod namespace/name, node, runtime container ID, resolved
host cgroup-v2 path, resolved cgroup inode/id, `AttachContainer` result, allowed
read result, blocked read result, adapter metrics, and detach result. The target
is rerun-safe: it uses names derived from `syva-k8s-it-<pid>` and removes the
pod, namespace, local processes, and `/tmp/syva-k8s-it-<pid>` on exit.

The target fails red if the pod cannot be attached with a real cgroup id, if the
forbidden read succeeds, if the error is not `EPERM` / `Operation not
permitted`, or if `file_open deny_delta` is not exactly `1`.

Still out of scope:

- cgroup movement / zone escape protection,
- a remote control plane,
- REST expansion,
- UI,
- new BPF hook semantics.
