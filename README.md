# Syva

Syva is a local Linux/eBPF LSM enforcement engine for container and Kubernetes
workloads. It runs per node, keeps zone membership and policy in BPF maps, and
uses kernel hooks to deny cross-zone operations before they complete.

Syva v0.2 is intentionally small:

- `syva-core` owns eBPF load/attach, BPF maps, health, metrics, and the local
  `syva.core.v1` Unix-socket API.
- `syva-file`, `syva-k8s`, and `syva-api` are adapters that translate local
  files, Kubernetes CRDs, or REST calls into `syva-core` commands.
- There is no active Syva control plane in this repository.

## Problem

Containers share a kernel. Namespaces and cgroups shape isolation, but they do
not encode whether one workload should be allowed to read another workload's
files, signal its processes, attach a debugger, or connect to its Unix sockets.

Syva adds a node-local enforcement layer:

1. Adapters define zones and policy.
2. `syva-core` maps containers/cgroups and protected host paths to zones.
3. eBPF LSM hooks resolve caller and target zones and allow or deny.

## Architecture

```text
syva-file ──┐
syva-k8s  ──┼── gRPC over Unix socket ──► syva-core ──► eBPF LSM hooks
syva-api  ──┘        syva.core.v1          BPF maps
```

Active components:

- `syva-proto`: `syva.core.v1` protobuf API.
- `syva-core-client`: shared Unix-socket gRPC client for adapters.
- `syva-core`: Linux enforcement engine.
- `syva-adapter-file`: TOML policy directory reconciler.
- `syva-adapter-k8s`: `SyvaZonePolicy` CRD reconciler.
- `syva-adapter-api`: REST proxy to the local core API.
- `syva-ebpf-common`: shared `repr(C)` userspace/eBPF types.
- `syva-ebpf`: separate nightly eBPF workspace.
- `xtask`: build/check helper.

The previous v0.3 `syva-cp` control-plane experiment, CP client, CP proto, CP
reconciler, CP deployment manifests, and legacy monolithic `syva` binary have
been removed from the active workspace. Historical CP design notes live under
`docs/archive/`.

## Enforcement

Syva currently builds hooks for file open, exec, executable mmap, ptrace,
signals, cgroup attach, and Unix stream connect. The hot path is map-based:

- `ZONE_MEMBERSHIP`: cgroup to zone.
- `ZONE_POLICY`: zone policy flags.
- `INODE_ZONE_MAP`: protected inode to zone.
- `ZONE_ALLOWED_COMMS`: explicitly allowed cross-zone pairs.
- `ENFORCEMENT_COUNTERS` and `ENFORCEMENT_EVENTS`: observability.

Kernel read failures fail open for node safety, but Syva treats them as degraded
security. Hook error/lost counters move health from `healthy` to `degraded`.
Missing BPF attachment is `unsafe` and returns an unhealthy readiness status.

## Membership

`syva-core` has a membership service for:

- container ID
- optional Kubernetes pod namespace/name/UID
- cgroup ID
- zone name and zone ID
- source adapter
- source generation
- observed timestamp

Membership updates are idempotent and generation-aware. Stale updates are
ignored, conflicting zone assignments are reported, and successful observations
produce explicit BPF map update intents.
For detach, generation `0` means the caller does not have a source generation
and the container is detached regardless of the stored generation.

The automatic file and Kubernetes pod/container watcher integration is not
finished in this round. Those adapters reconcile zones, host paths, and
communication policy; container membership must currently be supplied through
`syva.core.v1 AttachContainer` until the watcher path is wired end to end.

## Limitations

- Full eBPF build/load/runtime verification requires Linux with BPF LSM support.
- Lima verifies Linux build/test/eBPF object compilation from macOS, but runtime
  load/attach enforcement still needs a privileged Linux host or CI runner.
- `/proc` and `/sys` coverage is incomplete.
- `INODE_ZONE_MAP` is still keyed by inode number only, not `(dev, ino)`, so
  cross-filesystem inode collisions remain a known correctness risk.
- `SyvaZonePolicy` status/finalizers/leader election are not implemented.
- Operational alerting around degraded health is still a follow-up.

## Local Checks

Fast host-safe checks:

```sh
cargo fmt --all -- --check
cargo test -p syva-proto -p syva-ebpf-common -p syva-adapter-api
cargo check -p syva-proto -p syva-ebpf-common -p syva-adapter-api -p syva-core-client
```

Linux-only checks:

```sh
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --manifest-path eval/oracle/Cargo.toml
cargo build --manifest-path eval/harness/Cargo.toml
cargo run -p xtask -- build-ebpf
```

## Testing on macOS with Lima

macOS developers should use Lima as the supported Linux bridge:

```sh
limactl start ./lima/syva.yaml
limactl shell syva-dev
cargo test --workspace
```

Repo commands wrap the same flow:

```sh
make lima-up
make lima-check
make lima-test
make lima-shell
```

`make lima-check` runs the active Linux validation path through `xtask ci`:
format check, clippy, workspace check, workspace tests, eval crate builds, and
eBPF object build.

## Runtime Verification

Before tagging v0.2, capture runtime evidence on a privileged Linux host with
BPF LSM support:

```sh
sudo -E make verify-runtime
```

This runs the ignored local-mode runtime tests explicitly. It checks Linux,
root, and the required `syva` group before attempting BPF load/attach and local
core RPC verification. See [docs/release/v0.2-runtime-verification.md](docs/release/v0.2-runtime-verification.md).

## Run

Linux only, with the required BPF privileges and kernel config:

```sh
RUST_LOG=syva_core=debug cargo run --bin syva-core -- \
  --socket-path /run/syva/syva-core.sock
```

Then point an adapter at the local socket:

```sh
RUST_LOG=syva_file=debug cargo run --bin syva-file -- \
  --policy-dir ./policies \
  --core-socket /run/syva/syva-core.sock
```

## Roadmap

Next work should focus on wiring real pod/container watchers into
`AttachContainer`, adding `(dev, ino)` file identity, and exercising runtime
load/attach behavior on a privileged Linux host in CI or blackbox tests.
