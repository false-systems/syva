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

Syva v0.2 currently builds six BPF-LSM hooks: file open, exec,
executable mmap, ptrace, signals, and Unix stream connect. The hot path is
map-based:

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
- Cgroup movement / zone escape protection is not enforced through BPF-LSM in
  v0.2. `cgroup_attach_task` is not a BPF-LSM hook on supported mainline
  kernels; this needs a follow-up using a valid cgroup BPF mechanism or another
  kernel-supported hook.
- `INODE_ZONE_MAP` is still keyed by inode number only, not `(dev, ino)`, so
  cross-filesystem inode collisions remain a known correctness risk.
- `SyvaZonePolicy` status/finalizers/leader election are not implemented.
- Operational alerting around degraded health is still a follow-up.

## Local Checks

Fast host-safe checks:

```sh
make macos-check
```

Linux-only checks:

```sh
make fmt
make lint
make test
make precommit
make ci
```

`make precommit` and `make ci` are non-privileged gates: formatting, clippy,
workspace tests, eval crate builds, release-doc drift checks, proto build check,
and release eBPF object build. They do not run BPF-LSM attach or container
runtime tests. On macOS, run the full gate through Lima with `make lima-check`;
direct host checks are limited to `make macos-check` and the lightweight
pre-commit hooks.

`cargo run -p xtask -- build-ebpf` builds the release eBPF object by default. Use
`cargo run -p xtask -- build-ebpf --debug` only for development experiments.

Optional pre-commit hook setup:

```sh
pipx install pre-commit
pre-commit install
pre-commit run --all-files
```

The hook set runs fast formatting/proto/release-doc checks. Run
`make precommit` before pushing release-candidate changes.

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
sudo -E make verify-integration
sudo -E make verify-container-integration
```

All three are **privileged Linux / BPF-LSM** gates (the container gate also needs
a container runtime); they are `#[ignore]`d in normal `cargo test`.

`verify-runtime` runs the ignored local-mode runtime tests explicitly. It checks
Linux, root, and the required `syva` group before attempting BPF load/attach,
self-tests, and local core RPC verification.

`verify-integration` uses the same privileged preflight, then proves a real
kernel denial: a zone-a workload in a cgroup can read a zone-a file but is
blocked with `EPERM` when reading a zone-b file. This is process/cgroup
enforcement evidence, not container runtime discovery.

`verify-container-integration` proves the same `file_open` denial against a
**real container** (`docker`/`nerdctl`/`podman`; override with
`SYVA_CONTAINER_RUNTIME`). It requires a container runtime in addition to the
privileged BPF-LSM preflight, and fails clearly rather than falling back to a
process test. It proves one container-backed `file_open` path, not every hook.

See [docs/release/v0.2-runtime-verification.md](docs/release/v0.2-runtime-verification.md).

## Deployment (Lima development)

A single-node development deployment path exists for the Lima VM. It deploys
`syva-core` as a node-local agent and proves the *deployed* instance blocks a
real container's cross-zone `file_open`:

```sh
make lima-up
make lima-bootstrap          # install/verify deps (idempotent)
make lima-deploy             # build + install + start syva-core, prove healthy
make lima-verify-deployment  # prove the deployed core blocks a real container
make lima-undeploy           # stop and clean up
```

`make lima-smoke` runs bootstrap → deploy → verify → undeploy in one command.
This is a development deployment proof, not a production/Kubernetes install. See
[docs/deployment/lima.md](docs/deployment/lima.md).

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
`AttachContainer`, adding `(dev, ino)` file identity, expanding privileged
runtime blackbox coverage, and moving privileged runtime verification into a
self-hosted or otherwise suitable Linux CI path.
