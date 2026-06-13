# Syvä

**Your containers share a kernel. Syvä makes the kernel enforce the boundaries between them.**

Syvä is a node-local Linux/eBPF LSM enforcement engine. It puts each workload in
a *zone*, keeps zone membership and policy in BPF maps, and uses kernel LSM hooks
to **deny cross-zone operations before they happen** — file opens, exec,
executable `mmap`, `ptrace`, signals, Unix-socket connects, and network access
(an Isolated zone is locked to loopback only).

Current release: **v0.3.0** (the Kubernetes membership watcher release), on
the v0.2 kernel-enforcement contract; the canonical control API is
`syva.core.v1`. The network lock — `socket_sendmsg` / `socket_bind` and the
per-zone `network_mode` switch — landed after the v0.3.0 tag and is on
`main`, unreleased.

No sidecar. No proxy. No remote control plane. Run `syva-core` per node, point an
adapter at it, done.

> *Syvä* (Finnish) — *deep*. Where enforcement happens.

---

## The idea

Namespaces and cgroups put up structural walls, but nothing checks whether
container A should be allowed to read container B's files, signal its processes,
attach a debugger, or connect to its sockets. The kernel doesn't know these
workloads shouldn't interact.

Syvä makes it know:

```text
 Node
 ════════════════════════════════════════════════
   zone: "frontend"            zone: "database"
  ┌──────────────┐            ┌──────────────┐
  │ nginx        │            │ postgres     │
  │ web          │            │ redis        │
  └──────────────┘            └──────────────┘
        │                            │
        │  open("/db/secret") ───X   │
        │  exec("/db/pg_dump") ──X   │
        │  ptrace(redis_pid) ────X   │
        │  kill(pg_pid) ─────────X   │
        │  connect(10.0.0.5) ────X   │
        │                            │
        X = denied in the kernel, before it happens
```

Same zone — or an explicitly allowed pair — is permitted. Any other cross-zone
operation is denied with `EPERM` and recorded in per-hook counters and the event
stream. An *Isolated* zone (the default network mode) is additionally
network-locked: non-loopback TCP/UDP connect, datagram send, and bind are
denied in the kernel, so the zone reaches loopback only.

## Proof, not promises

Syvä ships with reproducible **kernel-level enforcement evidence**, not just unit
tests. Each gate prints its declared PASS/BLOCK contract *before* it runs and
then asserts real kernel evidence — a per-hook deny counter delta, an `EPERM`
from a live syscall, a recorded would-deny, or an escape detection — not just
exit codes:

- `verify-runtime` — loads the release eBPF object, attaches all nine BPF-LSM
  hooks, and passes the cgroup / inode / unix self-tests.
- `verify-integration` — a zoned process reads its own zone's file (allowed) but
  is blocked from another zone's file with `EPERM`.
- `verify-container-integration` — the same denial against a **real container**
  (`docker` / `nerdctl` / `podman`).
- `verify-k8s-membership` — an annotated Kubernetes pod is attached by
  `syva-k8s` and blocked from a zone-b file by `file_open` enforcement.
- `verify-audit-mode` — with `--mode audit`, the same cross-zone read is
  recorded as a would-deny decision but **not** blocked (observe-only rollout
  path).
- `verify-network-lock` — an Isolated zone is denied non-loopback
  `connect`/`sendmsg`/`bind` with `EPERM` (loopback only), while a Bridged zone
  is allowed out (the per-zone lock/open switch).
- `verify-cgroup-escape` — a zoned task migrating out of its cgroup is
  **detected** (counter + degraded health). Detection only — BPF-LSM cannot
  block cgroup movement on supported kernels.
- `verify-egress-cidr` — a network-locked zone reaches only its allowlisted
  IPv4/IPv6 CIDRs and optional destination ports; every other destination stays
  denied with `EPERM`.
- `verify-inode-identity` — a cross-filesystem inode-number collision is not
  zone-confused: the unzoned same-ino file on another filesystem stays
  readable while the genuinely zoned file is still denied (composite
  `(dev, ino)` file identity).
- `verify-cross-zone-tcp` — exact IPv4 pod-IP-to-zone mappings make TCP
  connect use the zone-pair rule: same-zone allowed, cross-zone denied until
  `AllowComm`.

These are privileged Linux + BPF-LSM gates (the container gate also needs a
container runtime, and the Kubernetes gate needs `kubectl` against a local
single-node cluster); they are `#[ignore]`d in normal `cargo test`. See
[docs/release/v0.2-runtime-verification.md](docs/release/v0.2-runtime-verification.md).

## Features

- **Nine kernel-enforced hooks** — file open, exec, executable `mmap`,
  `ptrace`, signals, Unix-socket connect, and the network lock (outbound
  `connect`/`sendmsg` + `bind`) that makes an Isolated zone loopback-only, all
  via BPF-LSM.
- **Node-local by design** — one `syva-core` per node behind the `syva.core.v1`
  Unix socket; no control plane. Scale with the Kubernetes primitives you
  already run.
- **Adapters for your world** — TOML files (`syva-file`), Kubernetes
  `SyvaZonePolicy` CRDs (`syva-k8s`), or REST (`syva-api`).
- **Operator CLI** — `syvactl` talks to a running core over gRPC:
  `status`, `zones list/register/remove`, `host-paths register`,
  `comms list/allow/deny`, and `events --follow`.
- **Audit mode for rollout** — `syva-core --mode audit` records every
  would-deny decision (per-hook counters + `WOULD_DENY` events) without
  blocking, so you can measure impact before enforcing. The mode is exposed in
  `/healthz` and metrics and proven by `verify-audit-mode`.
- **Observability built in** — `/healthz` (`healthy` / `degraded` / `unsafe`
  with reasons) and `/metrics` (per-hook decisions, self-test state, BPF map
  errors, membership outcomes); Grafana dashboard and Prometheus alerts under
  [`deploy/monitoring/`](deploy/monitoring/).
- **Fail-open, never fail-dark** — a kernel read failure allows the operation but
  flips health to `degraded` and increments an error counter.
- **One-command dev deploy** — `make lima-smoke` deploys to a Lima VM and proves
  a real container gets blocked.

## Requirements

Enforcement runs on Linux only:

- **BPF LSM enabled** — `bpf` must appear in `/sys/kernel/security/lsm`
  (enable at boot with `lsm=...,bpf` if it doesn't).
- **cgroup v2** and **kernel BTF** (`/sys/kernel/btf/vmlinux`) — struct
  offsets are resolved from BTF at startup, never hardcoded.
- **Root** (or equivalent BPF privileges) to load and attach the LSM programs.

macOS works for development through the Lima VM below; building and testing
are host-safe everywhere.

## Quickstart (Lima development VM)

A single-node development deployment that deploys `syva-core` as a node-local
agent and proves the *deployed* instance blocks a real container's cross-zone
`file_open`:

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

## Architecture

```text
syva-file ──┐
syva-k8s  ──┤
syva-api  ──┼── gRPC over Unix socket ──► syva-core ──► eBPF LSM hooks
syvactl   ──┘        syva.core.v1                       BPF maps
```

| Crate | Role |
| --- | --- |
| `syva-core` | Linux enforcement engine; eBPF load/attach, BPF maps, health/metrics, `syva.core.v1` |
| `syva-proto` | `syva.core.v1` protobuf API |
| `syva-core-client` | shared Unix-socket gRPC client |
| `syvactl` | thin local operator CLI over `syva.core.v1` |
| `syva-adapter-file` (`syva-file`) | TOML policy directory reconciler |
| `syva-adapter-k8s` (`syva-k8s`) | `SyvaZonePolicy` CRD reconciler |
| `syva-adapter-api` (`syva-api`) | partial REST proxy to the local core |
| `syva-ebpf` / `syva-ebpf-common` | the eBPF programs and shared `repr(C)` types |
| `xtask` | build / check / verify helper |

The v0.3 `syva-cp` control-plane experiment (and the legacy monolithic `syva`
binary) were removed; historical design notes live under
[`docs/archive/`](docs/archive/).

## How enforcement works

`syva-core` populates BPF maps; the eBPF programs read them on every relevant
syscall. Every hook follows one decision shape: resolve the caller's zone from
its cgroup, resolve the target's zone (files/exec by inode), and allow if the
zones match or are an explicitly allowed pair — otherwise deny with `EPERM`.
The three network hooks are the one exception: they have no target zone — a
zoned, non-global caller whose zone lacks network access is denied any
non-loopback `connect` / `sendmsg` / `bind`.

Maps on the hot path:

- `ZONE_MEMBERSHIP` — cgroup → zone
- `ZONE_POLICY` — zone policy flags
- `INODE_ZONE_MAP` — protected file `(dev, ino)` → zone
- `ZONE_ALLOWED_COMMS` — explicitly allowed cross-zone pairs
- `ENFORCEMENT_MODE` — the global enforce / audit switch
- `ENFORCEMENT_COUNTERS` / `ENFORCEMENT_EVENTS` — observability
- `CGROUP_ESCAPE_COUNT` — detected cgroup-escape events

Kernel struct offsets are resolved from BTF at startup, so there are no
hardcoded offsets. A caller or target not in any zone is invisible to
enforcement.

## Control surface

The canonical control API is the local gRPC API `syva.core.v1` on the
`syva-core` Unix socket — adapters and `syvactl` are clients of it. The REST API
(`syva-api`) is partial. Full API contract, generation/error semantics, and the
OpenAPI document live under [`docs/api/`](docs/api/).

```sh
syvactl status                 # gRPC Status: health, hooks, self-tests, counters
syvactl zones list             # registered zones
syvactl comms list             # allowed cross-zone pairs
syvactl events --follow        # live enforcement deny stream
```

`syva-core status` shows the same gRPC status (falling back to pinned BPF
counters if the socket is unavailable); `syva-core events --follow` streams deny
events directly from the ring buffer.

## Membership

`syva-core` tracks container membership (container ID, optional pod identity,
cgroup ID, zone, source adapter, source generation, observed timestamp). Updates
are idempotent and generation-aware: stale updates are ignored, conflicting zone
assignments are reported, and successful observations produce explicit BPF map
update intents.

`syva-k8s` includes an annotation-based membership watcher. Pods scheduled to
the local node with `syva.false.systems/zone: <zone>` are reconciled into
`AttachContainer` calls after the adapter resolves each running container's real
host cgroup id. Pods without that annotation are ignored. `syva-file` still
reconciles zones, host paths, and communication policy only; it does not watch
workload membership yet.

## Limitations (honest)

- Full eBPF build/load/runtime verification requires Linux with BPF LSM support.
  Lima verifies Linux build/test and eBPF object compilation from macOS, but
  runtime load/attach enforcement still needs a privileged Linux host or CI
  runner.
- `/proc` and `/sys` coverage is incomplete.
- Cgroup movement / zone escape cannot be **prevented** through BPF-LSM:
  `cgroup_attach_task` is not a BPF-LSM hook on supported mainline kernels. It
  is **detected** instead — a best-effort fentry program records a zoned task
  leaving its cgroup (counter, `ESCAPE` event, degraded health; proven by
  `verify-cgroup-escape`) — but the migration itself is not blocked.
- `INODE_ZONE_MAP` is keyed by composite `(dev, ino)` (the kernel superblock
  `s_dev` plus `i_ino`), so cross-filesystem inode collisions are
  disambiguated — proven by `verify-inode-identity`. Residual: all subvolumes
  of one btrfs filesystem share a superblock, so same-ino files in *sibling
  subvolumes of the same filesystem* still alias.
- `SyvaZonePolicy` status / finalizers / leader election are not implemented.
- Kubernetes membership assignment is annotation-based. The
  `verify-k8s-membership` gate proves it end to end only when run on a
  privileged Linux/Kubernetes node; it is not covered by macOS checks.

## Container images

`syva-core` and `syva-adapter-k8s` images are published to GHCR for
`linux/amd64` and `linux/arm64` on each version tag (see
`docs/deployment/kubernetes.md`):

```text
ghcr.io/false-systems/syva-core:<version>
ghcr.io/false-systems/syva-adapter-k8s:<version>
```

Or build them yourself from the repo `Dockerfile`:

```sh
docker build --target syva-core        -t syva-core:dev .
docker build --target syva-adapter-k8s -t syva-adapter-k8s:dev .
```

## Build, test, and verify

Fast host-safe checks (macOS-friendly):

```sh
make macos-check
```

Full non-privileged gates (formatting, clippy, workspace tests, eval crate
builds, proto/OpenAPI/API-doc checks, release-doc drift check, and the release
eBPF object build):

```sh
make ci          # or: make fmt / make lint / make test / make precommit
```

`cargo run -p xtask -- build-ebpf` builds the release eBPF object by default; use
`--debug` only for development experiments.

macOS uses Lima as the Linux bridge for the full workspace and eBPF build:

```sh
make lima-up
make lima-check
```

Privileged runtime evidence (privileged Linux + BPF LSM; the container gate also
needs a container runtime):

```sh
sudo -E make verify-runtime
sudo -E make verify-integration
sudo -E make verify-container-integration
sudo -E make verify-k8s-membership
sudo -E make verify-audit-mode
sudo -E make verify-network-lock
sudo -E make verify-egress-cidr
sudo -E make verify-cross-zone-tcp
sudo -E make verify-cgroup-escape
sudo -E make verify-inode-identity
```

## Run it directly

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

- Broader Kubernetes runtime resolver coverage.
- Expanded privileged runtime blackbox coverage.
- Privileged runtime verification in a self-hosted (or otherwise suitable)
  Linux CI path.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in this work
by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
