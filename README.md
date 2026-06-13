# Syvä

**Your containers share a kernel. Syvä makes the kernel enforce the boundaries between them.**

[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![release](https://img.shields.io/badge/release-v0.4.0-2ea44f.svg)](CHANGELOG.md)
[![platform](https://img.shields.io/badge/platform-Linux%20%E2%89%A5%205.10%20%C2%B7%20BPF--LSM-informational.svg)](#requirements)
[![enforcement](https://img.shields.io/badge/enforcement-kernel%20proven-8a2be2.svg)](#proof-not-promises)

Syvä is a node-local Linux/eBPF enforcement engine. It puts each workload in a
*zone* and uses kernel **BPF-LSM** hooks to **deny cross-zone operations before
they happen** — reading another zone's files, executing its binaries, debugging
or signaling its processes, talking to its sockets, or reaching the network it
isn't allowed to. The decision lives in the kernel, on the syscall path, and
returns `EPERM` before the operation completes.

No sidecar. No proxy. No remote control plane. Run `syva-core` per node, point
an adapter at it, done.

> *Syvä* (Finnish) — *deep*. Where enforcement happens.

```text
                         one shared kernel
  ┌────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │   zone: frontend                          zone: database         │
  │   ┌───────────────┐                       ┌───────────────┐      │
  │   │  nginx · web   │                       │  postgres      │     │
  │   └───────┬───────┘                       └───────┬───────┘      │
  │           │                                       │              │
  │           │   open   /db/secret    ──────╳        │              │
  │           │   exec   /db/pg_dump   ──────╳        │              │
  │           │   ptrace postgres      ──────╳        │              │
  │           │   connect 10.0.0.5:5432 ─────╳        │              │
  │           │                                       │              │
  │   ════════╪═══════════════  Syvä  ════════════════╪═══════════   │
  │           ▼            (BPF-LSM, on the           ▼              │
  │        syscall          syscall path)          syscall          │
  │                                                                  │
  │   ╳  denied in the kernel, before it happens — returns EPERM     │
  └────────────────────────────────────────────────────────────────┘
```

Same zone — or an explicitly allowed pair — is permitted. Everything else
cross-zone is denied and recorded. An *Isolated* zone (the default) is also
network-locked: it reaches loopback only until you open it.

---

## Contents

- [Why Syvä is different](#why-syvä-is-different)
- [Quickstart (Kubernetes)](#quickstart-kubernetes)
- [Architecture](#architecture)
- [Proof, not promises](#proof-not-promises)
- [Features](#features)
- [Requirements](#requirements)
- [Control surface](#control-surface)
- [How enforcement works](#how-enforcement-works)
- [Limitations (honest)](#limitations-honest)
- [Build, test, and verify](#build-test-and-verify)
- [License](#license)

## Why Syvä is different

- **The kernel decides, not a proxy.** Enforcement is BPF-LSM on the syscall
  path — there is no userspace data path to bypass, no sidecar to outrun.
- **Small frozen mechanism, open policy.** The eBPF layer enforces a handful of
  proven decision *shapes*; everything expressive lives in the data that fills
  the BPF maps, supplied at runtime over one gRPC API. Policy is hot-swappable
  (an `AllowComm` flips a live denial to an allow with no redeploy); the kernel
  surface stays small and auditable. See
  [docs/design/predicate-shapes.md](docs/design/predicate-shapes.md).
- **Proven, both ways.** Reproducible privileged gates assert that Syvä
  *blocks* what it should **and** *doesn't over-block* what it shouldn't —
  because the failure that gets a security tool ripped out is the false denial,
  not the missed one.

## Quickstart (Kubernetes)

```sh
kubectl apply -f deploy/k8s/
```

One apply installs the `SyvaZonePolicy` CRD, the `syva-system` namespace + RBAC,
and the per-node DaemonSet (`syva-core` + `syva-k8s`). Then declare a zone and
annotate workloads:

```sh
kubectl apply -f - <<'EOF'
apiVersion: syva.dev/v1alpha1
kind: SyvaZonePolicy
metadata: { name: payments, namespace: default }
spec: {}
EOF

kubectl annotate pod my-pod syva.false.systems/zone=payments
```

Watch denials explain themselves — zone names, process, path or destination,
and the reason:

```sh
kubectl exec -n syva-system ds/syva -c syva-core -- syvactl events --follow
```

```text
14:22:01Z  DENY  file_open       payments → database  pid=1843 comm=cat  path=/db/secret
              why: cross-zone file open — a workload read another zone's protected file
14:22:07Z  DENY  socket_connect  payments → host      pid=1902 comm=curl dst=10.0.0.5:5432
              why: network egress outside zone policy — destination not allowed for this zone
```

See [docs/deployment/kubernetes.md](docs/deployment/kubernetes.md). For a local
single-node development loop on macOS or Linux, see
[Lima deployment](docs/deployment/lima.md) (`make lima-smoke`).

## Architecture

Policy flows in through adapters; the core compiles it into BPF maps; the kernel
hooks read those maps on every relevant syscall and allow or deny; enriched
events flow back out.

```text
   POLICY — what to enforce                  OBSERVABILITY — what happened
   ┌─────────────────────────────┐          ┌─────────────────────────────┐
   │ syva-file   TOML directory   │          │ syvactl events --follow     │
   │ syva-k8s    SyvaZonePolicy   │          │ /metrics   per-zone denies  │
   │ syva-api    REST proxy       │          │ /healthz   enforcement state│
   │ syvactl     operator CLI     │          └──────────────▲──────────────┘
   └──────────────┬──────────────┘                          │ enriched
                  │  gRPC · syva.core.v1 · Unix socket       │ deny events
                  ▼                                          │
   ┌──────────────────────────────────────────────────────────────────────┐
   │                              syva-core                                 │
   │      zone registry · container membership · ingest → BPF maps         │
   └──────────────────────────────────┬───────────────────────────────────┘
                                       │ writes maps / drains events
   ════════════════════════════════════════════════════════════  userspace
                                       │                              kernel
                                       ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │  BPF maps   ZONE_MEMBERSHIP · ZONE_POLICY · INODE_ZONE_MAP ·           │
   │             ZONE_ALLOWED_COMMS · IP_ZONE_MAP · EGRESS_CIDR · …         │
   │                  ▲                                                     │
   │                  │ read on every relevant syscall                     │
   │   ┌──────────────┴───────────────────────────────────────────────┐   │
   │   │  9 BPF-LSM hooks                                              │   │
   │   │  file_open · bprm_check · mmap_file · ptrace · task_kill      │   │
   │   │  unix_connect · socket_connect · socket_sendmsg · socket_bind │   │
   │   └──────────────────────────────┬───────────────────────────────┘   │
   │                                   ▼   allow (0)  /  deny (EPERM)       │
   └──────────────────────────────────────────────────────────────────────┘
```

| Crate | Role |
| --- | --- |
| `syva-core` | Linux enforcement engine; eBPF load/attach, BPF maps, health/metrics, `syva.core.v1` |
| `syva-proto` | `syva.core.v1` protobuf API |
| `syva-core-client` | shared Unix-socket gRPC client |
| `syvactl` | thin local operator CLI over `syva.core.v1` |
| `syva-adapter-file` (`syva-file`) | TOML policy directory reconciler |
| `syva-adapter-k8s` (`syva-k8s`) | `SyvaZonePolicy` CRD + pod membership reconciler |
| `syva-adapter-api` (`syva-api`) | partial REST proxy to the local core |
| `syva-ebpf` / `syva-ebpf-common` | the eBPF programs and shared `repr(C)` types |
| `xtask` | build / check / verify helper |

## Proof, not promises

Syvä ships reproducible **kernel-level enforcement evidence**, not just unit
tests. Each gate declares a PASS/BLOCK contract, runs against a real kernel, and
asserts real evidence — a per-hook deny-counter delta, an `EPERM` from a live
syscall, a recorded would-deny — never just an exit code.

It proves enforcement works **in both directions**:

- **It blocks** — `verify-integration` (process), `verify-container-integration`
  (a real `docker`/`nerdctl`/`podman` container), `verify-k8s-membership` (an
  annotated pod), `verify-network-lock`, `verify-egress-cidr`,
  `verify-cross-zone-tcp` (pod-IP zone pairs), `verify-inode-identity`
  (cross-filesystem `(dev, ino)` is not zone-confused). Each asserts EPERM +
  `deny_delta=1`.
- **It doesn't over-block** — `verify-allow` proves the must-not-block contract:
  same-zone access, loopback from a locked zone, and an `AllowComm`'d pair stay
  allowed at `deny_delta=0`, with a control in the same run that a real
  cross-zone open *still* denies. A core that blocked everything would fail
  here, so "green" cannot mean "allows nothing through."
- **It loads and observes** — `verify-runtime` (loads the release object,
  attaches all nine hooks, passes the cgroup/inode/unix self-tests),
  `verify-events` (enriched deny stream), `verify-audit-mode` (would-deny
  recorded, operation proceeds), `verify-cgroup-escape` (escape detected, not
  prevented), `verify-deployment` (the deployed DaemonSet blocks a real
  container).

These are privileged Linux + BPF-LSM gates (`#[ignore]`d in normal
`cargo test`); the container gate also needs a container runtime, the Kubernetes
gate a local cluster. Latest evidence:
[docs/release/v0.4.0-runtime-verification.md](docs/release/v0.4.0-runtime-verification.md).

## Features

- **Nine kernel-enforced hooks** — file open, exec, executable `mmap`, `ptrace`,
  signals, Unix-socket connect, and the network lock (outbound
  `connect`/`sendmsg` + `bind`) that makes an Isolated zone loopback-only — all
  via BPF-LSM.
- **Network policy, layered** — per-zone lock/open (`network_mode`), egress CIDR
  allowlists with optional ports (IPv4 + IPv6), and pod-IP → zone mappings so
  cross-zone TCP follows the same `AllowComm` zone-pair rule as everything else.
- **Deny events that explain themselves** — every denial carries zone names, the
  process `comm`, the registered file path or destination `ip:port`, and a
  templated reason (`what_failed` / `why_it_matters` / `possible_causes`),
  streamed live, logged structured, and counted per-zone.
- **Node-local by design** — one `syva-core` per node behind the `syva.core.v1`
  Unix socket; no control plane. Scale with the Kubernetes primitives you run.
- **Adapters for your world** — TOML files (`syva-file`), Kubernetes
  `SyvaZonePolicy` CRDs (`syva-k8s`), or REST (`syva-api`).
- **Audit mode for rollout** — `--mode audit` records would-deny decisions
  without blocking, so you measure impact before enforcing.
- **Observability built in** — `/healthz` (`healthy`/`degraded`/`unsafe` with
  reasons) and `/metrics` (per-hook + per-zone decisions, self-test state, map
  errors); Grafana dashboard and Prometheus alerts under
  [`deploy/monitoring/`](deploy/monitoring/).
- **Fail-open, never fail-dark** — a kernel read failure allows the operation
  but flips health to `degraded` and increments an error counter.

## Requirements

Enforcement runs on Linux only:

- **Linux ≥ 5.10** — the pinned kernel floor (BPF-LSM, the BPF ring buffer, and
  per-superblock tmpfs inode allocation all hold from there).
- **BPF LSM enabled** — `bpf` must appear in `/sys/kernel/security/lsm` (enable
  at boot with `lsm=...,bpf` if it doesn't).
- **cgroup v2** and **kernel BTF** (`/sys/kernel/btf/vmlinux`) — struct offsets
  are resolved from BTF at startup, never hardcoded.
- **Root** (or equivalent BPF privileges) to load and attach the LSM programs.

macOS works for development through the Lima VM; building and testing are
host-safe everywhere.

## Control surface

Policy is **live and programmable**, not a static file format. The canonical
control API is the local gRPC API `syva.core.v1` on the `syva-core` Unix
socket; every adapter and `syvactl` is a client of it. The verbs map straight
to BPF map updates the kernel reads on the next syscall:

- `RegisterZone` / `RemoveZone` — define a zone and its policy
- `AllowComm` / `DenyComm` — open or close a cross-zone pair **at runtime**
- `AttachContainer` / `DetachContainer` — bind a cgroup to a zone
- `RegisterHostPath` — claim files `(dev, ino)` for a zone
- `SetIpZone` / `RemoveIpZone` — map a pod IP to a zone for cross-zone TCP
- `Status` / `WatchEvents` — health + the live enriched deny stream

Because the decision data lives in maps, changes take effect with no reload and
no redeploy — `verify-cross-zone-tcp` exercises exactly this: an `AllowComm`
call flips a live kernel denial to an allow mid-test. (The file adapter also
reconciles TOML on change; "no static policy" is the point.) The REST API
(`syva-api`) is a partial proxy. Full contract and OpenAPI under
[`docs/api/`](docs/api/).

```sh
syvactl status                 # health, hooks, self-tests, counters
syvactl zones list             # registered zones
syvactl comms list             # allowed cross-zone pairs
syvactl events --follow        # live, enriched deny stream
```

## How enforcement works

`syva-core` populates BPF maps; the eBPF programs read them on every relevant
syscall. Every hook follows one decision shape: resolve the caller's zone from
its cgroup, resolve the target's zone (files/exec by `(dev, ino)`), and allow if
the zones match or are an explicitly allowed pair — otherwise deny with `EPERM`.
The three network hooks are the exception: they have no target zone, so a zoned,
non-global caller whose zone lacks network access is denied any non-loopback
`connect` / `sendmsg` / `bind` (unless an egress allowlist or pod-IP zone-pair
permits it).

Kernel struct offsets are resolved from BTF at startup — no hardcoded offsets. A
caller or target not in any zone is invisible to enforcement (allowed).

### Policy → enforcement

What a written policy actually does. Each section of the file-adapter policy
maps to a specific kernel mechanism — or, where there is no LSM hook for it, is
explicitly **planned, not enforced** (parsed and validated, but Syvä does not
enforce it; use the noted alternative). Source of truth is the code, not this
table; it is checked against the hooks and the adapter.

| Policy section | Enforced by | Status |
| --- | --- | --- |
| `[filesystem] host_paths` | `INODE_ZONE_MAP` → `file_open`, `bprm_check`, `mmap_file` | **enforced** |
| `[network] mode` | `ZONE_POLICY` flag → `socket_connect`/`sendmsg`/`bind` (network lock) | **enforced** |
| `[network] allowed_zones` | `ZONE_ALLOWED_COMMS` → every cross-zone hook | **enforced** |
| `[network] allowed_egress` | `EGRESS_CIDR` maps → `socket_connect`/`sendmsg` (CIDR + optional port, v4/v6) | **enforced** |
| `[capabilities] allowed` | only `CAP_SYS_PTRACE` → `ptrace_access_check`; other capabilities are not read by any hook | **partial** (ptrace only) |
| `[network] allowed_ingress` | — no inbound LSM hook | **planned** — use NetworkPolicy / iptables |
| `[resources]` cpu/memory/io/pids | cgroup controllers, not BPF-LSM | **planned** — validated, not enforced by Syvä |
| `[devices] allowed` | device cgroup controller | **planned** |
| `[syscalls] deny` | seccomp | **planned** — use a seccomp profile |
| `[zone]` (name, type) | — | metadata only |

Pod-IP → zone mapping for cross-zone TCP is set through the gRPC `SetIpZone`
(driven by the Kubernetes adapter's cluster-wide pod-IP watch), not the TOML
schema; it enforces via `IP_ZONE_MAP` + `ZONE_ALLOWED_COMMS`.

Container membership is tracked per node (container ID, optional pod identity,
cgroup ID, zone, source adapter, generation); updates are idempotent and
generation-aware. `syva-k8s` reconciles annotated pods into `AttachContainer`
calls after resolving each container's real host cgroup id, and maintains a
cluster-wide pod-IP → zone view for cross-zone TCP.

## Limitations (honest)

- Full eBPF load/attach/runtime verification requires a privileged Linux host
  with BPF LSM; hosted CI can build and test but cannot run the enforcement
  gates (no one grants BPF-LSM on their kernel). Lima covers Linux build/test
  and eBPF object compilation from macOS — not runtime attachment.
- `/proc` and `/sys` coverage is incomplete.
- Cgroup movement / zone escape cannot be **prevented** through BPF-LSM:
  `cgroup_attach_task` is not a BPF-LSM hook on supported mainline kernels. It
  is **detected** instead (counter, `ESCAPE` event, degraded health; proven by
  `verify-cgroup-escape`) — the migration itself is not blocked.
- `INODE_ZONE_MAP` is keyed by composite `(dev, ino)`, so cross-filesystem inode
  collisions are disambiguated (proven by `verify-inode-identity`). Residual:
  sibling subvolumes of one btrfs filesystem share a superblock dev, so same-ino
  files within one btrfs filesystem still alias.
- Pod-IP → zone mapping is IPv4 only so far; `SyvaZonePolicy`
  status/finalizers/leader election are not implemented.

## Build, test, and verify

```sh
make macos-check   # fast host-safe checks (macOS-friendly)
make ci            # full non-privileged gate: fmt, clippy, tests, doc/proto/
                   # api guardrails, release eBPF object build
```

`cargo run -p xtask -- build-ebpf` builds the release eBPF object (the runtime
artifact); `--debug` is for development only. On macOS, `make lima-up` then
`make lima-check` runs the full workspace and eBPF build inside a Lima VM.

Privileged runtime evidence (privileged Linux + BPF LSM; the container gate also
needs a container runtime):

```sh
sudo -E make verify-runtime
sudo -E make verify-integration
sudo -E make verify-container-integration
sudo -E make verify-allow              # the must-not-block contract
sudo -E make verify-events             # enriched deny stream
sudo -E make verify-network-lock
sudo -E make verify-egress-cidr
sudo -E make verify-cross-zone-tcp
sudo -E make verify-inode-identity
sudo -E make verify-audit-mode
sudo -E make verify-cgroup-escape
sudo -E make verify-k8s-membership     # needs a local single-node cluster
```

Run the core directly on Linux:

```sh
RUST_LOG=syva_core=debug cargo run --bin syva-core -- \
  --socket-path /run/syva/syva-core.sock
```

## Container images

Published to GHCR for `linux/amd64` and `linux/arm64` on each version tag:

```text
ghcr.io/false-systems/syva-core:<version>
ghcr.io/false-systems/syva-adapter-k8s:<version>
```

Or build them yourself: `docker build --target syva-core -t syva-core:dev .`
(and `--target syva-adapter-k8s`). See
[docs/deployment/kubernetes.md](docs/deployment/kubernetes.md).

## Roadmap

- Kernel-enforcement contract gates running per-commit on self-hosted runners
  with a small kernel matrix (own kernels are a permanent dependency of building
  this).
- Broader Kubernetes runtime resolver coverage; IPv6 pod-IP mapping.
- Expanded privileged runtime blackbox coverage.

Historical design notes (the removed v0.3 `syva-cp` control-plane experiment and
the legacy monolithic binary) live under [`docs/archive/`](docs/archive/).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in this work
by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
