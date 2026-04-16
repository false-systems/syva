# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Read AGENT.md after this file — it covers how to work, not what exists.

## What This Is

Syva is an eBPF enforcement engine that drops kernel-level container isolation onto existing Linux systems. It populates BPF maps that 7 LSM hooks check on every `open()`, `exec()`, `mmap(PROT_EXEC)`, `kill()`, `ptrace()`, `cgroup_attach()`, and `unix_stream_connect()`.

v0.2 splits Syva into a two-layer architecture: a **core engine** (eBPF + gRPC server) and **adapters** (file/k8s/api) that connect via Unix socket. The core never knows where commands came from.

```
syva-file ──┐
syva-k8s  ──┼── gRPC / Unix socket ──► syva-core ──► 7 LSM hooks
syva-api  ──┘
```

Extracted from the [Rauha](https://github.com/yairfalse/rauha) container runtime. Enforcement-only — doesn't manage containers, images, or networking.

## Build & Test Commands

```bash
cargo build -p syva-proto           # Proto + generated Rust (works on any OS)
cargo build -p syva-ebpf-common     # Shared types (works on any OS)
cargo build -p syva-adapter-api     # REST adapter (works on any OS)
cargo test -p syva-proto            # Proto compile + field tests
cargo test -p syva-ebpf-common      # Type-size + layout tests
cargo test                          # All workspace tests

# Run a single test
cargo test -p syva-ebpf-common -- test_name

# Full workspace build (Linux only — aya requires Linux libc)
cargo build                         # All crates

# eBPF programs (separate workspace, Linux only)
# xtask shells out to `cargo +nightly ... -Z build-std=core` against the
# bpfel-unknown-none target. There is NO rust-toolchain.toml — you must have
# a nightly toolchain installed via rustup before this will work.
cargo run -p xtask -- build-ebpf             # Debug build
cargo run -p xtask -- build-ebpf --release   # Release build

# Run the core engine (Linux only, requires root for BPF)
RUST_LOG=syva_core=debug cargo run --bin syva-core -- --socket-path /run/syva/syva-core.sock

# Run the file adapter (Linux only, connects to running core)
RUST_LOG=syva_file=debug cargo run --bin syva-file -- --policy-dir ./policies

# Legacy monolithic binary (still compiles, v0.1 compat)
RUST_LOG=syva=debug cargo run --bin syva -- --policy-dir ./policies

# Blackbox oracle suite (standalone, not in workspace — see eval/README.md)
SYVA_SOCKET=/tmp/syva-oracle.sock \
  cargo test --manifest-path eval/oracle/Cargo.toml -- case_001 --exact --nocapture

# Spec-driven harness — runs every eval/harness/cases/*.yaml through the oracle
SYVA_SOCKET=/tmp/syva-oracle.sock \
  cargo run --manifest-path eval/harness/Cargo.toml
```

Cross-platform crates: `syva-proto`, `syva-ebpf-common`, `syva-adapter-api`, `xtask`. Everything else requires Linux (aya, containerd-client).

## Architecture

### Two-Layer Design

**Core** (`syva-core`): Loads eBPF, manages BPF maps, runs self-tests, serves gRPC on `/run/syva/syva-core.sock`. Health endpoint on `:9091`. No policy awareness — adapters tell it what to enforce.

**Adapters** (separate binaries): Connect to core via gRPC, translate their domain into core commands:
- `syva-file` — TOML policy files + containerd watcher + hot-reload (v0.1 behavior)
- `syva-k8s` — SyvaZonePolicy CRDs + Pod annotation watcher
- `syva-api` — REST API for programmatic zone management

### gRPC API (`syva-proto`)

12 RPCs defined in `syva-proto/proto/syva_core.proto`:
- **Zone lifecycle**: `RegisterZone`, `RemoveZone`, `ListZones`
- **Container membership**: `AttachContainer`, `DetachContainer`
- **Communication policy**: `AllowComm`, `DenyComm`, `ListComms`
- **Inode registration**: `RegisterHostPath` (supports `recursive` flag)
- **Observability**: `Status` (includes `max_zones`), `WatchEvents` (server streaming)

### Crate Structure

| Crate | Binary | Target | Purpose |
|-------|--------|--------|---------|
| `syva-proto` | — | any | Protobuf definitions + generated server/client code |
| `syva-core` | `syva-core` | Linux | eBPF enforcement engine + gRPC server + health endpoint |
| `syva-adapter-file` | `syva-file` | Linux | TOML policies, containerd watcher, hot-reload |
| `syva-adapter-k8s` | `syva-k8s` | Linux | SyvaZonePolicy CRD + Pod watcher (kube-rs) |
| `syva-adapter-api` | `syva-api` | any | REST API proxy to core gRPC |
| `syva` | `syva` | Linux | Frozen v0.1 monolithic binary — kept for drop-in compat only. Do NOT port new features here; all new work targets the v0.2 core/adapter split. |
| `syva-ebpf-common` | — | `no_std` + userspace | `#[repr(C)]` types shared between kernel and userspace |
| `syva-ebpf` | — | `bpfel-unknown-none` | 7 eBPF LSM programs (separate workspace, nightly) |
| `xtask` | — | any | Build helper for eBPF programs |

### Core Startup Sequence (`syva-core`)

1. Health server (`:9091`, 503 until ready)
2. Load eBPF (BTF offsets from `/sys/kernel/btf/vmlinux`, programs loaded but not attached)
3. Attach 7 LSM hooks
4. 3 self-tests (cgroup, inode, unix socket offset chains) — abort on failure
5. Health → 200, drop `CAP_SYS_ADMIN`
6. gRPC server on Unix socket — wait for adapter connections
7. 30s counter monitoring loop, SIGTERM/SIGINT handler

### Key Files

**syva-core/src/**:
- **rpc/mod.rs** — `SyvaCoreService` implementing all 10 gRPC RPCs. Bridges proto API to `ZoneRegistry` + `EnforceEbpf`. Container ID validation. Zone draining on `DrainingComplete`.
- **ebpf.rs** — `EnforceEbpf`: two-phase load/attach, BPF map management, `register_single_inode()` (non-recursive) and `populate_inode_zone_map()` (recursive), `remove_zone_comm_pair()` (targeted) vs `remove_zone_comms()` (all), 3 self-tests, mutual exclusion on `/sys/fs/bpf/syva/`.
- **zone.rs** — `ZoneRegistry`: zone lifecycle (Pending→Active→Pending, Active→Draining→cleanup). Zone IDs capped at `MAX_ZONES` (4096, BPF Array limit). `revive_draining()` for policy re-add.
- **btf.rs** — Minimal BTF parser. Reads `/sys/kernel/btf/vmlinux`, resolves struct field offsets. Replaces pahole.
- **health.rs** — Axum HTTP: `/healthz` (readiness), `/metrics` (Prometheus text with per-hook counters).
- **events.rs** — Ring buffer drain, `HOOK_NAMES` array (7 entries).

**syva-adapter-file/src/**:
- **policy.rs** — TOML policy loading from directory (filename = zone name)
- **reload.rs** — `PolicyDirWatcher`, `diff_policies()`, `PolicyChange` enum. Diffs only — apply logic uses gRPC.
- **watcher.rs** — Containerd event watcher. Zone names via `watch` channel. cgroup_id resolution.
- **translate.rs** — Local `ZonePolicy` → proto `ZonePolicy`
- **connect.rs** — Unix socket gRPC client with exponential backoff retry
- **types.rs** — Full TOML-deserializable policy types (adapter's concern, not core's)

**syva-adapter-k8s/src/**:
- **crd.rs** — `SyvaZonePolicy` CRD definition (`syva.dev/v1alpha1`)
- **watcher.rs** — kube-rs watch loops for CRDs and Pods
- **mapper.rs** — `syva.dev/zone` annotation, CRD spec → proto translation

### eBPF Programs (`syva-ebpf/src/`)

Seven LSM hooks, all using `bpf_probe_read_kernel`:

| File | LSM Hook | Blocks |
|------|----------|--------|
| `file_guard.rs` | `file_open` | Cross-zone file access. Runs cgroup + inode self-tests on first invocation. |
| `exec_guard.rs` | `bprm_check_security` | Cross-zone binary execution |
| `mmap_guard.rs` | `mmap_file` | Cross-zone `mmap(PROT_EXEC)` |
| `ptrace_guard.rs` | `ptrace_access_check` | Cross-zone debugging. Always denied regardless of `ZONE_ALLOWED_COMMS`. |
| `signal_guard.rs` | `task_kill` | Cross-zone signals |
| `cgroup_lock.rs` | `cgroup_attach_task` | Zone escape via cgroup manipulation |
| `unix_guard.rs` | `unix_stream_connect` | Cross-zone Unix socket connections. Resolves peer cgroup via `sock→sk_cgrp_data`. |

### BPF Maps

9 maps in `syva-ebpf/src/main.rs`: `ZONE_MEMBERSHIP` (cgroup→zone, HashMap), `ZONE_POLICY` (zone→policy, Array, max 4096), `INODE_ZONE_MAP` (inode→zone, HashMap, `NO_PREALLOC`), `ZONE_ALLOWED_COMMS` (cross-zone pairs), `SELF_TEST` + `SELF_TEST_INODE` + `SELF_TEST_UNIX` (offset chain validation), `ENFORCEMENT_COUNTERS` (per-hook per-CPU), `ENFORCEMENT_EVENTS` (ring buffer, 4MB).

### Deployment

Two-container pods sharing a Unix socket via `emptyDir`:
- **File mode** (`deploy/v0.2/daemonset-file.yaml`): `syva-core` + `syva-file` (ConfigMap policies)
- **K8s mode** (`deploy/v0.2/daemonset-k8s.yaml`): `syva-core` + `syva-k8s` (CRD policies, RBAC included)
- **Legacy** (`deploy/syva-daemonset.yaml`): monolithic `syva` binary (v0.1 compat)

DaemonSet probes: startup (tcpSocket, 5s interval, 12 failures), liveness (tcpSocket, 30s), readiness (`GET /healthz`, 10s). PriorityClass `system-node-critical`.

### Subcommands

**syva-core**:
- `syva-core` (no subcommand) — enforcement engine + gRPC server
- `syva-core status` — reads pinned `ENFORCEMENT_COUNTERS`
- `syva-core events --follow [--format text|json]` — streams from ring buffer (ndjson in JSON mode)

**syva-file**:
- `syva-file` (no subcommand) — connect to core, load policies, watch containerd, hot-reload
- `syva-file verify` — dry-run policy validation (standalone, no core needed)

**syva-k8s**: no subcommands. Runs the CRD + Pod watcher loop. Flags only (`--socket-path`, kube-config discovery).

**syva-api**: no subcommands. Flags: `--socket-path` (default `/run/syva/syva-core.sock`), `--port` (default 8080). REST surface:
- `POST /zones` — register zone (body: `{zone_name, policy}`)
- `DELETE /zones/{name}` — remove zone (query: `?drain=true`)
- `POST /zones/{name}/containers` — attach container
- `DELETE /containers/{id}` — detach container
- `POST /zones/{name}/comms` — allow cross-zone comm
- `GET /status` — core status snapshot
- `GET /events` — SSE stream from the ring buffer

### Enforcement Semantics

- **Fail-open on error**: `bpf_probe_read_kernel` failure → allow + increment error counter
- **Zone ID cap**: IDs capped at MAX_ZONES (4096) — `ZONE_POLICY` BPF Array limit
- **Mutual exclusion**: One core instance per node (`/sys/fs/bpf/syva/` pin check)
- **Symmetry**: `AllowComm` is bidirectional (both directions written atomically). Adapters enforce symmetry policy.
- **Unzoned containers**: Not in `ZONE_MEMBERSHIP`, invisible to all hooks. By design.
- **ptrace**: Cross-zone always denied. Intra-zone gated by `POLICY_FLAG_ALLOW_PTRACE`.

### Known Limitations

- `/proc` and `/sys` inodes not in `INODE_ZONE_MAP` — cross-zone `/proc/<pid>/mem` access possible
- `INODE_ZONE_MAP` keyed by `i_ino` alone (not `dev,ino`) — cross-filesystem collisions possible
- `ZONE_FLAG_PRIVILEGED` set in userspace but not checked by any hook (reserved)

## Conventions

- Policies are TOML with `#[serde(deny_unknown_fields)]` (adapter-file concern). See `policies/standard.toml`.
- No `.unwrap()` in production code — use `?` or `.ok_or_else()`.
- Tests go in `#[cfg(test)]` modules within source files.
- Comments explain *why*, not *what*.
- Container IDs validated (hex/dash/underscore, max 128 chars) before use.
- `syva-core` has NO dependency on any adapter crate. Adapters have NO dependency on each other.
- The gRPC socket path `/run/syva/syva-core.sock` is the only contract between core and adapters.
- **Socket ownership & perms**: `syva-core` creates the parent directory if missing, removes any stale socket file, and binds with the process umask — there is no explicit `chmod`. The socket ends up root-owned (core needs `CAP_BPF`/`CAP_SYS_ADMIN` to load anyway), so adapters must either run as root or share the socket through a pod-level `emptyDir` volume (the v0.2 DaemonSets do the latter).
- **Canonical policy shape**: read `policies/standard.toml` first — it is the worked example that every `syva-adapter-file` TOML field is derived from. `ZonePolicy` uses `#[serde(deny_unknown_fields)]`, so typos fail loudly.

## Platform Requirements

- Linux 6.1+ with `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Boot parameter: `lsm=lockdown,capability,bpf`
- BTF at `/sys/kernel/btf/vmlinux` (used for offset resolution, defaults for Linux 6.1+ if unavailable)
- containerd socket at `/run/containerd/containerd.sock` (for file adapter, configurable)
