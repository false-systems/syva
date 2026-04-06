# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Syva is a standalone eBPF enforcement agent that drops kernel-level container isolation onto existing Kubernetes/containerd clusters. No runtime replacement needed — it watches containerd events, maps workloads to zones by OCI annotation (`syva.dev/zone`), and populates BPF maps that 7 LSM hooks check on every `open()`, `exec()`, `mmap(PROT_EXEC)`, `kill()`, `ptrace()`, `cgroup_attach()`, and `unix_stream_connect()`.

Extracted from the [Rauha](https://github.com/yairfalse/rauha) container runtime as a separate product. Syva is enforcement-only — it doesn't manage containers, images, or networking.

## Build & Test Commands

```bash
cargo build -p syva-ebpf-common    # Build shared types (works on any OS)
cargo build -p xtask               # Build the eBPF build helper
cargo test -p syva-ebpf-common     # Run type-size + layout tests (7 default; 11 with `userspace` feature)
cargo test                         # All workspace tests

# Run a single test
cargo test -p syva-ebpf-common -- test_name

# Full workspace build (Linux only — aya crate requires Linux libc)
cargo build                        # Builds syva binary + syva-ebpf-common + xtask

# eBPF programs (separate workspace, requires nightly + Linux)
cargo run -p xtask -- build-ebpf             # Debug build
cargo run -p xtask -- build-ebpf --release   # Release build

# Run the agent (Linux only, requires root for BPF)
RUST_LOG=syva=debug cargo run --bin syva -- --policy-dir ./policies

# Run with a custom eBPF object (useful when iterating on eBPF programs)
RUST_LOG=syva=debug cargo run --bin syva -- --policy-dir ./policies --ebpf-obj ./target/bpfel-unknown-none/debug/syva-ebpf
```

The `syva` binary and `syva-ebpf` programs do not compile on macOS — `aya` uses Linux-specific libc symbols (netlink, bpf syscalls). Only `syva-ebpf-common` and `xtask` are cross-platform.

## Architecture

### Startup Sequence

1. **Load**: `EnforceEbpf::load()` reads BTF, resolves kernel struct offsets via pahole, injects them as globals into the eBPF object, loads 7 LSM programs via aya. Programs are loaded but **not attached** — no enforcement yet. `Drop` impl cleans up pins on failure.
2. **Policy-driven zone setup**: All policy files get zone IDs, `ZONE_POLICY` (Array), `ZONE_ALLOWED_COMMS`, and `INODE_ZONE_MAP` populated at startup — regardless of running containers.
3. **Discover**: `enumerate_cgroups()` walks `/sys/fs/cgroup` (max depth 8) looking for containerd-managed cgroups, reads each container's OCI `config.json` for the `syva.dev/zone` annotation. Uses retry loop (10 attempts, linear backoff 50ms × attempt, ~2.25s total window). Container IDs validated against `is_valid_container_id()` (hex/dash/underscore only, max 128 chars).
4. **Attach**: `attach_programs()` activates all 7 hooks atomically. This happens AFTER zone membership is populated, eliminating the startup race window where hooks would be active but `ZONE_MEMBERSHIP` is empty.
5. **Self-test**: `verify_self_test()` polls `SELF_TEST` map (20 × 50ms ≈ 1s) to verify cgroup offset chain. `verify_inode_self_test()` validates `FILE_F_INODE_OFFSET` and `INODE_I_INO_OFFSET` by comparing BPF-derived inode against userspace `stat()`. Aborts startup on mismatch.
6. **Cap drop**: `drop_unnecessary_capabilities()` drops `CAP_SYS_ADMIN` from the bounding set. BPF map operations use already-open file descriptors.
7. **Watch**: `watch_containerd_events()` subscribes to containerd's gRPC event stream for live container start/stop events, updating BPF maps in real time.
8. **Stream**: Ring buffer (4MB) drains deny events every 100ms in `block_in_place`, capped at 1000 events/tick. Lost events counted per-hook in `EnforcementCounters.lost`.
9. **Monitor**: Every 30s, enforcement error counters are checked. New errors trigger `tracing::warn` with hook name and guidance.

### Crate Structure

| Crate | Target | Purpose |
|-------|--------|---------|
| `syva` | Linux userspace | Main binary — CLI, eBPF lifecycle, containerd watcher, policy loading |
| `syva-ebpf-common` | `no_std` + userspace | `#[repr(C)]` types shared between kernel and userspace BPF maps. Has `userspace` feature flag — `syva` depends on it with this feature enabled; `syva-ebpf` uses it without (pure `no_std`) |
| `syva-ebpf` | `bpfel-unknown-none` | 7 eBPF LSM programs (separate workspace, nightly Rust) |
| `xtask` | any | Build helper — `cargo run -p xtask -- build-ebpf` |

### Key Files in `syva/src/`

- **zone.rs** — `ZoneRegistry`: single source of truth for zone lifecycle (Pending→Active→Pending). Enforces invariants: zone_id 0 reserved (wrapping_add with exhaustion check), stable IDs per name, refcount-based state transitions, duplicate container_id rejection, rollback on failure. `register_zone()` returns `Result<u32>`.
- **ebpf.rs** — `EnforceEbpf` struct: two-phase load (`load()` + `attach_programs()`), manages all BPF maps (membership, policy as Array, comms, inodes), resolves kernel offsets via pahole with word-boundary matching, verifies both cgroup and inode self-tests, mutual exclusion on `/sys/fs/bpf/syva/`. `populate_inode_zone_map()` does recursive scanning (depth 16) with cycle detection and path canonicalization. `Drop` impl cleans up pins.
- **watcher.rs** — Containerd integration: cgroup enumeration (depth-limited), live event subscription via gRPC, cgroup_id resolution from `/proc/{pid}/cgroup`, container ID validation (`is_valid_container_id`), retry loop for OCI config availability. Uses `mapper::LABEL_ZONE` for annotation key.
- **events.rs** — Ring buffer drain via `block_in_place` (100ms interval, 1000 event cap), `HOOK_NAMES` array (7 entries, pub).
- **policy.rs** — Scans a directory of `.toml` files, filename = zone name, deserializes directly into `ZonePolicy`
- **types.rs** — Policy types with `#[serde(deny_unknown_fields)]` on `ZonePolicy` and all sub-structs. `ZoneMetadata` for the `[zone]` TOML section. `validate()` checks resource bounds AND array size limits (host_paths ≤ 1000, allowed_zones ≤ 100, capabilities ≤ 41). Warns about non-enforced declarative fields.
- **mapper.rs** — Single source of truth for annotation key constants (`LABEL_ZONE = "syva.dev/zone"`, `LABEL_POLICY`).
- **main.rs** — CLI, startup orchestration with deferred attach, zone refcounting, 30s error counter monitoring, `drop_unnecessary_capabilities()`, live event loop.

### eBPF Programs (`syva-ebpf/src/`)

Seven LSM hooks, all using `bpf_probe_read_kernel` for verifier-safe kernel memory access:

| File | LSM Hook | Blocks |
|------|----------|--------|
| `file_guard.rs` | `file_open` | Cross-zone file access (via INODE_ZONE_MAP). Also runs inode self-test on first invocation. |
| `exec_guard.rs` | `bprm_check_security` | Cross-zone binary execution (via INODE_ZONE_MAP) |
| `mmap_guard.rs` | `mmap_file` | Cross-zone `mmap(PROT_EXEC)` — prevents code execution via shared library mapping |
| `ptrace_guard.rs` | `ptrace_access_check` | Cross-zone debugging. Reads `mode` arg for granularity. Cross-zone ptrace always denied regardless of `ZONE_ALLOWED_COMMS`. |
| `signal_guard.rs` | `task_kill` | Cross-zone signals |
| `cgroup_lock.rs` | `cgroup_attach_task` | Zone escape via cgroup manipulation. Intra-zone migration permitted by design. |
| `unix_guard.rs` | `unix_stream_connect` | Audit-only — emits events for cross-zone Unix socket connects. Full enforcement deferred pending peer cgroup resolution. |

Kernel struct offsets are patched at load time via `BpfLoader::set_global()`. Two self-tests validate offset chains: `SELF_TEST` (cgroup offsets) and `SELF_TEST_INODE` (file/inode offsets).

### BPF Maps

8 maps defined in `syva-ebpf/src/main.rs`: `ZONE_MEMBERSHIP` (cgroup→zone, HashMap), `ZONE_POLICY` (zone→policy, Array — O(1) lookup by dense zone_id), `INODE_ZONE_MAP` (inode→zone, HashMap with `BPF_F_NO_PREALLOC` — saves ~17MB idle memory), `ZONE_ALLOWED_COMMS` (cross-zone pairs, bidirectional), `SELF_TEST` (cgroup offset validation), `SELF_TEST_INODE` (file/inode offset validation), `ENFORCEMENT_COUNTERS` (per-hook per-CPU, 16 entries for headroom), `ENFORCEMENT_EVENTS` (ring buffer, 4MB).

### Zone Lifecycle

- **Refcounting**: Each zone has a reference count tracking active containers. When the last container leaves (zone goes Pending), only `ZONE_MEMBERSHIP` is cleaned up. `ZONE_POLICY`, `ZONE_ALLOWED_COMMS`, and `INODE_ZONE_MAP` persist until agent shutdown — this is intentional (re-activation is free).
- **allowed_zones symmetry**: Both zones must list each other in `network.allowed_zones`. One-sided declarations are logged as warnings and neither direction is written.
- **Duplicate protection**: `add_container()` rejects duplicate container_ids. `register_zone()` returns `Result<u32>` with zone ID exhaustion check (prevents wrap to ZONE_ID_HOST=0).

### Subcommands

- `syva` (no subcommand) — main enforcement loop
- `syva status` — reads pinned `ENFORCEMENT_COUNTERS` and prints per-hook allow/deny/error/lost totals. Flags hooks with errors or lost events.
- `syva events --follow` — streams deny events from pinned `ENFORCEMENT_EVENTS` ring buffer to stdout

### Mutual Exclusion

Syva refuses to load if BPF maps are already pinned at `/sys/fs/bpf/syva/`. Only one instance can run per node. The DaemonSet includes an init container (`cleanup-stale-bpf-pins`) that runs `rm -rf /sys/fs/bpf/syva` before the agent starts, preventing CrashLoopBackOff after OOM/SIGKILL.

### Enforcement Semantics

- **Fail-open on error**: If `bpf_probe_read_kernel` fails in any hook, the operation is allowed and the error counter is incremented. Errors are monitored every 30s with `tracing::warn`. `syva status` surfaces them.
- **Ring buffer lost counter**: When `ENFORCEMENT_EVENTS.reserve()` fails (buffer full), `EnforcementCounters.lost` is incremented per-hook. `syva status` shows lost events with a warning flag.
- **Global zone bypass**: All 7 hooks check `ZONE_FLAG_GLOBAL` first and skip enforcement. Currently unreachable — all `add_zone_member` calls hardcode `NonGlobal`.
- **`ZONE_FLAG_PRIVILEGED`**: Defined and set in userspace for `ZoneType::Privileged`, but not checked by any eBPF program. Reserved for future use.
- **INODE_ZONE_MAP inode-only key**: Keyed by `i_ino` alone (not `dev,ino`). Cross-filesystem inode collisions possible. Documented limitation in `ebpf.rs`.
- **Host path scanning**: `populate_inode_zone_map()` recursively scans host_paths (depth limit 16, cycle detection via visited inodes, path canonicalization via `fs::canonicalize()`). Per-zone cap at `MAX_INODES / MAX_ZONES`.
- **ptrace mode**: `ptrace_guard` reads `mode` argument. Cross-zone ptrace is always denied regardless of `ZONE_ALLOWED_COMMS`. Mode is logged in deny event context field.

### Threat Model: Unzoned Containers

Containers without a `syva.dev/zone` annotation are **not in `ZONE_MEMBERSHIP`** and are invisible to all hooks. This means:
- Unzoned processes can access files in `INODE_ZONE_MAP` (file_open/exec hooks skip unzoned callers).
- Zoned callers ARE blocked from ptrace/signalling host processes (target not in any zone → deny).
- Unzoned processes can ptrace/signal zoned processes freely (they bypass all enforcement).

This is by design — Syva enforces boundaries between zones, not between zoned and unzoned workloads. If your threat model requires protecting zoned resources from unzoned processes, all containers must be labelled.

### Known Limitation: /proc and /sys Access

Virtual filesystem inodes (`/proc`, `/sys`) are not in `INODE_ZONE_MAP`. A zoned process can read `/proc/<pid>/mem` of processes in other zones. Deferred to a future `/proc`-specific LSM hook.

### What Syva Enforces vs Declares

| Policy field | Kernel enforcement |
|---|---|
| `network.allowed_zones` | **Enforced** — cross-zone ptrace/signal/file/exec/mmap blocked |
| `filesystem.host_paths` | **Enforced** — inodes registered in INODE_ZONE_MAP (recursive scan) |
| `POLICY_FLAG_ALLOW_PTRACE` | **Enforced** — intra-zone ptrace gated |
| `capabilities.allowed` | Declarative — caps_mask written but not checked by hooks (CAP_SYS_PTRACE used as policy signal for ptrace flag) |
| `resources.*` | Declarative — use cgroup controllers |
| `devices.allowed` | Declarative — use device cgroup |
| `syscalls.deny` | Declarative — use seccomp |
| `network.allowed_egress/ingress` | Declarative — use NetworkPolicy |

## Conventions

- Policies are TOML with `#[serde(deny_unknown_fields)]`. Typos in field names cause parse errors. See `policies/standard.toml` for the canonical example.
- `memory_limit` in policies accepts both integers (bytes) and strings (`"4Gi"`, `"512Mi"`, `"1G"`). `MemoryLimit` inner field is private — use `MemoryLimit::new()`.
- `ZonePolicy::validate()` checks resource bounds (cpu_shares, pids_max, io_weight > 0), warns on unknown capability names, enforces array size limits, and emits info logs for non-enforced declarative fields.
- Zoned callers are denied access to host processes (target not in any zone) in ptrace and signal hooks. `ZONE_ID_HOST = 0` in deny events.
- `POLICY_FLAG_ALLOW_PTRACE` only permits intra-zone ptrace. Cross-zone ptrace is always denied.
- `INODE_ZONE_MAP` only works for bind-mounted host paths (`host_paths` in `[filesystem]`). Container-internal paths (`writable_paths`) have different overlayfs inodes. `host_paths` are canonicalized and recursively scanned at startup.
- The policy TOML is deserialized directly into `ZonePolicy` (with optional `[zone]` metadata via `ZoneMetadata`).
- Container IDs from containerd events are validated (`is_valid_container_id` — hex/dash/underscore, max 128 chars) before use in filesystem paths.
- Containers without a `syva.dev/zone` annotation are silently skipped (no enforcement).
- Policies are loaded once at startup. No hot-reload.
- Tests go in `#[cfg(test)]` modules within source files.
- Pahole field matching uses word boundaries to avoid substring false matches.
- No `.unwrap()` in production code paths — use `?` or `.ok_or_else()`.
- Annotation key constant (`LABEL_ZONE`) lives in `mapper.rs` — single source of truth.

## Platform Requirements

- Linux 6.1+ with `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Boot parameter: `lsm=lockdown,capability,bpf`
- BTF at `/sys/kernel/btf/vmlinux`
- `pahole` recommended (for kernel offset resolution; defaults correct for Linux 6.1+)
- containerd socket at `/run/containerd/containerd.sock` (configurable via `--containerd-sock`)
