# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Syva is a standalone eBPF enforcement agent that drops kernel-level container isolation onto existing Kubernetes/containerd clusters. No runtime replacement needed — it watches containerd events, maps workloads to zones by OCI annotation (`syva.dev/zone`), and populates BPF maps that 5 LSM hooks check on every `open()`, `exec()`, `kill()`, `ptrace()`, and `cgroup_attach()`.

Extracted from the [Rauha](https://github.com/yairfalse/rauha) container runtime as a separate product. Syva is enforcement-only — it doesn't manage containers, images, or networking.

## Build & Test Commands

```bash
cargo build -p syva-ebpf-common    # Build shared types (works on any OS)
cargo build -p xtask               # Build the eBPF build helper
cargo test -p syva-ebpf-common     # Run type-size + caps tests (8 tests)
cargo test                         # All workspace tests

# Full workspace build (Linux only — aya crate requires Linux libc)
cargo build                        # Builds syva binary + syva-ebpf-common + xtask

# eBPF programs (separate workspace, requires nightly + Linux)
cargo xtask build-ebpf             # Debug build
cargo xtask build-ebpf --release   # Release build

# Run the agent (Linux only, requires root for BPF)
RUST_LOG=syva=debug cargo run --bin syva -- --policy-dir ./policies
```

The `syva` binary and `syva-ebpf` programs do not compile on macOS — `aya` uses Linux-specific libc symbols (netlink, bpf syscalls). Only `syva-ebpf-common` and `xtask` are cross-platform.

## Architecture

### Startup Sequence

1. **Load**: `EnforceEbpf::load()` reads BTF, resolves kernel struct offsets via pahole, injects them as globals into the eBPF object, loads 5 LSM programs via aya. `Drop` impl cleans up pins on failure.
2. **Self-test**: `verify_self_test()` (async) triggers a synthetic file open, then polls `SELF_TEST` map to verify offset chain correctness. Aborts if offsets are wrong — no silent enforcement failure.
3. **Policy-driven zone setup**: All policy files get zone IDs, `ZONE_POLICY`, `ZONE_ALLOWED_COMMS`, and `INODE_ZONE_MAP` populated at startup — regardless of running containers. This ensures comms and inode maps are complete even for zones with no containers yet.
4. **Discover**: `enumerate_cgroups()` walks `/sys/fs/cgroup` (max depth 8) looking for containerd-managed cgroups, reads each container's OCI `config.json` for the `syva.dev/zone` annotation. Uses retry loop (up to 10 attempts) for config availability. Containers join pre-allocated zone IDs.
5. **Watch**: `watch_containerd_events()` subscribes to containerd's gRPC event stream for live container start/stop events, updating BPF maps in real time
6. **Stream**: Ring buffer drains deny events every 100ms in `block_in_place`, capped at 1000 events/tick

### Crate Structure

| Crate | Target | Purpose |
|-------|--------|---------|
| `syva` | Linux userspace | Main binary — CLI, eBPF lifecycle, containerd watcher, policy loading |
| `syva-ebpf-common` | `no_std` + userspace | `#[repr(C)]` types shared between kernel and userspace BPF maps |
| `syva-ebpf` | `bpfel-unknown-none` | 5 eBPF LSM programs (separate workspace, nightly Rust) |
| `xtask` | any | Build helper — `cargo xtask build-ebpf` |

### Key Files in `syva/src/`

- **zone.rs** — `ZoneRegistry`: single source of truth for zone lifecycle (Pending→Active→Pending). Replaces scattered HashMaps. Enforces invariants: zone_id 0 reserved, stable IDs per name, refcount-based state transitions, rollback on failure.
- **ebpf.rs** — `EnforceEbpf` struct: loads eBPF, manages all BPF maps (membership, policy, comms, inodes), resolves kernel offsets via pahole with word-boundary matching, verifies self-test, mutual exclusion on `/sys/fs/bpf/syva/`. `Drop` impl cleans up pins.
- **watcher.rs** — Containerd integration: cgroup enumeration (depth-limited), live event subscription via gRPC, cgroup_id resolution from `/proc/{pid}/cgroup`, retry loop for OCI config availability
- **events.rs** — Ring buffer drain via `block_in_place` (100ms interval, 1000 event cap), unzoned access debug logging
- **policy.rs** — Scans a directory of `.toml` files, filename = zone name, deserializes directly into `ZonePolicy`
- **types.rs** — Inlined policy types (`ZonePolicy`, `ZoneType`, `MemoryLimit` newtype with human-readable deserialization)
- **mapper.rs** — Annotation key constants (`syva.dev/zone`, `syva.dev/policy`)
- **main.rs** — CLI, startup orchestration, zone refcounting, live event loop with BPF map cleanup on zone emptying

### eBPF Programs (`syva-ebpf/src/`)

Five LSM hooks, all using `bpf_probe_read_kernel` for verifier-safe kernel memory access:

| File | LSM Hook | Blocks |
|------|----------|--------|
| `file_guard.rs` | `file_open` | Cross-zone file access (via INODE_ZONE_MAP) |
| `exec_guard.rs` | `bprm_check_security` | Cross-zone binary execution (via INODE_ZONE_MAP) |
| `ptrace_guard.rs` | `ptrace_access_check` | Cross-zone debugging |
| `signal_guard.rs` | `task_kill` | Cross-zone signals |
| `cgroup_lock.rs` | `cgroup_attach_task` | Zone escape via cgroup manipulation |

Kernel struct offsets are patched at load time via `BpfLoader::set_global()`. A one-shot self-test (`SELF_TEST` map) validates the offset chain on first `file_open` and is verified by userspace at startup.

### BPF Maps

7 maps defined in `syva-ebpf/src/main.rs`: `ZONE_MEMBERSHIP` (cgroup→zone), `ZONE_POLICY` (zone→policy), `INODE_ZONE_MAP` (inode→zone for file/exec hooks), `ZONE_ALLOWED_COMMS` (cross-zone pairs, bidirectional), `SELF_TEST` (offset validation), `ENFORCEMENT_COUNTERS` (per-hook per-CPU), `ENFORCEMENT_EVENTS` (ring buffer, 1MB).

### Zone Lifecycle

- **Refcounting**: Each zone has a reference count tracking active containers. Zone BPF map entries are cleaned up when the last container leaves.
- **allowed_zones symmetry**: Both zones must list each other in `network.allowed_zones`. One-sided declarations are logged as warnings and neither direction is written.
- **Policy write-once**: `ZONE_POLICY` is written once per zone_id, tracked via `zone_policies_written: HashSet<u32>`.

### Subcommands

- `syva` (no subcommand) — main enforcement loop
- `syva status` — reads pinned `ENFORCEMENT_COUNTERS` and prints per-hook allow/deny/error totals
- `syva events --follow` — streams deny events from pinned `ENFORCEMENT_EVENTS` ring buffer to stdout

### Mutual Exclusion

Syva refuses to load if BPF maps are already pinned at `/sys/fs/bpf/syva/`. Only one instance can run per node. Stale pins from a crashed instance must be cleaned manually: `rm -rf /sys/fs/bpf/syva`.

## Conventions

- Policies are TOML. See `policies/standard.toml` for the canonical example.
- `memory_limit` in policies accepts both integers (bytes) and strings (`"4Gi"`, `"512Mi"`, `"1G"`). `MemoryLimit` inner field is private — use `MemoryLimit::new()`.
- `ZonePolicy::validate()` checks resource bounds (cpu_shares, pids_max, io_weight > 0) and warns on unknown capability names.
- Zoned callers are denied access to host processes (target not in any zone) in ptrace and signal hooks. `ZONE_ID_HOST = 0` in deny events.
- `POLICY_FLAG_ALLOW_PTRACE` only permits intra-zone ptrace, not cross-zone.
- `INODE_ZONE_MAP` only works for bind-mounted host paths (`host_paths` in policy). Container-internal paths (`writable_paths`) have different overlayfs inodes.
- Zone lifecycle: Pending (policy configured, no containers) → Active (containers present) → Pending (last container left, BPF maps stay configured). Policy-defined zones persist — re-activation is free.
- The policy TOML is deserialized directly into `ZonePolicy` (no intermediate `PolicyFile` types).
- Containers without a `syva.dev/zone` annotation are silently skipped (global zone, no enforcement). Debug-level log emitted if an unzoned process hits enforcement paths.
- Policies are loaded once at startup. No hot-reload.
- Tests go in `#[cfg(test)]` modules within source files.
- Pahole field matching uses word boundaries to avoid substring false matches.

## Platform Requirements

- Linux 6.1+ with `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Boot parameter: `lsm=lockdown,capability,bpf`
- BTF at `/sys/kernel/btf/vmlinux`
- `pahole` recommended (for kernel offset resolution; defaults correct for Linux 6.1+)
- containerd socket at `/run/containerd/containerd.sock` (configurable via `--containerd-sock`)
