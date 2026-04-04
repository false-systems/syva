# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Syva is a standalone eBPF enforcement agent that drops kernel-level container isolation onto existing Kubernetes/containerd clusters. No runtime replacement needed — it watches containerd events, maps workloads to zones by OCI annotation (`syva.dev/zone`), and populates BPF maps that 5 LSM hooks check on every `open()`, `exec()`, `kill()`, `ptrace()`, and `cgroup_attach()`.

Extracted from the [Rauha](https://github.com/yairfalse/rauha) container runtime as a separate product. Syva is enforcement-only — it doesn't manage containers, images, or networking.

## Build & Test Commands

```bash
cargo build -p syva-ebpf-common    # Build shared types (works on any OS)
cargo build -p xtask               # Build the eBPF build helper
cargo test -p syva-ebpf-common     # Run type-size tests (6 tests)
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

### How It Works

1. **Load**: `EnforceEbpf::load()` reads BTF, resolves kernel struct offsets via pahole, injects them as globals into the eBPF object, loads 5 LSM programs via aya
2. **Discover**: `enumerate_cgroups()` walks `/sys/fs/cgroup` looking for containerd-managed cgroups, reads each container's OCI `config.json` for the `syva.dev/zone` annotation
3. **Enforce**: For each labelled container, writes cgroup→zone mapping into `ZONE_MEMBERSHIP` BPF map and zone→policy into `ZONE_POLICY` map
4. **Watch**: `watch_containerd_events()` subscribes to containerd's gRPC event stream for live container start/stop events, updating BPF maps in real time
5. **Stream**: Ring buffer drains deny events every 100ms, logs them via tracing

### Crate Structure

| Crate | Target | Purpose |
|-------|--------|---------|
| `syva` | Linux userspace | Main binary — CLI, eBPF lifecycle, containerd watcher, policy loading |
| `syva-ebpf-common` | `no_std` + userspace | `#[repr(C)]` types shared between kernel and userspace BPF maps |
| `syva-ebpf` | `bpfel-unknown-none` | 5 eBPF LSM programs (separate workspace, nightly Rust) |
| `xtask` | any | Build helper — `cargo xtask build-ebpf` |

### Key Files in `syva/src/`

- **ebpf.rs** — `EnforceEbpf` struct: loads eBPF, manages BPF maps, resolves kernel offsets via pahole, mutual exclusion check on `/sys/fs/bpf/syva/`
- **watcher.rs** — Containerd integration: cgroup enumeration, live event subscription via gRPC, cgroup_id resolution from `/proc/{pid}/cgroup`
- **events.rs** — Ring buffer drain loop (100ms interval), `read_unaligned` for BPF ring buffer data
- **policy.rs** — Scans a directory of `.toml` files, filename = zone name, deserializes directly into `ZonePolicy`
- **types.rs** — Inlined policy types (`ZonePolicy`, `ZoneType`, `NetworkMode`, etc.) — no external dependency
- **mapper.rs** — Annotation key constants (`syva.dev/zone`, `syva.dev/policy`)

### eBPF Programs (`syva-ebpf/src/`)

Five LSM hooks, all using `bpf_probe_read_kernel` for verifier-safe kernel memory access:

| File | LSM Hook | Blocks |
|------|----------|--------|
| `file_guard.rs` | `file_open` | Cross-zone file access |
| `exec_guard.rs` | `bprm_check_security` | Cross-zone binary execution |
| `ptrace_guard.rs` | `ptrace_access_check` | Cross-zone debugging |
| `signal_guard.rs` | `task_kill` | Cross-zone signals |
| `cgroup_lock.rs` | `cgroup_attach_task` | Zone escape via cgroup manipulation |

Kernel struct offsets are patched at load time via `BpfLoader::set_global()`. A one-shot self-test (`SELF_TEST` map) validates the offset chain on first `file_open`.

### BPF Maps

7 maps defined in `syva-ebpf/src/main.rs`: `ZONE_MEMBERSHIP` (cgroup→zone), `ZONE_POLICY` (zone→policy), `INODE_ZONE_MAP` (inode→zone), `ZONE_ALLOWED_COMMS` (cross-zone pairs), `SELF_TEST` (offset validation), `ENFORCEMENT_COUNTERS` (per-hook per-CPU), `ENFORCEMENT_EVENTS` (ring buffer, 1MB).

### Mutual Exclusion

Syva refuses to load if BPF maps are already pinned at `/sys/fs/bpf/syva/`. Only one instance can run per node. Stale pins from a crashed instance must be cleaned manually: `rm -rf /sys/fs/bpf/syva`.

## Conventions

- Policies are TOML. See `policies/standard.toml` for the canonical example.
- The policy TOML is deserialized directly into `ZonePolicy` (no intermediate `PolicyFile` types).
- Containers without a `syva.dev/zone` annotation are silently skipped (global zone, no enforcement).
- Policies are loaded once at startup. No hot-reload.
- Network setup failures, missing containerd socket, etc. are logged as warnings — the agent keeps running.
- Tests go in `#[cfg(test)]` modules within source files.

## Platform Requirements

- Linux 6.1+ with `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Boot parameter: `lsm=lockdown,capability,bpf`
- BTF at `/sys/kernel/btf/vmlinux`
- containerd socket at `/run/containerd/containerd.sock` (configurable via `--containerd-sock`)
