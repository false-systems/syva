# Syva

**Kernel-level enforcement for containers that are already running.**

Your containers run on shared kernels. Namespaces set up walls, but nothing watches the doors. A process can't see across a namespace boundary, but the kernel doesn't know that two containers *shouldn't* talk to each other. There's no enforcement at the syscall level, no audit trail of what was allowed or denied.

Syva adds what's missing. Five eBPF LSM hooks run inside the kernel on every `open()`, `exec()`, `kill()`, `ptrace()`, and `cgroup_attach()`. Every call is checked against zone membership. Every deny is recorded. No runtime replacement — deploy a DaemonSet and label your workloads.

> *Syvä* (Finnish) — deep. Where enforcement happens.

---

## How It Works

```
Container calls open("/data/secret.txt")
  │
  ├─ kernel hits file_open LSM hook
  ├─ syva eBPF program fires
  ├─ lookup: process cgroup → zone_id = A
  ├─ lookup: file inode → file_zone = B
  ├─ A ≠ B → return -EACCES
  │
  └─ process gets "Permission denied"
```

This isn't a userspace proxy. It's enforced in the kernel on every access with zero daemon round-trip. Policy changes are a BPF map update, not a process restart.

## The Zone Model

Every container belongs to exactly one zone. Zones are the unit of isolation — what can see what, what can touch what.

```
┌──────────────────────────────────────────────────────┐
│                    Node                              │
│                                                      │
│   ┌──────────────────┐    ┌──────────────────┐       │
│   │     Zone A       │    │     Zone B       │       │
│   │                  │    │                  │       │
│   │  web-server      │    │  database        │       │
│   │  api-gateway     │    │  redis           │       │
│   │                  │    │                  │       │
│   └──────────────────┘    └──────────────────┘       │
│              ╳ denied by default ╳                    │
│                                                      │
│   syva ─── watches containerd ─── populates BPF maps │
└──────────────────────────────────────────────────────┘
```

Cross-zone access requires an explicit policy rule. Allow-list, not deny-list.

## LSM Hooks

| Hook | Blocks | Why It Matters |
|------|--------|----------------|
| `file_open` | Cross-zone file access | A container in Zone A can't read Zone B's files |
| `bprm_check_security` | Cross-zone exec | Can't execute binaries owned by another zone |
| `ptrace_access_check` | Cross-zone debugging | Can't attach a debugger to another zone's processes |
| `task_kill` | Cross-zone signals | Can't kill or signal processes in another zone |
| `cgroup_attach_task` | Zone escape | Can't move a process out of its zone's cgroup |

Every deny emits an event to a BPF ring buffer with the caller PID, zone IDs, and context — available for audit and real-time monitoring.

## Deploy

### Kubernetes

```yaml
# Label your workloads
metadata:
  annotations:
    syva.dev/zone: "frontend"
```

```bash
# Create zone policies
kubectl create configmap syva-policies \
  --from-file=frontend.toml=policies/frontend.toml \
  --from-file=database.toml=policies/database.toml \
  -n syva-system

# Deploy Syva
kubectl apply -f deploy/syva-daemonset.yaml
```

Syva runs as a privileged DaemonSet. It watches containerd events, reads `syva.dev/zone` annotations from container specs, and populates BPF maps.

### Standalone

```bash
syva --policy-dir /etc/syva/policies \
     --containerd-sock /run/containerd/containerd.sock
```

## Zone Policies

Declarative TOML. Allow-list model — nothing is permitted unless explicitly listed.

```toml
[capabilities]
allowed = ["CAP_NET_BIND_SERVICE", "CAP_CHOWN"]

[resources]
cpu_shares = 1024
memory_limit = 536870912   # 512Mi
pids_max = 512

[network]
mode = "bridged"
allowed_zones = ["frontend"]
allowed_egress = ["0.0.0.0/0:443"]

[filesystem]
writable_paths = ["/data", "/tmp", "/var/log"]

[syscalls]
deny = ["mount", "umount2", "pivot_root"]
```

Each `.toml` file in the policy directory defines a zone. The filename is the zone name — `agent-sandbox.toml` creates zone `agent-sandbox`.

## Enforcement Observability

Every deny decision is emitted to a BPF ring buffer and logged:

```
WARN DENY hook=file_open pid=1847 caller_zone=2 target_zone=3 context=8421376
WARN DENY hook=ptrace_access_check pid=992 caller_zone=1 target_zone=2 context=0
```

Per-hook enforcement counters (allow/deny/error, per CPU) are always available:

```bash
syva status
# syva: ACTIVE
#   file_open:    allow=48201  deny=3  error=0
#   bprm_check:   allow=892    deny=0  error=0
#   ptrace_check: allow=12     deny=1  error=0
```

## How Offset Resolution Works

eBPF programs need to read kernel struct fields (`task_struct->cgroups`, `file->f_inode`). These offsets vary between kernel versions. Syva handles this automatically:

1. If `pahole` is installed, reads real offsets from the running kernel's BTF
2. Injects resolved offsets into the eBPF programs as globals before loading
3. Runs a one-shot self-test: compares `bpf_get_current_cgroup_id()` (BPF helper, known-good) against the offset-chain-derived value
4. If they differ, refuses to load — no silent enforcement failure

Defaults are correct for Linux 6.1+.

## Building

```bash
cargo build                        # workspace (Linux only — aya requires Linux libc)
cargo xtask build-ebpf             # eBPF programs (requires nightly)
cargo xtask build-ebpf --release   # optimized eBPF
cargo test                         # all tests
```

### Requirements

- Linux 6.1+ with `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Boot parameter: `lsm=lockdown,capability,bpf`
- BTF at `/sys/kernel/btf/vmlinux`
- Rust nightly (for eBPF programs only)
- `pahole` recommended (for kernel offset resolution)

## Architecture

```
┌────────────────────────────────────────────────────┐
│                    syva binary                     │
│                                                    │
│  ┌──────────┐  ┌───────────┐  ┌────────────────┐  │
│  │ policy   │  │ containerd│  │  eBPF loader   │  │
│  │ loader   │  │ watcher   │  │  (aya + BTF)   │  │
│  │ (TOML)   │  │ (gRPC)    │  │                │  │
│  └────┬─────┘  └─────┬─────┘  └───────┬────────┘  │
│       │              │                │            │
│       └──────────────┴────────────────┘            │
│                      │                             │
│              BPF map operations                    │
└──────────────────────┬─────────────────────────────┘
                       │
         ┌─────────────▼─────────────┐
         │     Linux kernel          │
         │                           │
         │  5 LSM hooks              │
         │  7 BPF maps               │
         │  ring buffer → userspace  │
         └───────────────────────────┘
```

| Crate | Purpose |
|-------|---------|
| `syva` | Main binary — CLI, eBPF lifecycle, containerd watcher |
| `syva-ebpf-common` | `#[repr(C)]` types shared between kernel and userspace |
| `syva-ebpf` | eBPF LSM programs (separate build, `bpfel-unknown-none`) |
| `xtask` | Build helper for eBPF compilation |

## Trade-offs

**eBPF is not a hardware boundary.** Zone identity is reconstructed via BPF map lookup on every enforcement call. Defended by the `cgroup_attach_task` hook, but it's defense-in-depth, not VM-level isolation.

**LSM is additive-only.** eBPF LSM programs can deny access but cannot override SELinux/AppArmor denials. Zone policy must be a subset of existing MAC policy.

**No hot-reload.** Policies are loaded once at startup. Restart the agent to pick up changes.

**Covert channels** via shared kernel resources (CPU cache timing, memory pressure) are not addressable by eBPF. Same limitation as all OS-level isolation.

## License

Apache-2.0
