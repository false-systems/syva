# Syva

**Your containers share a kernel. Syva makes the kernel enforce boundaries between them.**

Today, container isolation is structural — namespaces and cgroups set up walls. But nothing checks whether Container A is accessing Container B's files, sending it signals, or attaching a debugger to it. The kernel doesn't know these containers shouldn't interact.

Syva fixes this. It loads small programs into the kernel (via eBPF) that intercept security-sensitive operations — opening files, executing binaries, mapping executable memory, sending signals — and checks whether the caller is allowed to touch the target. If not, the operation is denied before it happens.

No sidecar. No proxy. No runtime replacement. Deploy the core engine per node, connect an adapter for your environment, done.

> *Syvä* (Finnish) — deep. Where enforcement happens.

---

## AI Agent Isolation

AI agents run code. They make tool calls, spawn subprocesses, read files, and interact with APIs — all inside containers that share a kernel with everything else on the node. Namespaces don't stop an agent container from reading another container's files through bind mounts, sending signals to adjacent processes, or attaching a debugger to a database running next door.

Syva enforces these boundaries in the kernel. Put your agent workloads in one zone, your production services in another, and the kernel blocks every cross-zone `open()`, `exec()`, `mmap()`, `ptrace()`, and `kill()` — before it happens, not after.

```
 Node
 ═══════════════════════════════════════════════════

   Zone: "agent-sandbox"         Zone: "production"
  ┌─────────────────┐           ┌─────────────────┐
  │                 │           │                 │
  │   ai-agent      │           │   api-server    │
  │   code-runner   │           │   postgres      │
  │                 │           │                 │
  └─────────────────┘           └─────────────────┘

          │                              │
          │   open("/db/data") ──────X   │
          │   exec("/usr/bin/pg_dump") X │
          │   ptrace(api_pid) ───────X   │
          │   kill(postgres_pid, 9) ──X  │
          │                              │
          X = denied by Syva in the kernel
```

An agent sandbox policy locks it down:

```toml
# agent-sandbox.toml

[capabilities]
allowed = ["CAP_NET_BIND_SERVICE"]

[resources]
memory_limit = "4Gi"
pids_max = 256

[network]
mode = "bridged"
allowed_zones = []    # no cross-zone communication

[filesystem]
writable_paths = ["/tmp", "/workspace"]
host_paths = ["/srv/agent/workspace"]

[syscalls]
deny = ["mount", "umount2", "pivot_root", "ptrace"]
```

No `allowed_zones` means the agent zone is fully isolated — every cross-zone operation is denied at the kernel level. The agent can run arbitrary code inside its zone, but it cannot reach anything outside it.

---

## What Syva Does

Imagine two groups of containers on the same node:

```
 Node
 ═══════════════════════════════════════════════════

   Zone: "frontend"              Zone: "database"
  ┌─────────────────┐           ┌─────────────────┐
  │                 │           │                 │
  │   nginx         │           │   postgres      │
  │   react-app     │           │   redis         │
  │                 │           │                 │
  └─────────────────┘           └─────────────────┘

          │                              │
          │   open("/db/data") ──────X   │
          │   mmap(lib, PROT_EXEC) ──X   │
          │   kill(pg_pid, 9) ───────X   │
          │   ptrace(redis_pid) ─────X   │
          │                              │
          X = denied by Syva in the kernel
```

Without Syva, these containers can interact through the shared kernel — read each other's files via `/proc`, send signals, attach debuggers, load each other's shared libraries. With Syva, every such operation hits a kernel checkpoint that verifies zone membership first.

## How It Works

Syva has two layers: a **core engine** that manages eBPF enforcement, and **adapters** that tell it what to enforce.

```
 ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
 │ syva-file    │  │ syva-k8s     │  │ syva-api     │
 │ TOML/ConfigMap│  │ CRD + Pods   │  │ REST API     │
 └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
        └─────────────────┼─────────────────┘
                          │
               gRPC / Unix socket
                          │
        ┌─────────────────▼─────────────────┐
        │           syva-core               │
        │   BPF maps + 7 LSM hooks          │
        │   Health :9091 + Prometheus        │
        └───────────────────────────────────┘
```

**The core** loads eBPF programs into the kernel and exposes a gRPC API over a Unix socket. It handles zone registration, container membership, cross-zone communication policy, and inode-level file enforcement. It never knows where commands came from.

**Adapters** connect to the core and translate their domain into enforcement commands:
- **syva-file** — reads TOML policy files, watches containerd for container events, hot-reloads on ConfigMap changes
- **syva-k8s** — watches `SyvaZonePolicy` CRDs and Pod annotations via kube-rs
- **syva-api** — exposes a REST API for programmatic zone management

**Step 1: Label your containers.**

```yaml
metadata:
  annotations:
    syva.dev/zone: "frontend"
```

Or define a CRD (with the k8s adapter):

```yaml
apiVersion: syva.dev/v1alpha1
kind: SyvaZonePolicy
metadata:
  name: frontend
spec:
  network:
    allowedZones: ["database"]
  filesystem:
    hostPaths: ["/srv/frontend/static"]
```

**Step 2: The kernel enforces.**

Every sensitive operation goes through Syva's kernel hooks:

```
 Process in "frontend" zone calls open()
      │
      ▼
 Kernel hits the file_open hook
      │
      ▼
 Syva's eBPF program runs:
   ┌─────────────────────────────────────┐
   │ 1. What zone is the caller in?      │  → "frontend"
   │ 2. What zone owns this file?        │  → "database"
   │ 3. Are these zones allowed to talk?  │  → No
   │ 4. DENY. Return -EACCES.            │
   └─────────────────────────────────────┘
      │
      ▼
 Process gets "Permission denied"
 Event logged to ring buffer
```

This check happens **inside the kernel**, on every call. No round-trip to userspace. No daemon in the path.

## Seven Kernel Hooks

Syva intercepts seven operations. Together, they cover the main ways containers can interact through a shared kernel:

```
 ┌──────────────────────────────────────────────────────────────────┐
 │                                                                  │
 │   open()              Can this process read/write this file?     │
 │                                                                  │
 │   exec()              Can this process run this binary?          │
 │                                                                  │
 │   mmap(PROT_EXEC)     Can this process map executable memory?    │
 │                                                                  │
 │   ptrace()            Can this process debug/inspect that one?   │
 │                                                                  │
 │   kill()              Can this process send a signal to that?    │
 │                                                                  │
 │   cgroup_attach()     Can this process escape its zone?          │
 │                                                                  │
 │   unix_connect()      Cross-zone Unix socket connections blocked  │
 │                                                                  │
 └──────────────────────────────────────────────────────────────────┘

 Each hook:  caller zone ──?── target zone
             same zone → allow
             different zone, no policy rule → DENY
             different zone, explicit allow → allow
```

Every deny is recorded with the caller PID, both zone IDs, and hook-specific context (file inode, target cgroup, ptrace mode, etc.).

## Zone Policies

Each `.toml` file in the policy directory defines one zone. The filename is the zone name — `agent-sandbox.toml` creates zone `agent-sandbox`.

```toml
# database.toml

[capabilities]
allowed = ["CAP_NET_BIND_SERVICE", "CAP_CHOWN"]

[resources]
cpu_shares = 1024
memory_limit = 536870912   # 512Mi in bytes
pids_max = 512

[network]
mode = "bridged"
allowed_zones = ["frontend"]    # frontend can talk to database

[filesystem]
writable_paths = ["/data", "/tmp", "/var/log"]
host_paths = ["/srv/database/data"]   # enforced via INODE_ZONE_MAP

[syscalls]
deny = ["mount", "umount2", "pivot_root"]
```

**Default: deny everything.** Cross-zone communication only happens when both zones list each other in `allowed_zones`.

**What Syva enforces vs declares:**

| Policy field | Kernel enforcement |
|---|---|
| `network.allowed_zones` | **Enforced** — cross-zone file/exec/mmap/ptrace/signal blocked |
| `filesystem.host_paths` | **Enforced** — inodes registered for file/exec/mmap hooks |
| `POLICY_FLAG_ALLOW_PTRACE` | **Enforced** — intra-zone ptrace gated on `CAP_SYS_PTRACE` in capabilities |
| `capabilities`, `resources`, `devices`, `syscalls`, `network.allowed_egress/ingress` | **Declarative only** — use seccomp, cgroups, NetworkPolicy |

Syva logs a warning at startup for each declarative-only field that is configured.

---

## Installation

### Prerequisites

**Kernel requirements:**
- Linux 6.1+ with `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Boot parameter: `lsm=lockdown,capability,bpf`
- BTF at `/sys/kernel/btf/vmlinux`
- `pahole` is NOT required — kernel struct offsets are resolved directly from BTF at startup

**Runtime requirements:**
- containerd with Unix socket at `/run/containerd/containerd.sock` (configurable)
- Root access or `CAP_BPF` + `CAP_SYS_ADMIN` + `CAP_PERFMON`

### Building from Source

```bash
# Build all binaries (Linux only — aya uses Linux-specific libc)
cargo build --release

# Build the eBPF programs (requires nightly Rust)
cargo run -p xtask -- build-ebpf --release

# Binaries:
#   target/release/syva-core       — enforcement engine
#   target/release/syva-file       — file/ConfigMap adapter
#   target/release/syva-k8s        — Kubernetes CRD adapter
#   target/release/syva-api        — REST API adapter
```

### Deploy on Kubernetes — ConfigMap Policies

```bash
kubectl create namespace syva-system

kubectl create configmap syva-policies \
  --from-file=frontend.toml=policies/frontend.toml \
  --from-file=database.toml=policies/database.toml \
  -n syva-system

kubectl apply -f deploy/v0.2/daemonset-file.yaml
```

This deploys two containers per node: `syva-core` (enforcement) + `syva-file` (policy adapter), sharing a Unix socket via `emptyDir`.

### Deploy on Kubernetes — CRD Policies

```bash
kubectl apply -f deploy/v0.2/daemonset-k8s.yaml

# Define a zone via CRD
kubectl apply -f - <<EOF
apiVersion: syva.dev/v1alpha1
kind: SyvaZonePolicy
metadata:
  name: frontend
spec:
  network:
    allowedZones: ["database"]
  filesystem:
    hostPaths: ["/srv/frontend/static"]
EOF
```

Label your pods with `syva.dev/zone: "frontend"`. Containers without the annotation are not enforced.

### Deploy Standalone

```bash
# Terminal 1: Start the core engine
syva-core --socket-path /run/syva/syva-core.sock

# Terminal 2: Start the file adapter
syva-file --policy-dir /etc/syva/policies --socket-path /run/syva/syva-core.sock
```

### Verify

```bash
# Check enforcement status
kubectl exec -n syva-system -c syva-core daemonset/syva -- syva-core status

# Validate policies without loading BPF
syva-file verify --policy-dir ./policies
```

---

## Observability

Every deny is emitted as a structured event:

```
DENY hook=file_open pid=1847 caller_zone=2 target_zone=3 context=8421376
DENY hook=ptrace    pid=992  caller_zone=1 target_zone=2 context=4
```

Stream events in real time:

```bash
syva-core events --follow
syva-core events --follow --format json    # ndjson output
```

Events come from a BPF ring buffer (4MB, ~75K events). Allows are tracked in per-CPU counters only — no per-event overhead for the common path. Lost events (ring buffer overflow) are counted per-hook and shown in `syva-core status`.

Prometheus metrics are available at `:9091/metrics` — per-hook allow/deny/error/lost counters, plus agent health gauges. Enforcement errors (kernel struct read failures) are monitored every 30 seconds.

## How Syva Handles Kernel Differences

eBPF programs read kernel struct fields (`task_struct->cgroups`, `file->f_inode`). The byte offset of these fields changes between kernel versions. Syva handles this:

```
 Startup
    │
    ├─ Parse /sys/kernel/btf/vmlinux for kernel struct offsets
    ├─ Inject offsets into eBPF programs as globals
    ├─ Load programs (verified by kernel, not yet attached)
    │
    ├─ Attach all 7 hooks (enforcement begins)
    ├─ Adapters connect and populate BPF maps via gRPC
    │
    ├─ Three self-tests validate offset chains:
    │   ├─ Cgroup: BPF helper vs offset chain
    │   ├─ Inode: BPF-derived inode vs stat()
    │   └─ Unix socket: peer cgroup resolution
    │
    ├─ All pass? → enforcement active, drop CAP_SYS_ADMIN
    └─ Any fail? → refuse to start (no silent failure)
```

If BTF is unavailable, defaults for Linux 6.1+ are used (self-tests validate correctness).

## Architecture

```
 ┌────────────────┐  ┌────────────────┐  ┌────────────────┐
 │   syva-file    │  │   syva-k8s     │  │   syva-api     │
 │ TOML/ConfigMap │  │  CRD + Pods    │  │   REST API     │
 └───────┬────────┘  └───────┬────────┘  └───────┬────────┘
         └──────────────────┬┘───────────────────┘
                            │
                 gRPC / Unix socket
                 /run/syva/syva-core.sock
                            │
         ┌──────────────────▼──────────────────┐
         │            syva-core                │
         │   ZoneRegistry + BPF map mgmt       │
         │   Health :9091 + Prometheus          │
         │   gRPC server (10 RPCs)             │
         └──────────────────┬──────────────────┘
                            │
 ┌──────────────────────────▼──────────────────────────────┐
 │                      Linux kernel                       │
 │                                                         │
 │  ZONE_MEMBERSHIP    cgroup_id → zone    (who is where)  │
 │  ZONE_POLICY        zone → caps, flags  (Array, O(1))   │
 │  INODE_ZONE_MAP     inode → zone        (NO_PREALLOC)   │
 │  ZONE_ALLOWED_COMMS (zone, zone) → ok   (who can talk)  │
 │  ENFORCEMENT_EVENTS ring buffer, 4MB    (what happened)  │
 │                                                         │
 │  7 LSM hooks: open/exec/mmap/kill/ptrace/cgroup/unix    │
 └─────────────────────────────────────────────────────────┘
```

| Crate | Binary | What it does |
|-------|--------|------------|
| `syva-core` | `syva-core` | Enforcement engine. Loads eBPF, serves gRPC, health/metrics. |
| `syva-adapter-file` | `syva-file` | Reads TOML policies, watches containerd, hot-reloads. |
| `syva-adapter-k8s` | `syva-k8s` | Watches SyvaZonePolicy CRDs and Pod annotations. |
| `syva-adapter-api` | `syva-api` | REST API for programmatic zone management. |
| `syva-proto` | — | gRPC contract between core and adapters. |
| `syva-ebpf` | — | 7 kernel programs. Separate build, `bpfel-unknown-none`. |
| `syva-ebpf-common` | — | `#[repr(C)]` types shared between kernel and userspace. |

## Building

```bash
cargo build --release              # all binaries (Linux only)
cargo run -p xtask -- build-ebpf   # kernel programs (requires nightly Rust)
cargo test                         # all tests
```

**Requires:** Linux 6.1+, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, boot with `lsm=lockdown,capability,bpf`.

## Limitations

**Software enforcement, not hardware.** Syva uses BPF maps in kernel memory. It's defense-in-depth, not a hypervisor boundary. A kernel exploit could bypass it.

**Additive only.** eBPF LSM hooks can deny but never override existing MAC policy (SELinux, AppArmor). Syva stacks on top.

**Policy hot-reload.** Policies are polled every 5 seconds. ConfigMap updates are detected via symlink rotation. Zones removed while containers are running transition to draining state — enforcement continues until the last container leaves.

**One instance per node.** Syva pins BPF maps at `/sys/fs/bpf/syva/`. A second instance will refuse to start. The DaemonSet init container cleans stale pins automatically.

**Fail-open on errors.** Kernel struct read failures allow the operation (with error counter increment). This is defense-in-depth — a read failure shouldn't block the system. Errors are monitored and surfaced in `syva status`.

**Declarative-only fields.** Capabilities, resources, devices, syscalls, and network egress/ingress in policy TOML are parsed but not enforced by Syva's eBPF hooks. Use seccomp, cgroups, and NetworkPolicy for those. Syva warns at startup about configured-but-not-enforced fields.

**/proc access not controlled.** Virtual filesystem inodes are not in `INODE_ZONE_MAP`. Cross-zone `/proc/<pid>/mem` access is possible. Deferred to a future release.

**Enforcement gap during rolling update.** During a DaemonSet rolling update, the init container removes old BPF pins before the new agent starts. Between pin removal and new hook attachment (10-30 seconds), all LSM hooks are inactive. Plan upgrades during maintenance windows or accept the gap as a tradeoff for clean restart.

## License

Apache-2.0
