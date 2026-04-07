# Syva

**Your containers share a kernel. Syva makes the kernel enforce boundaries between them.**

Today, container isolation is structural — namespaces and cgroups set up walls. But nothing checks whether Container A is accessing Container B's files, sending it signals, or attaching a debugger to it. The kernel doesn't know these containers shouldn't interact.

Syva fixes this. It loads small programs into the kernel (via eBPF) that intercept security-sensitive operations — opening files, executing binaries, mapping executable memory, sending signals — and checks whether the caller is allowed to touch the target. If not, the operation is denied before it happens.

No sidecar. No proxy. No runtime replacement. Deploy one agent per node, label your containers, done.

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

## How It Works — Step by Step

**Step 1: You label your containers.**

Add an annotation to your pods or containers:

```yaml
metadata:
  annotations:
    syva.dev/zone: "frontend"
```

**Step 2: You write zone policies.**

One TOML file per zone. The filename is the zone name.

```
/etc/syva/policies/
  ├── frontend.toml
  └── database.toml
```

**Step 3: Syva watches containerd.**

When a container starts, Syva reads its annotation, looks up the matching policy, and writes an entry into a kernel-level map:

```
 Container starts
      │
      ▼
 Syva sees the containerd event
      │
      ▼
 Reads annotation: syva.dev/zone = "frontend"
      │
      ▼
 Writes to BPF map:  cgroup_id → zone "frontend"
      │
      ▼
 Now the kernel knows this container belongs to "frontend"
```

**Step 4: The kernel enforces.**

From this point, every sensitive operation by that container goes through Syva's kernel hooks:

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
 │   unix_connect()      Cross-zone Unix socket audit (visibility)  │
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
- `pahole` recommended (for kernel struct offset resolution; defaults correct for Linux 6.1+)

**Runtime requirements:**
- containerd with Unix socket at `/run/containerd/containerd.sock` (configurable)
- Root access or `CAP_BPF` + `CAP_SYS_ADMIN` + `CAP_PERFMON`

### Building from Source

```bash
# Build the agent (Linux only — aya uses Linux-specific libc)
cargo build --release

# Build the eBPF programs (requires nightly Rust)
cargo run -p xtask -- build-ebpf --release

# The agent binary is at target/release/syva
# The eBPF object is at syva-ebpf/target/bpfel-unknown-none/release/syva-ebpf
```

### Deploy on Kubernetes

**1. Create policies as a ConfigMap:**

```bash
kubectl create namespace syva-system

kubectl create configmap syva-policies \
  --from-file=frontend.toml=policies/frontend.toml \
  --from-file=database.toml=policies/database.toml \
  -n syva-system
```

**2. Deploy the DaemonSet:**

```bash
kubectl apply -f deploy/syva-daemonset.yaml
```

This deploys one Syva agent per node as a DaemonSet with:
- An init container that cleans up stale BPF pins from previous crashes
- `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_PERFMON` (dropped to `CAP_BPF` + `CAP_PERFMON` after BPF load)
- Read-only root filesystem, seccomp RuntimeDefault
- Resource limits: 50m–500m CPU, 64Mi–256Mi memory
- `hostPID: true` (required for cgroup ID resolution via `/proc/{pid}/cgroup`)
- Mounts: `/sys/fs/bpf`, `/sys/fs/cgroup` (ro), `/sys/kernel/btf` (ro), containerd socket, containerd state (ro)

**3. Label your pods:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    syva.dev/zone: "frontend"
spec:
  containers:
    - name: app
      image: your-app:latest
```

Containers without `syva.dev/zone` are not enforced — they run in the global zone with no restrictions.

**4. Verify:**

```bash
# Check agent status on a node
kubectl exec -n syva-system daemonset/syva -- syva status
```

```
syva: ACTIVE
  pin path: /sys/fs/bpf/syva
  hooks:
    file_open        allow=48201  deny=3     error=0    lost=0
    bprm_check       allow=892    deny=0     error=0    lost=0
    ptrace_check     allow=12     deny=1     error=0    lost=0
    task_kill        allow=340    deny=0     error=0    lost=0
    cgroup_attach    allow=28     deny=0     error=0    lost=0
    mmap_file        allow=15420  deny=0     error=0    lost=0
    unix_connect     allow=84     deny=0     error=0    lost=0
```

### Deploy Standalone

```bash
# Create policy directory
mkdir -p /etc/syva/policies
cp policies/standard.toml /etc/syva/policies/

# Run the agent
syva --policy-dir /etc/syva/policies
```

Uses `/run/containerd/containerd.sock` by default. Override with `--containerd-sock`.

Pass `--ebpf-obj` to specify a custom eBPF object file (useful during development).

---

## Observability

Every deny is emitted as a structured event:

```
DENY hook=file_open pid=1847 caller_zone=2 target_zone=3 context=8421376
DENY hook=ptrace    pid=992  caller_zone=1 target_zone=2 context=4
```

Stream events in real time:

```bash
syva events --follow
```

Events come from a BPF ring buffer (4MB, ~75K events). Allows are tracked in per-CPU counters only — no per-event overhead for the common path. Lost events (ring buffer overflow) are counted per-hook and shown in `syva status`.

Enforcement errors (kernel struct read failures) are monitored every 30 seconds. If errors are detected, a warning is logged with guidance to check `syva status` and install `pahole`.

## How Syva Handles Kernel Differences

eBPF programs read kernel struct fields (`task_struct->cgroups`, `file->f_inode`). The byte offset of these fields changes between kernel versions. Syva handles this:

```
 Startup
    │
    ├─ Load BTF from /sys/kernel/btf/vmlinux
    ├─ Run pahole to get real offsets for this kernel
    ├─ Inject offsets into eBPF programs as globals
    ├─ Load programs (verified by kernel, not yet attached)
    │
    ├─ Populate all BPF maps (zones, policies, inodes, comms)
    ├─ Enumerate existing containers
    │
    ├─ Attach all 7 hooks (enforcement begins)
    │
    ├─ Self-test: compare two ways of reading cgroup_id
    │   ├─ BPF helper (known correct)
    │   └─ Offset chain (what we just configured)
    │
    ├─ Inode self-test: compare BPF-derived inode with stat()
    │   └─ Validates FILE_F_INODE_OFFSET and INODE_I_INO_OFFSET
    │
    ├─ Match? → enforcement active, drop CAP_SYS_ADMIN
    └─ Mismatch? → refuse to start (no silent failure)
```

If `pahole` isn't installed, defaults for Linux 6.1+ are used.

## Architecture

```
 ┌───────────────────────────────────────────────────────────┐
 │                        syva                               │
 │                                                           │
 │   Policy Loader          containerd Watcher    eBPF Mgr   │
 │   reads TOML files       gRPC event stream     aya + BTF  │
 │        │                       │                   │      │
 │        └───────────────────────┼───────────────────┘      │
 │                                │                          │
 │                     BPF map read/write                    │
 └────────────────────────────────┼──────────────────────────┘
                                  │
 ┌────────────────────────────────▼──────────────────────────┐
 │                      Linux kernel                         │
 │                                                           │
 │  ZONE_MEMBERSHIP    cgroup_id → zone      (who is where)  │
 │  ZONE_POLICY        zone → caps, flags    (Array, O(1))   │
 │  INODE_ZONE_MAP     inode → zone          (NO_PREALLOC)   │
 │  ZONE_ALLOWED_COMMS (zone, zone) → ok     (who can talk)   │
 │  ENFORCEMENT_EVENTS ring buffer, 4MB      (what happened)  │
 │                                                           │
 │  7 LSM hooks checking open/exec/mmap/kill/ptrace/cgroup/  │
 │  unix_connect                                             │
 └───────────────────────────────────────────────────────────┘
```

| Crate | What it is |
|-------|------------|
| `syva` | The agent binary. Loads eBPF, watches containerd, manages maps. |
| `syva-ebpf` | The 7 kernel programs. Separate build, targets `bpfel-unknown-none`. |
| `syva-ebpf-common` | Types shared between kernel and userspace (`#[repr(C)]`, `no_std`). |
| `xtask` | Build helper: `cargo run -p xtask -- build-ebpf` |

## Building

```bash
cargo build                        # agent + shared types (Linux only)
cargo run -p xtask -- build-ebpf   # kernel programs (requires nightly Rust)
cargo test                         # all tests
```

**Requires:** Linux 6.1+, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, boot with `lsm=lockdown,capability,bpf`.

## Limitations

**Software enforcement, not hardware.** Syva uses BPF maps in kernel memory. It's defense-in-depth, not a hypervisor boundary. A kernel exploit could bypass it.

**Additive only.** eBPF LSM hooks can deny but never override existing MAC policy (SELinux, AppArmor). Syva stacks on top.

**No hot-reload.** Policies load at startup. Restart the agent to pick up changes.

**One instance per node.** Syva pins BPF maps at `/sys/fs/bpf/syva/`. A second instance will refuse to start. The DaemonSet init container cleans stale pins automatically.

**Fail-open on errors.** Kernel struct read failures allow the operation (with error counter increment). This is defense-in-depth — a read failure shouldn't block the system. Errors are monitored and surfaced in `syva status`.

**Declarative-only fields.** Capabilities, resources, devices, syscalls, and network egress/ingress in policy TOML are parsed but not enforced by Syva's eBPF hooks. Use seccomp, cgroups, and NetworkPolicy for those. Syva warns at startup about configured-but-not-enforced fields.

**/proc access not controlled.** Virtual filesystem inodes are not in `INODE_ZONE_MAP`. Cross-zone `/proc/<pid>/mem` access is possible. Deferred to a future release.

**Unix socket enforcement is audit-only.** The `unix_stream_connect` hook emits events but does not block. Full enforcement requires peer cgroup resolution, which is pending.

## License

Apache-2.0
