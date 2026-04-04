# Syva

**Your containers share a kernel. Syva makes the kernel enforce boundaries between them.**

Today, container isolation is structural — namespaces and cgroups set up walls. But nothing checks whether Container A is accessing Container B's files, sending it signals, or attaching a debugger to it. The kernel doesn't know these containers shouldn't interact.

Syva fixes this. It loads small programs into the kernel (via eBPF) that intercept security-sensitive operations — opening files, executing binaries, sending signals — and checks whether the caller is allowed to touch the target. If not, the operation is denied before it happens.

No sidecar. No proxy. No runtime replacement. Deploy one agent per node, label your containers, done.

> *Syvä* (Finnish) — deep. Where enforcement happens.

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
          │   kill(pg_pid, 9) ───────X   │
          │   ptrace(redis_pid) ─────X   │
          │                              │
          X = denied by Syva in the kernel
```

Without Syva, these containers can interact through the shared kernel — read each other's files via `/proc`, send signals, attach debuggers. With Syva, every such operation hits a kernel checkpoint that verifies zone membership first.

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

## Five Kernel Hooks

Syva intercepts five operations. Together, they cover the main ways containers can interact through a shared kernel:

```
 ┌─────────────────────────────────────────────────────────────┐
 │                                                             │
 │   open()    Can this process read/write this file?          │
 │                                                             │
 │   exec()    Can this process run this binary?               │
 │                                                             │
 │   ptrace()  Can this process debug/inspect that process?    │
 │                                                             │
 │   kill()    Can this process send a signal to that process? │
 │                                                             │
 │   cgroup_attach()  Can this process escape its zone?        │
 │                                                             │
 └─────────────────────────────────────────────────────────────┘

 Each hook:  caller zone ──?── target zone
             same zone → allow
             different zone, no policy rule → DENY
             different zone, explicit allow → allow
```

Every deny is recorded with the caller PID, both zone IDs, and hook-specific context (file inode, target cgroup, etc.).

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
allowed_egress = ["0.0.0.0/0:443"]

[filesystem]
writable_paths = ["/data", "/tmp", "/var/log"]

[syscalls]
deny = ["mount", "umount2", "pivot_root"]
```

**Default: deny everything.** Cross-zone communication only happens when both zones list each other in `allowed_zones`.

## Deploy

### On Kubernetes

```bash
# 1. Create policies as a ConfigMap
kubectl create configmap syva-policies \
  --from-file=frontend.toml \
  --from-file=database.toml \
  -n syva-system

# 2. Deploy the DaemonSet (one agent per node)
kubectl apply -f deploy/syva-daemonset.yaml

# 3. Label your pods
#    Add to your pod spec:
#      annotations:
#        syva.dev/zone: "frontend"
```

Syva runs as a privileged DaemonSet with `CAP_BPF`, `CAP_SYS_ADMIN`, and `CAP_PERFMON`. It mounts `/sys/fs/bpf`, `/sys/fs/cgroup`, and the containerd socket.

### Standalone

```bash
syva --policy-dir /etc/syva/policies
```

Uses `/run/containerd/containerd.sock` by default. Override with `--containerd-sock`.

### Verify

```bash
syva status
```

```
syva: ACTIVE
  pin path: /sys/fs/bpf/syva
  hooks:
    file_open:      allow=48201  deny=3   error=0
    bprm_check:     allow=892    deny=0   error=0
    ptrace_check:   allow=12     deny=1   error=0
    task_kill:      allow=340    deny=0   error=0
    cgroup_attach:  allow=28     deny=0   error=0
```

## Observability

Every deny is emitted as a structured event:

```
WARN DENY  hook=file_open  pid=1847  caller_zone=2  target_zone=3  context=8421376
WARN DENY  hook=ptrace     pid=992   caller_zone=1  target_zone=2  context=0
```

These events come from a BPF ring buffer (1MB, ~21K events) and are logged via `tracing`. Allows are tracked in per-CPU counters only — no per-event overhead for the common path.

## How Syva Handles Kernel Differences

eBPF programs read kernel struct fields (`task_struct->cgroups`, `file->f_inode`). The byte offset of these fields changes between kernel versions. Syva handles this:

```
 Startup
    │
    ├─ Load BTF from /sys/kernel/btf/vmlinux
    ├─ Run pahole to get real offsets for this kernel
    ├─ Inject offsets into eBPF programs as globals
    ├─ Load and attach programs
    │
    ├─ Self-test: open a file, compare two ways of reading cgroup_id
    │   ├─ BPF helper (known correct)
    │   └─ Offset chain (what we just configured)
    │
    ├─ Match? → enforcement active
    └─ Mismatch? → refuse to load (no silent failure)
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
 │  ZONE_POLICY        zone → caps, flags    (what's allowed) │
 │  INODE_ZONE_MAP     inode → zone          (who owns what)  │
 │  ZONE_ALLOWED_COMMS (zone, zone) → ok     (who can talk)   │
 │  ENFORCEMENT_EVENTS ring buffer           (what happened)  │
 │                                                           │
 │  5 LSM hooks checking every open/exec/kill/ptrace/cgroup  │
 └───────────────────────────────────────────────────────────┘
```

| Crate | What it is |
|-------|------------|
| `syva` | The agent binary. Loads eBPF, watches containerd, manages maps. |
| `syva-ebpf` | The 5 kernel programs. Separate build, targets `bpfel-unknown-none`. |
| `syva-ebpf-common` | Types shared between kernel and userspace (`#[repr(C)]`, `no_std`). |
| `xtask` | Build helper: `cargo xtask build-ebpf` |

## Building

```bash
cargo build                        # agent + shared types (Linux only)
cargo xtask build-ebpf             # kernel programs (requires nightly Rust)
cargo test                         # all tests
```

**Requires:** Linux 6.1+, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, boot with `lsm=lockdown,capability,bpf`.

## Limitations

**Software enforcement, not hardware.** Syva uses BPF maps in kernel memory. It's defense-in-depth, not a hypervisor boundary. A kernel exploit could bypass it.

**Additive only.** eBPF LSM hooks can deny but never override existing MAC policy (SELinux, AppArmor). Syva stacks on top.

**No hot-reload.** Policies load at startup. Restart the agent to pick up changes.

**One instance per node.** Syva pins BPF maps at `/sys/fs/bpf/syva/`. A second instance will refuse to start.

## License

Apache-2.0
