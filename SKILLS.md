# SKILLS.md — operating manual for AI coding agents

Cliff-notes version of CLAUDE.md and AGENT.md. Read those for depth; keep this in working memory at all times.

## The thesis (do not violate)

**Syva is kernel-level zone isolation, simpler than NetworkPolicy + AppArmor + seccomp combined.**

When considering any change, ask: does this make the kernel-level isolation sharper, or does it make Syva look more like a generic policy management tool? If the latter, don't add it.

This is the line. A v0.3 control-plane experiment (`syva-cp`) crossed it and was removed; the design notes are archived under `docs/archive/` as a record of what not to rebuild here.

## Architecture

```
TOML files ─────► syva-file ──┐
SyvaZonePolicy CRDs ─► syva-k8s ─┤── Unix socket (syva.core.v1) ──► syva-core ──► 6 LSM hooks
HTTP requests ─► syva-api ────┘                                       │
                                                                       └─► BPF maps
```

- `syva-core` runs per-node, owns the eBPF programs and BPF maps, exposes `syva.core.v1` gRPC on a local Unix socket.
- Adapters connect to the local core. Each adapter translates its domain (TOML files / k8s CRDs / REST) into core RPCs.
- No remote control plane. Scale is achieved by composing with k8s primitives (RBAC, namespaces, audit logs, GitOps tooling like Argo/Flux).
- **v0.2 attaches six BPF-LSM hooks:** `file_open`, `bprm_check_security`, `ptrace_access_check`, `task_kill`, `mmap_file`, `unix_stream_connect`. cgroup-movement / zone-escape protection is **out of v0.2 scope** — `cgroup_attach_task` is not a BPF-LSM hook on mainline kernels; do not reintroduce it.

## Hard rules — breaking these breaks the security model

1. **Attach happens after zone population.** `attach_programs()` runs after `ZONE_MEMBERSHIP` is populated. The window between the two is a security gap. Never reorder.
2. **Self-tests are not optional.** All three self-tests (`verify_self_test`, `verify_inode_self_test`, `verify_unix_self_test`) must pass before enforcement begins. Abort startup on failure. Never route around them, never disable "temporarily."
3. **Zone 0 is `ZONE_ID_HOST`.** No container ever gets zone_id 0. The `wrapping_add` exhaustion check exists for this — don't change zone-ID assignment without auditing it.
4. **Fail-open is policy, not a bug.** Every `bpf_probe_read_kernel` failure allows the operation and increments the error counter. Intentional. Don't convert to fail-closed without explicit design discussion.
5. **Mutual exclusion at `/sys/fs/bpf/syva/`.** Only one syva-core per node. The pin check is the enforcement mechanism. Don't remove it. Don't add `--force`.
6. **`allowed_zones` symmetry enforced at load time.** One-sided declarations are rejected. Don't weaken to warning-only.

## Code rules — non-negotiable

- **No `.unwrap()` in production paths.** Use `?` or `.ok_or_else()`. `unwrap` signals "I didn't think about this path"; not acceptable in kernel enforcement code.
- **Comments explain *why*, not *what*.** Kernel constraints, verifier quirks, intentional design choices, known limitations. "// increment counter" is noise. "// fail-open: verifier cannot prove read safety here, count and allow" is signal.
- **No wrapper types without invariants.** `ZoneId(u32)` is fine because zone 0 is reserved and the type encodes that. `pub struct Foo(Bar)` with no methods is a rename, not an abstraction.
- **No trait objects where enums suffice.** The hook set is fixed (six hooks in v0.2); policy types are known at compile time. Use enums. `dyn Trait` on a hot path pays a vtable cost for flexibility you don't need.
- **No async where sync is fine.** Ring-buffer drain is `block_in_place` on a 100ms timer. Map operations are sync. Async is for the gRPC server, the containerd watcher, and the health endpoint.
- **No dead feature flags.** If a flag exists but no eBPF program checks it, document it as reserved or remove it.
- **No backwards-compatibility hacks.** No renamed `_unused`, no `// removed: see issue X` comments. Delete it.

## eBPF discipline (Brendan Gregg's rules, applied here)

- **Do the minimum in the kernel.** A hook answers one question: is this operation permitted. Classification, formatting, policy evaluation — all userspace.
- **Instrument what the kernel already tracks.** cgroup IDs, inode numbers, task PIDs. Don't re-derive what `bpf_get_current_cgroup_id()` already gives you.
- **Measure errors explicitly.** Every `bpf_probe_read_kernel` failure must be counted in `ENFORCEMENT_COUNTERS`. An unmeasured error is invisible; an invisible error looks like a working system.
- **The working set is the hot path.** Map lookups on the deny/allow path must stay cache-resident. `ZONE_MEMBERSHIP` and `ZONE_POLICY` are sized for this; `INODE_ZONE_MAP` uses `BPF_F_NO_PREALLOC` because it is large and not every lookup is hot. Don't add unbounded-growth maps on the critical path.
- **Use static analysis before dynamic.** Before adding a kernel-struct offset chain, verify with `bpftool btf dump` or `pahole`. Offset errors are silent.

## Where to look

| You need... | Read |
|---|---|
| Codebase architecture, file roles, eBPF map definitions | `CLAUDE.md` |
| Mental model, debugging playbook, open work, git workflow | `AGENT.md` |
| Thesis, hard rules, code + eBPF discipline | `SKILLS.md` (this file) |
| Linux verification from macOS via Lima | `docs/development/lima.md` |
| Why the removed v0.3 control plane existed (historical) | `docs/archive/0002-control-plane.md` |
| Write-discipline patterns from the removed CP code (reference) | `docs/archive/0003-transactional-write-discipline.md` |

## When stuck

- **Don't improvise.** Stop and report what you found.
- **Don't disable self-tests** even temporarily. Find the underlying issue.
- **Don't add `--force` flags** to bypass safety checks. Find the root cause.
- **Don't commit broken intermediate states.** Each PR must build and pass tests.
- **Don't skip hooks** (`--no-verify`, `--no-gpg-sign`). If a hook fails, fix the cause.

## Resist scope creep

These are not free wins — each one risks turning Syva into a generic policy tool, so don't add them without an explicit decision:

- New eBPF hooks
- New policy fields
- Anything that reintroduces a remote control plane (`syva-cp`, assignment streams, Postgres)

The current follow-ups (pod/container watchers into `AttachContainer`, `(dev, ino)` file identity, runtime load/attach verification) are tracked in `AGENT.md`.
