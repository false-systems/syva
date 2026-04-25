# AGENT.md

Operational field manual for Claude Code working on Syvä.
Read CLAUDE.md first. This file covers *how to work*, not *what exists*.

---

## Heartbeat Audit Exception

Node heartbeats are the single control-plane operation exempt from ADR 0003
Rule 8's "audit every mutation" discipline.

- Heartbeats happen many times per minute per node.
- `last_seen_at` is telemetry, not policy.
- Auditing every heartbeat would drown the audit log in low-value noise.

Heartbeats still write a `control_plane_events` row with
`event_type = 'node.heartbeat'`, preserving the causal spine. They do **not**
write to `audit_log`. This exception is specific to heartbeats and must not be
copied to any other operation.

---

## syva-core ingests zones via syva-cp

After session 4b, `syva-core` has one and only one ingestion path: the
`NodeAssignmentUpdate` stream from `syva-cp`. The local gRPC surface that
existed in v0.2 is deleted. `--cp-endpoint` is mandatory.

Adapters (`syva-file`, `syva-k8s`, `syva-api`) push zones to `syva-cp`
directly via `syva-cp-client`. They do not connect to `syva-core`.

Single-node operation (laptop, demo, CI) is achieved by running both
`syva-cp` and `syva-core` on the same machine, with `syva-cp` using a local
Postgres. There is no separate "local mode" code path.

If easier single-node operation becomes important, the future plan is to ship a
`syva-cp --embedded` mode that bundles Postgres or SQLite into the control
plane binary. That work is not in scope here.

---

## Mental Model: How to Think About This Codebase

Syvä is a kernel enforcement boundary. Every line of eBPF code runs in a
context with no allocator, no stdlib, a 512-byte stack, and a verifier that
will reject any path it cannot prove safe. Userspace code is the loader,
policy translator, and event consumer. The two halves have different failure
modes and different rules.

When something is wrong, work from the outside in:
1. What observable symptom exists? (`syva status`, ring buffer events, kernel logs)
2. Which hook produced it? (HOOK_NAMES, ENFORCEMENT_COUNTERS)
3. What kernel path does that hook sit on?
4. What does the verifier see at that point?

Never guess at kernel struct layout. Verify with `pahole`, `bpftool btf dump`,
or `/sys/kernel/btf/vmlinux`. A wrong offset silently reads garbage — the
verifier does not catch semantic errors, only safety errors.

---

## Gregg's Rules, Applied to This Codebase

Brendan Gregg's eBPF principles distilled to what matters here:

**Do the minimum in the kernel.**
eBPF programs are not the place to compute, format, or decide. They answer one
question — is this operation permitted — and emit one event if not. All
classification, policy evaluation, and formatting happens in userspace. If you
find yourself adding logic to a hook beyond a map lookup and a flag check, stop
and ask whether that belongs in the ring buffer consumer instead.

**Instrument what the kernel already tracks.**
cgroup IDs, inode numbers, task PIDs — the kernel maintains these. Read them.
Don't re-derive what you can look up. `bpf_get_current_cgroup_id()` is cheaper
and safer than walking the task struct yourself.

**Measure errors explicitly.**
Every `bpf_probe_read_kernel` call can fail. Fail-open is the policy here (see
CLAUDE.md), but failures must be counted. `ENFORCEMENT_COUNTERS` exists for
this. An unmeasured error is invisible. An invisible error looks like a working
system.

**The working set is the hot path.**
Map lookups on the hot path must hit L1/L2. `ZONE_MEMBERSHIP` and
`ZONE_POLICY` are sized for this. Don't add maps with unbounded growth on the
deny/allow critical path. `INODE_ZONE_MAP` uses `BPF_F_NO_PREALLOC` precisely
because it is large and not every lookup is hot.

**Use static analysis before dynamic.**
Before adding a new offset chain, trace it through `bpftool btf dump file
/sys/kernel/btf/vmlinux format c | grep -A20 'struct unix_sock'`. Know the
layout before writing a single line of eBPF. Offset errors are silent. Layout
verification is free.

---

## Lean Code Rules

This codebase has no boilerplate tolerance. These are not preferences.

**No wrapper types for wrapping's sake.**
If a newtype adds no invariant, it adds noise. `ZoneId(u32)` is fine because
zone 0 is reserved and the type encodes that. A newtype that is just `pub
struct Foo(Bar)` with no methods is a rename, not an abstraction.

**No trait objects where enums suffice.**
The hook set is fixed at 7. The policy types are known at compile time. Use
enums. `dyn Trait` in hot paths pays a vtable cost for flexibility you don't
need.

**No async where sync is fine.**
The ring buffer drain is `block_in_place` on a 100ms timer. That is not a
candidate for async refactoring. Async is appropriate for the containerd gRPC
watcher and the health endpoint. Not for map operations.

**No `unwrap()` in production paths.**
Already in CLAUDE.md. Reiterating because agents regress on this. Use `?`.
If the error context needs enrichment, use `.context("what we were doing")` via
`anyhow`. The `unwrap` signals "I didn't think about this path." That is not
acceptable in kernel enforcement code.

**No dead feature flags.**
If a flag is set but never checked by any eBPF program (`ZONE_FLAG_PRIVILEGED`
at time of writing), it must be documented as reserved, not silently present.
Don't add new flags without a corresponding hook check or a `// reserved:
rationale` comment.

**Inline comments explain *why*, not *what*.**
The code shows what. Comments explain kernel version constraints, verifier
quirks, intentional design choices, and known limitations. "// increment
counter" is noise. "// fail-open: verifier cannot prove read safety here, count
and allow" is signal.

---

## The Three Open Threads

### 1. Health Endpoint

**Goal**: make Syvä deployable. Liveness probes require HTTP.

**Scope**: add `axum` to `syva/Cargo.toml`. Bind a separate port (default 9091,
not 8080 — avoid collision with common workloads). Two routes only:

- `GET /healthz` — liveness. Returns 200 + JSON:
  ```json
  { "status": "ok", "policy_loaded": true, "zones_active": 3,
    "enforcement_mode": "enforce", "uptime_secs": 412 }
  ```
  Returns 503 if BPF programs are not attached (startup incomplete or detached).
- `GET /metrics` — Prometheus text format. Expose `ENFORCEMENT_COUNTERS`
  (allow/deny/error/lost per hook) as gauges. Use the `metrics` +
  `metrics-exporter-prometheus` crates. Hook names from `events::HOOK_NAMES`.

**What constitutes unhealthy** (503 on /healthz):
- BPF programs not attached (`EnforceEbpf.attached == false`)
- Self-test failed at startup (agent should have exited, but guard anyway)
- Policy directory empty / zero zones loaded

**What does NOT constitute unhealthy**:
- Lost events (warn in /metrics, not a liveness failure)
- Enforcement errors (same — surface in metrics)
- Zero active containers (policy loaded is enough for liveness)

**Implementation notes**:
- Spawn the HTTP server as a separate tokio task in `main.rs` *before* the
  enforcement loop, so it can report startup state.
- Pass health state via a `Arc<RwLock<HealthState>>` — not channels. The
  health state changes infrequently; reads are frequent.
- `HealthState` struct: `attached: bool`, `zones_loaded: usize`,
  `policy_loaded: bool`, `start_time: Instant`.
- Port configurable via `--health-port` CLI arg.

**What not to do**:
- Don't embed the HTTP server in `EnforceEbpf`. Separation of concerns.
- Don't use `warp` or `actix`. `axum` is already the Tokio-native choice.
- Don't expose raw BPF map contents over HTTP. `syva events` and `syva status`
  are the interfaces for that.

---

### 2. Unix Socket Full Enforcement

**Goal**: `unix_guard.rs` currently emits events but always returns 0 (allow).
Complete the enforcement by resolving the peer's cgroup.

**The kernel struct path** (verify against your running kernel before coding):
```
sock ptr (from hook arg)
  → struct unix_sock (cast via bpf_probe_read_kernel)
      → peer: *mut sock
          → sk_cgroup_data: struct sock_cgroup_data
              → val: u64  (encodes cgroup pointer, use bpf_get_current_cgroup_id pattern)
```

Actual field: `sock->sk_cgroup_data` is a `sock_cgroup_data` — on kernels with
cgroup v2, `.val` holds the cgroup pointer. Extract the cgroup id via the same
offset chain used in the existing cgroup self-test (`SELF_TEST` map). Reuse
those offsets — don't create a parallel offset resolution path.

**Verification steps before implementing**:
```bash
# confirm unix_sock layout on target kernel
pahole -C unix_sock /sys/kernel/btf/vmlinux
# confirm peer field offset
bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -A 30 'struct unix_sock'
# confirm sock_cgroup_data layout
pahole -C sock_cgroup_data /sys/kernel/btf/vmlinux
```

**eBPF change** (`unix_guard.rs`):
1. Read `peer` from `unix_sock` using `bpf_probe_read_kernel`.
2. From `peer`, read `sk_cgroup_data.val` using existing cgroup offset globals.
3. Look up peer cgroup_id in `ZONE_MEMBERSHIP`.
4. If peer zone == caller zone, or pair in `ZONE_ALLOWED_COMMS` → allow.
5. Otherwise deny and emit event (same pattern as `signal_guard.rs`).
6. Fail-open on any `bpf_probe_read_kernel` failure, increment error counter.

**New global offset needed**: `UNIX_SOCK_PEER_OFFSET` — resolve in `ebpf.rs`
alongside existing offsets. Same pahole + word-boundary matching pattern.

**Self-test**: add a `SELF_TEST_UNIX` map (same shape as `SELF_TEST`). Verify
the peer offset chain reads a valid cgroup_id in `verify_self_test()` before
attaching. This is not optional — a wrong offset here silently misidentifies
peers.

**What not to do**:
- Don't add a separate cgroup resolution function. Reuse the existing offset
  globals.
- Don't change the map schema. Peer zone resolution uses existing maps.
- Don't skip the self-test. The existing self-tests exist because offset errors
  are invisible without them.

---

### 3. CO-RE Migration

**Goal**: eliminate pahole dependency, eliminate startup offset resolution
latency, make Syvä portable across kernel versions without runtime offset
lookup.

**What CO-RE actually means here**: instead of calling pahole at startup to
find `task_struct.css_set` offset and patching it via `BpfLoader::set_global()`,
the eBPF program uses BTF-aware field accessors that aya resolves against
`/sys/kernel/btf/vmlinux` at load time. The offset is baked into the BPF
relocation table, not passed as a global.

**Current flow** (what we're replacing):
```
startup → pahole → parse offset → set_global("CGROUP_OFFSET", val) → eBPF reads global
```

**CO-RE flow**:
```
startup → aya loads object → aya reads /sys/kernel/btf/vmlinux → resolves BTF relocations → eBPF uses field directly
```

**aya version check**: you're on `aya = "0.13"` / `aya-ebpf = "0.1.x"`. CO-RE
relocation support is present. The mechanism in aya-ebpf is
`bpf_core_read!()` macro — use it for all kernel struct field accesses that
currently go through offset globals.

**Migration order** (do not migrate all at once):
1. `FILE_F_INODE_OFFSET` and `INODE_I_INO_OFFSET` first — used in inode
   self-test, simplest chain, easy to validate.
2. Cgroup offset chain (`CGROUP_OFFSET`, `CSS_SET_OFFSET`) second — used in
   every hook, highest value.
3. `UNIX_SOCK_PEER_OFFSET` third — add it CO-RE-native from the start when
   implementing thread 2 above. Don't add it as a global and migrate later.

**For each offset converted**:
- Remove the `set_global()` call in `ebpf.rs`
- Replace `bpf_probe_read_kernel` + manual offset arithmetic with `bpf_core_read!()`
- Remove the corresponding pahole invocation
- Keep the self-test — it now validates the CO-RE read returns sane values
  rather than validating an offset. Same observable behavior, different mechanism.

**When pahole is gone**: remove it from platform requirements in CLAUDE.md.
Update the startup sequence documentation. Keep BTF requirement
(`/sys/kernel/btf/vmlinux`) — CO-RE needs it.

**What not to do**:
- Don't migrate everything in one commit. Each offset chain is a separate,
  testable unit.
- Don't remove self-tests when removing pahole. The self-tests validate
  semantics, not mechanism.
- Don't assume CO-RE "just works" — run `bpftool prog load` with `--debug` to
  see relocation resolution in action before trusting it in production.

---

## Debugging Playbook

**Hook not firing**:
```bash
bpftool prog list          # confirm program loaded
bpftool prog show id <N>   # confirm attached
cat /sys/kernel/debug/tracing/trace_pipe  # raw BPF trace output (aya-log)
```

**Offset chain wrong** (symptom: self-test fails at startup, or events show
cgroup_id 0):
```bash
pahole -C task_struct /sys/kernel/btf/vmlinux | grep -E 'css_set|cgroups'
bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h
grep -A 5 'css_set' /tmp/vmlinux.h
```

**Verifier rejection** (symptom: `cargo run` fails with `Permission denied` or
`invalid program`):
```bash
RUST_LOG=aya=debug cargo run --bin syva -- --policy-dir ./policies 2>&1 | grep -A 20 'verifier'
```
The verifier error message names the instruction offset. Count instructions in
the relevant eBPF function from the top to find the line.

**Ring buffer lost events**:
`syva status` shows lost count per hook. If non-zero, the ring buffer is full
before userspace drains it. Options: increase ring buffer size (currently 4MB,
defined in `syva-ebpf/src/main.rs`), decrease drain interval (currently 100ms
in `events.rs`), or reduce event verbosity (emit only on deny, not on allow).

**Map lookup returning None unexpectedly**:
```bash
bpftool map dump name ZONE_MEMBERSHIP   # confirm cgroup_id is in the map
bpftool map dump name ZONE_POLICY       # confirm zone_id has a policy entry
cat /sys/fs/cgroup/<container>/cgroup.controllers  # confirm cgroup exists
```

---

## Git Workflow

**No direct commits to main. No merge commits. No squash-at-the-end.**

Branch per thread:
```
feat/health-endpoint
feat/unix-enforcement
feat/core-migration
```

Commit as you go. Each commit must:
- Build (`cargo build`)
- Pass tests (`cargo test -p syva-ebpf-common`)
- Leave the codebase in a working state

Commit message format:
```
<scope>: <what changed and why>

syva: add /healthz endpoint with BPF attach state check

HTTP server binds on --health-port (default 9091). Returns 503 if
programs not yet attached. Avoids liveness false-positives during
the startup window between load() and attach_programs().
```

Scopes: `ebpf`, `syva`, `policy`, `watcher`, `events`, `build`, `docs`.

PR per thread. PR description states:
- what the thread was (link to AGENT.md section)
- what changed
- how it was tested (which kernel version, which containerd version)
- any self-test results

**No "WIP" commits on main.** WIP commits are fine on feature branches.
**No commits that disable self-tests** even temporarily.
**No commits that change offset resolution without updating the corresponding
self-test.**

---

## Invariants That Must Not Break

These are not conventions. Breaking them breaks the security model.

1. **Attach happens after zone population.** `attach_programs()` is always
   called after `ZONE_MEMBERSHIP` is populated. Any refactor of startup
   sequence must preserve this ordering. The window between attach and
   population is a security gap.

2. **Self-tests are not optional.** Both `verify_self_test()` and
   `verify_inode_self_test()` must pass before enforcement begins. Startup
   must abort on failure. Never route around them.

3. **Zone 0 is ZONE_ID_HOST.** No container gets zone_id 0. The
   `wrapping_add` exhaustion check in `register_zone()` exists for this.
   Don't change zone ID assignment logic without auditing this check.

4. **Fail-open is a policy, not a bug.** Every `bpf_probe_read_kernel`
   failure allows the operation and increments the error counter. This is
   intentional. Don't convert fail-open paths to fail-closed without explicit
   design discussion — the blast radius of a kernel read failure in a
   production cluster is a cluster outage.

5. **Mutual exclusion at `/sys/fs/bpf/syva/`.** Only one Syvä instance per
   node. The pin check is the enforcement mechanism. Don't remove it. Don't
   add a `--force` flag.

6. **`allowed_zones` symmetry is enforced at load time.** One-sided
   declarations are logged and rejected. Don't weaken this to a warning-only
   path — asymmetric allows are a policy misconfiguration that silently
   doesn't do what the operator intended.
