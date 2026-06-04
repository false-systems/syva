# AGENT.md

Operational field manual for agents working on Syva.

Read `CLAUDE.md` first for the active architecture and `SKILLS.md` for the
security invariants. Syva is a kernel enforcement project; keep changes small,
testable, and honest about what is enforced.

## Mental Model

Syva has two halves:

- Userspace keeps BPF maps accurate: zones, membership, inode ownership, and
  allowed zone pairs.
- eBPF LSM hooks make fast allow/deny decisions from those maps.

When debugging, work from the observable symptom inward:

1. Check `syva-core status`, `/healthz`, `/metrics`, and ring-buffer events.
2. Identify the hook via `HOOK_NAMES` and `ENFORCEMENT_COUNTERS`.
3. Check the relevant BPF map with `bpftool`.
4. Verify kernel struct layout through BTF, not guesses.

Kernel read failures fail open and increment counters. Treat that as degraded
security in code, docs, and reports.

## Verification

macOS direct checks are useful for fast feedback:

```bash
make macos-check
```

Linux verification from macOS:

```bash
make lima-up
make lima-check
make lima-shell
```

Native Linux:

```bash
cargo run -p xtask -- ci
```

Runtime attach/enforcement tests still need a privileged Linux kernel with BPF
LSM support.

## Debugging

Hook not firing:

```bash
bpftool prog list
bpftool map dump name ZONE_MEMBERSHIP
bpftool map dump name ZONE_POLICY
```

Offset/self-test failures:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h
grep -A 5 'css_set' /tmp/vmlinux.h
```

Verifier rejection:

```bash
RUST_LOG=aya=debug cargo run --bin syva-core 2>&1 | grep -A 20 verifier
```

## Current Follow-Ups

- Wire file/k8s pod/container watchers into `AttachContainer` and
  `DetachContainer`.
- Change file identity from inode-only to `(dev, ino)`.
- Add privileged Linux runtime load/attach blackbox verification.
- Continue CO-RE migration one offset chain at a time while keeping self-tests.

## Git Hygiene

Do not revert unrelated user changes. Keep semantic changes focused. Avoid
format-only churn unless it is needed to make CI gate cleanly. Never disable an
eBPF self-test to get a build green.
