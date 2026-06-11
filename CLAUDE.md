# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository. It describes the active repository architecture.
Read `AGENT.md` for working practices and `SKILLS.md` for security-model rules.

## Current State

Syva v0.2 is the active product line: local `syva-core` + adapters + eBPF
enforcement. The v0.3 `syva-cp` control-plane experiment has been removed from
the active workspace. Historical CP notes are archived under `docs/archive/`.

Do not add new code that depends on `syva-cp`, `syva_control.proto`,
`cp_reconcile`, Postgres, node heartbeats, team ownership, or CP assignment
streams in this repository.

## Build And Test

Host-safe checks:

```bash
make macos-check
```

Linux full checks:

```bash
make fmt
make lint
make test
make precommit
make ci
```

Every `make` target wraps one source of truth: `cargo run -p xtask -- <cmd>`
(`fmt`, `lint`, `check`, `test`, `proto-check`, `check-release-docs`,
`check-ebpf-artifact-policy`, `eval-build`, `precommit`, `ci`, `build-ebpf`).
CI (`.github/workflows/ci.yml`) invokes the same xtask commands, so `make ci`
reproduces CI locally.

Run a focused test:

```bash
cargo test -p syva-core zone::tests::register_zone_is_idempotent  # one unit test
cargo test -p <crate> <name-substring>                           # by name
```

The eval suites live outside the workspace (own manifests, run via `--manifest-path`):

```bash
cargo test --manifest-path eval/oracle/Cargo.toml -- case_003 --exact --nocapture
cargo run  --manifest-path eval/harness/Cargo.toml               # spec harness
```

`build-ebpf` builds the release eBPF object by default because that is the
runtime artifact. Use `--debug` only for development.

macOS uses Lima for Linux verification:

```bash
make lima-up
make lima-check
make lima-shell
```

`make lima-check` runs format check, clippy, workspace check, workspace tests,
eval crate builds, and eBPF object compilation in the `syva-dev` Lima VM.

Privileged runtime evidence is separate (privileged Linux / BPF-LSM only; the
container gate also needs a container runtime). All are `#[ignore]`d in normal
`cargo test`:

```bash
sudo -E make verify-runtime              # load + attach 7 hooks + self-tests
sudo -E make verify-integration          # process/cgroup file_open denial (EPERM)
sudo -E make verify-container-integration # same denial against a real container
sudo -E make verify-audit-mode           # audit mode records would-deny without blocking
```

The gates above each start their own core. To verify a core that is
already running, use `make verify-deployment` (needs `SYVA_SOCKET`, default
`/run/syva/syva-core.sock`, plus a container runtime). The single-node Lima
deployment lifecycle is `make lima-bootstrap` → `lima-deploy` →
`lima-verify-deployment` → `lima-undeploy`, wrapped end to end by
`make lima-smoke`.

## Release-Doc Drift Guardrail

`cargo run -p xtask -- check-release-docs` (run by `make precommit`, `make ci`,
and the CI `guardrails` job) fails the build when tracked docs/code drift from
the v0.2 contract. It scans tracked `*.md`/`*.rs`/`*.proto`/`*.toml`/`*.yaml`
(excluding `docs/archive/`, and skipping fenced code blocks) and, outside code
fences, rejects:

```text
- stale hook counts: "6 hooks" / "six hooks" / "8 hooks"   (v0.4 has seven)
- "syva_cgroup_attach"
- "cgroup_attach_task" UNLESS nearby text marks it a known gap
  ("not a bpf-lsm hook", "out of v0.2 scope", "do not reintroduce", assert!)
- "lima proves/verifies runtime|enforcement" without a "not"/"unless" caveat
- "debug ebpf" called the "default"/"runtime artifact" (release is the default)
```

It also requires `README.md`, `CLAUDE.md`, `AGENT.md`, `SKILLS.md`, and
`docs/release/v0.2-runtime-verification.md` to each mention all three runtime
gates: `verify-runtime`, `verify-integration`, `verify-container-integration`.
Preserve these invariants when editing docs (put illustrative trigger strings
inside code fences, which the checker skips). `xtask/src/main.rs` is exempt
because it stores the trigger strings as literals.

## Active Crates

| Crate | Binary | Purpose |
| --- | --- | --- |
| `syva-proto` | - | `syva.core.v1` protobuf API |
| `syva-core-client` | - | Unix-socket gRPC client for adapters |
| `syva-core` | `syva-core` | Linux eBPF enforcement engine and local API |
| `syvactl` | `syvactl` | Thin local operator CLI over `syva.core.v1` |
| `syva-adapter-file` | `syva-file` | TOML policy reconciler |
| `syva-adapter-k8s` | `syva-k8s` | `SyvaZonePolicy` CRD reconciler |
| `syva-adapter-api` | `syva-api` | REST proxy to local core |
| `syva-ebpf-common` | - | Shared userspace/eBPF C-layout types |
| `syva-ebpf` | - | Separate nightly eBPF workspace |
| `xtask` | - | Build/check helper |

Eval crates under `eval/` are outside the workspace and use their own
manifests.

API docs live under `docs/api/`. The protobuf/gRPC API (`syva.core.v1`) is the
source of truth; OpenAPI documents only the partial REST API; `syvactl` is a
thin local gRPC client. Keep `cargo run -p xtask -- check-api-docs` and
`cargo run -p xtask -- check-openapi` green when changing the control surface.

## Enforcement Model

`syva-core` populates BPF maps; seven eBPF LSM programs (`syva-ebpf/src/`) read
them on every relevant syscall and allow or deny:

| Hook (LSM) | File | Blocks cross-zone |
| --- | --- | --- |
| `file_open` | `file_guard.rs` | file open |
| `bprm_check_security` | `exec_guard.rs` | exec |
| `mmap_file` | `mmap_guard.rs` | `mmap(PROT_EXEC)` |
| `ptrace_access_check` | `ptrace_guard.rs` | ptrace |
| `task_kill` | `signal_guard.rs` | signals |
| `unix_stream_connect` | `unix_guard.rs` | Unix socket connect |
| `socket_connect` | `socket_guard.rs` | outbound TCP/UDP (egress lock) |

Every hook follows one decision shape: resolve the caller's zone from
`bpf_get_current_cgroup_id()` → `ZONE_MEMBERSHIP`; resolve the target's zone
(file/exec via inode → `INODE_ZONE_MAP`); allow if same zone or an explicit
`ZONE_ALLOWED_COMMS` pair, otherwise deny. A deny returns `-1`, surfaced to
userspace as **EPERM** ("Operation not permitted"), not EACCES. A caller or
target not in any zone is invisible to enforcement (allowed). On a
`bpf_probe_read` failure the hook **fails open** and increments an error
counter.

`socket_connect` is the one hook with no target zone: it is an **egress lock**.
A non-global zoned caller may not initiate outbound non-loopback
AF_INET/AF_INET6 connects unless its zone policy carries
`POLICY_FLAG_ALLOW_EGRESS` (set for every `NetworkMode` except `Isolated`).
Loopback is always allowed; AF_UNIX is left to `unix_stream_connect`. Because
`Isolated` is the default network mode, default zones deny egress — roll this
out behind `--mode audit` first.

`syva-core --mode audit` switches the global `ENFORCEMENT_MODE` map to
observe-only: deny decisions are still counted (per-hook `deny` counter) and
emitted as `WOULD_DENY` events, but the hooks return 0 so the operation
proceeds. The default is enforce; audit is exposed via `/healthz`
(`enforcement_mode`) and the `syva_enforcement_mode` metric and is proven by
the `verify-audit-mode` gate.

Maps: `ZONE_MEMBERSHIP`, `ZONE_POLICY`, `INODE_ZONE_MAP`, `ZONE_ALLOWED_COMMS`,
`ENFORCEMENT_MODE` (global enforce/audit switch),
`ENFORCEMENT_COUNTERS` (per-hook allow/deny/error/lost), `ENFORCEMENT_EVENTS`
(ring buffer), `CGROUP_ESCAPE_COUNT` (detected escapes), plus `SELF_TEST*` maps
used only to validate offset chains at startup.

Separate from the seven LSM hooks, a best-effort fentry program
(`escape_guard.rs`, attached to `cgroup_attach_task`) detects cgroup-zone
escapes. It is not an LSM hook, does not count toward `expected_hooks`, and
cannot block — detection only. Kernel struct offsets are resolved from BTF at startup (`btf.rs`) and
patched into eBPF globals — no offsets are hardcoded.

## Key Files

`syva-core/src/`: `ebpf.rs` (load/attach, BPF map ops, self-tests, eBPF-object
discovery — release preferred over debug), `zone.rs` (zone registry + ID
allocation), `membership.rs` (container→zone), `ingest.rs` (RPC→map apply),
`rpc/mod.rs` (`syva.core.v1` gRPC service), `health.rs` (`/healthz` + `/metrics`),
`events.rs` (ring-buffer drain, `HOOK_NAMES`), `btf.rs` (offset resolution),
`container_id.rs` (ID validation), `types.rs` (shared core types). Privileged
integration tests are under
`syva-core/tests/` (all `#[ignore]`d; driven by the `verify-*` gates).

## Core Startup

`syva-core` always serves the local `syva.core.v1` Unix socket. Startup:

1. Start health server on `:9091`.
2. Load eBPF object.
3. Attach LSM hooks.
4. Run cgroup, inode, and Unix self-tests.
5. Mark BPF attached.
6. Start the local gRPC server at `--socket-path`.
7. Monitor hook counters and expose degraded health if fail-open errors appear.

Run on Linux:

```bash
RUST_LOG=syva_core=debug cargo run --bin syva-core -- \
  --socket-path /run/syva/syva-core.sock
```

## Membership

Container membership is tracked in `syva-core/src/membership.rs`. It records
container ID, optional pod identity, cgroup ID, source adapter, generation, zone,
and observed timestamp. It is idempotent, rejects stale generations, reports
conflicts, and produces BPF map update intents.
For `AttachContainer`, generation `0` means an ungenerated local update; it is
not stale only because generated state already exists, and metadata-only
reattach preserves the stored non-zero generation.
For `DetachContainer`, generation `0` means "no generation guard" and detaches
regardless of the stored generation; non-zero stale generations are refused with
a response message.

The adapters currently reconcile zones, host paths, and communication policy.
Automatic pod/container watcher integration still needs to call
`AttachContainer`/`DetachContainer` end to end.

## Health

The health server (`:9091`, configurable via `--health-port`) serves
`/healthz` (readiness JSON with the security status) and `/metrics`
(Prometheus enforcement-confidence metrics). See
`docs/operations/monitoring.md` for scrape, alert, and dashboard details.
Security status is:

- `healthy`: eBPF loaded, all seven supported hooks attached, mandatory self-tests
  passed, BPF counter reads are succeeding, and no active degradation is known.
- `degraded`: Syva is running, but BPF map errors, hook error/lost deltas,
  failed counter reads, or membership reconciliation problems reduce
  enforcement confidence.
- `unsafe`: eBPF is not loaded, fewer than seven hooks are attached, or mandatory
  startup self-tests failed.

Fail-open hook errors are degraded security, not harmless warnings.

## Known Limits

- Full BPF load/attach/runtime verification requires a privileged Linux host.
- Lima covers Linux build/test/eBPF object compilation from macOS, not guaranteed
  runtime attachment.
- Syva supports seven BPF-LSM hooks. Cgroup movement / zone escape cannot be
  **prevented** through BPF-LSM because `cgroup_attach_task` is not a BPF-LSM
  hook on supported kernels. It is instead **detected**: a best-effort fentry on
  `cgroup_attach_task` reads a migrating task's source cgroup (before the move)
  and records an escape when a zoned task leaves for an unzoned/other-zone
  cgroup (`syva_cgroup_escape_detected_total`, `WOULD`-style `ESCAPE` event,
  degraded health). The migration itself is not blocked. Proven by
  `verify-cgroup-escape`.
- `/proc` and `/sys` coverage remains incomplete.
- `INODE_ZONE_MAP` is keyed by inode only; `(dev, ino)` is still needed.
- Kubernetes adapter status/finalizers/leader election are not implemented.
