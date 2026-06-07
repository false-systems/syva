# CLAUDE.md

This file describes the active repository architecture for Claude Code.
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
sudo -E make verify-runtime              # load + attach 6 hooks + self-tests
sudo -E make verify-integration          # process/cgroup file_open denial (EPERM)
sudo -E make verify-container-integration # same denial against a real container
```

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

Security status is:

- `healthy`: BPF attached and no active degradation.
- `degraded`: Syva is running, but hook error/lost counters or membership
  reconciliation problems reduce enforcement confidence.
- `unsafe`: BPF is not attached or startup self-tests failed.

Fail-open hook errors are degraded security, not harmless warnings.

## Known Limits

- Full BPF load/attach/runtime verification requires a privileged Linux host.
- Lima covers Linux build/test/eBPF object compilation from macOS, not guaranteed
  runtime attachment.
- Syva v0.2 supports six BPF-LSM hooks. Cgroup movement / zone escape
  protection is not enforced through BPF-LSM because `cgroup_attach_task` is not
  a BPF-LSM hook on supported kernels; implement that follow-up with a valid
  cgroup BPF mechanism or another kernel-supported hook.
- `/proc` and `/sys` coverage remains incomplete.
- `INODE_ZONE_MAP` is keyed by inode only; `(dev, ino)` is still needed.
- Kubernetes adapter status/finalizers/leader election are not implemented.
