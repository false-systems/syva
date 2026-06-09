# Syvä Lima development deployment

This is a **single-node development deployment proof**: it deploys Syvä as a
node-local agent inside a Lima Linux VM and verifies that the *deployed* instance
blocks a real container's cross-zone `file_open`. It is not a production install
and not a Kubernetes deployment — see "Next deployment work" below.

The lifecycle is a managed background process (`syva-core` started under sudo
with a PID/log/socket), not a systemd service or container image.

## Quick start

From the repo root on the macOS/Linux host:

```sh
make lima-up                  # start the VM (once)
make lima-bootstrap           # install/verify deps (idempotent)
make lima-deploy              # build + install + start syva-core, prove healthy
make lima-verify-deployment   # prove the deployed core blocks a real container
make lima-undeploy            # stop and clean up
```

Or the one-command proof (bootstrap → deploy → verify → undeploy):

```sh
make lima-smoke
```

`make lima-reset` undeploys and prints how to recreate the VM.

## Requirements

- macOS or Linux host with [Lima](https://lima-vm.io/) (`limactl`).
- Linux guest with **BPF LSM** enabled (`bpf` in `/sys/kernel/security/lsm`).
  `lima-bootstrap` configures the kernel command line if needed and tells you to
  reboot.
- Privileged `sudo` inside the VM (loading/attaching BPF LSM programs needs root).
- A container runtime: `podman` (default), `docker`, or `nerdctl`. Override with
  `SYVA_CONTAINER_RUNTIME`.
- Rust stable + nightly with `rust-src`, `bpf-linker`, `clang`/LLVM, `protoc`.
  The base `lima/syva.yaml` installs most of this; `lima-bootstrap` adds the rest
  (nightly + `rust-src`, `bpf-linker`, the runtime, the `syva` group).

## Runtime layout

```text
/usr/local/bin/syva-core            deployed binary
/usr/lib/syva/syva-ebpf             deployed release eBPF object
/run/syva/syva-core.sock            local syva.core.v1 Unix socket
/run/syva/syva-core.pid             core PID
/tmp/syva-deploy/logs/syva-core.log core log (startup + self-tests)
/tmp/syva-deploy/{policies,integration}
:9091/healthz                       health endpoint
```

`make lima-deploy` prints the kernel, BPF LSM status, release eBPF object path,
core PID, health JSON, attached hook count (6), and self-test results.

## What this proves

- Syvä can be **deployed as a node-local agent** (build → install → start → healthy).
- The release eBPF object loads and the **six BPF-LSM hooks attach**
  (`file_open`, `bprm_check_security`, `ptrace_access_check`, `task_kill`,
  `mmap_file`, `unix_stream_connect`).
- The cgroup, inode, and Unix **self-tests pass**.
- `make lima-verify-deployment` runs a **real container** against the *deployed*
  core (via `verify-deployment`, which targets `SYVA_SOCKET` and does not start
  its own core) and proves a zone-a container is **blocked from reading a zone-b
  file** with `EPERM` and `file_open deny_delta=1`, while its own zone-a read
  succeeds.

### Declared verification contract

```text
=== syva deployment verification contract ===
PASS:  deployed Syvä allows a container in zone-a to read its zone-a file.
BLOCK: deployed Syvä blocks a container in zone-a from reading the zone-b file.
HOOK:  file_open
EXPECTED DENIAL: EPERM / Operation not permitted
EXPECTED KERNEL EVIDENCE: file_open deny_delta=1
```

The `deny_delta` is **workload-attributable** (the test container is the only
zoned workload performing the forbidden open). The `file_open` `allow` counter is
**global** — it counts allowed opens system-wide, including unzoned/system
processes — and is not workload-specific.

## What this does not prove

- Kubernetes adapter integration is not exercised end to end by this Lima
  deployment proof. The k8s adapter has an annotation-based membership watcher,
  but `verify-k8s-membership` is still a follow-up.
- All six hooks end to end — only `file_open` is proven with a container.
- cgroup-movement / zone-escape protection — out of v0.2 scope (not a BPF-LSM hook).
- Production hardening or multi-node deployment.

## Rerun safety

The deploy lifecycle is rerun-safe. `make lima-undeploy` stops the core with
SIGTERM (so it unpins its BPF maps), removes the socket/PID/runtime dirs, and
removes test containers and temp files. A redeploy starts from a clean state
(fresh maps, `zones_loaded=0`). `make lima-verify-deployment` uses a unique
container/zone/dir per run and detaches its membership on success, so repeated
runs against a long-lived deployed core stay correct — only the per-run
`deny_delta` is asserted, not the global counter.

## Troubleshooting

**`bpf` missing from `/sys/kernel/security/lsm`** — BPF LSM must be enabled at
boot. Run `make lima-bootstrap`; it adds `bpf` to `GRUB_CMDLINE_LINUX` and asks
you to reboot (`limactl stop syva-dev && limactl start syva-dev`).

**Permission denied loading BPF** — the core must run as root / with the right
capabilities. The deploy and verify targets use `sudo`.

**Container runtime missing** — install `podman`/`docker`/`nerdctl` or run
`make lima-bootstrap`. Select a non-default runtime with
`SYVA_CONTAINER_RUNTIME=docker`.

**Image pull fails** — set `SYVA_TEST_IMAGE=...` or pre-pull the image
(`sudo podman pull docker.io/library/busybox`). The VM may need network access.

**Expected denial errno** — a blocked cross-zone read returns `EPERM`
(`Operation not permitted`), because the hook denies by returning `-1`. It is not
`EACCES`.

**`allow` counter looks high** — that is expected. `file_open` runs on every
`open()` system-wide, so the global `allow` counter includes unrelated system
opens. Only `deny_delta` is attributable to the test workload.

## Next deployment work (follow-ups, not in this round)

- Container image build for `syva-core` + a DaemonSet packaging.
- Privileged `securityContext` and runtime socket mounts for Kubernetes.
- CRD or file-policy mounting and a Kubernetes adapter integration proof.
- A self-hosted privileged CI runner to run the runtime/deployment gates
  automatically (today they are manual via `workflow_dispatch`).
