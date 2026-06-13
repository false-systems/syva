# Self-hosted runner for the kernel-enforcement gates

Hosted CI (GitHub, most managed CI) can build and test Syva but **cannot run
the enforcement gates** — no provider grants BPF-LSM on their kernel. Proving
"it blocks, and it doesn't over-block" on every change therefore requires a
runner on a kernel we control. This is a *permanent* operational dependency of
the product category, not a one-time chore: budget for it as ongoing infra.

The gates run from `.github/workflows/privileged-runtime.yml`.

## Threat model — read first

The job runs `sudo` with BPF and kernel access. A compromised job is host root.
The controls are not optional hardening; they are the design:

- **No `pull_request` trigger.** The workflow runs only on pushes to `main`,
  release tags, and manual dispatch — a forked PR can never reach the
  privileged runner. (The standard self-hosted-runner compromise path is a
  fork PR that edits the workflow; we close it by not triggering on PRs.)
- **`if: github.repository == 'false-systems/syva'`** on every job — forks that
  enable Actions can't run it even via dispatch.
- **Dedicated, disposable host.** Never a developer workstation. The runner
  host is in-scope for exactly the threat Syva defends against, so isolate it
  at the infra level (its own VM/box, its own network segment).
- **Prefer ephemeral runners** — register with `--ephemeral` so each job gets a
  fresh runner that is torn down after one job. A compromised job then cannot
  persist to watch the next. A throwaway VM rolled between jobs is safer than
  persistent bare metal at this privilege level.

## Runner requirements

Label the runner `[self-hosted, linux, bpf-lsm, privileged]` (add `k8s` for the
Kubernetes-membership job). The host needs:

- Linux ≥ 5.10 with **BPF LSM enabled** — `bpf` in `/sys/kernel/security/lsm`
  (boot with `lsm=...,bpf`).
- cgroup v2 and kernel BTF (`/sys/kernel/btf/vmlinux`).
- Rust stable + nightly with `rust-src`, `bpf-linker`, `protoc`, `clang`.
- A container runtime (`docker`/`nerdctl`/`podman`) for the container gate.
- A `syva` group (`sudo groupadd --system syva`).
- Passwordless `sudo` for the runner user (the gates need root to load/attach).
- For the `k8s-gate` job only: a single-node cluster (k3s) reachable by
  `kubectl`, sharing the host `/proc` and cgroup namespace.

## Kernel matrix (why one runner isn't enough)

A single forgiving kernel (e.g. current Fedora) proves "works here" but hides
version-specific breakage — the same blind spot as testing on one deployed
pod. Run at least two runners: one **current** kernel and one near the
**floor** (5.10). They exercise the BTF-offset resolution and the LSM-hook
surface across the range Syva claims to support; differences in struct layout
or hook availability surface as a self-test failure at startup, not a silent
wrong-offset in production.

## What it runs

`kernel-gates` runs the full single-host sweep: load/attach/self-test, every
deny gate (integration, container, network-lock, egress-cidr, cross-zone-tcp,
inode-identity), the **allow** contract (`verify-allow` — the must-not-block
half), plus events, audit-mode, and cgroup-escape. `k8s-gate` runs the
Kubernetes membership gate on a cluster-equipped runner.

Keep `verify-allow` green before treating the suite as an authoritative
required check in branch protection: a deny-only gate passes even if the core
denies everything, so the allow side is what makes "green" mean what we claim.
