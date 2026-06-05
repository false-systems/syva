# Testing on macOS with Lima

Syva is Linux/eBPF software. macOS can run host-safe Rust checks directly, but
full workspace checks require Linux because `aya` uses Linux BPF and netlink
interfaces.

The supported macOS bridge is Lima.

## Start the VM

```sh
limactl start --name=syva-dev ./lima/syva.yaml
```

Or use the repo target:

```sh
make lima-up
```

The Lima config mounts your macOS home directory writable into the guest, so the
repo path remains the same inside Linux.

## Enter the VM

```sh
limactl shell syva-dev
cd /Users/yair/projects/syva
cargo test --workspace
```

Or:

```sh
make lima-shell
```

## Run Linux verification from macOS

```sh
make lima-check
```

`lima-check` runs:

```sh
cargo run -p xtask -- ci
```

`xtask ci` runs format check, clippy, full workspace check, full workspace
tests, eval crate builds, and eBPF object compilation. No Postgres service is
required.

## Local Guardrails

Use the Makefile hierarchy for ordinary development:

```sh
make fmt
make lint
make test
make precommit
make ci
```

`make precommit` and `make ci` are non-privileged. They include release-doc
drift checks and the release eBPF object build, but they do not load or attach
BPF LSM programs.

Optional pre-commit hook setup:

```sh
pipx install pre-commit
pre-commit install
pre-commit run --all-files
```

## Direct macOS checks

These checks avoid Linux-only `aya` userspace paths:

```sh
make macos-check
```

This target is useful for fast edit cycles, but it is not a replacement for
Linux verification.

## What Lima Verifies

**Linux compile verification:** `cargo check --workspace` verifies the Linux
userspace workspace inside Ubuntu.

**Workspace tests:** `cargo test --workspace` runs Linux userspace tests. Tests
that require real BPF load/attach still need privileges and kernel support.

**Eval compile verification:** `cargo run -p xtask -- eval-build` builds
`eval/oracle` and `eval/harness` so release contract tests do not bitrot.

**eBPF object build verification:** `cargo run -p xtask -- build-ebpf` builds
the release `syva-ebpf` object with nightly Rust, `rust-src`, and
`bpf-linker`. The release object is the runtime artifact; debug eBPF builds are
development-only.
The VM installs Ubuntu `linux-tools-*`; on some architectures `bpftool` is
provided through those packages rather than a package literally named
`bpftool`.

**eBPF load/attach verification:** not guaranteed by Lima. Loading BPF LSM
programs requires a Linux kernel with the right config and boot parameters,
plus privileges. Treat runtime attach/enforcement checks as native Linux CI or
privileged Linux-host work unless this VM has been explicitly validated for
that path.

**Blackbox enforcement verification:** the eval/oracle suite talks to a live
`syva-core`. It only verifies real enforcement if the VM can load and attach
BPF LSM programs successfully.

**Container integration test:** `sudo -E make verify-container-integration`
needs a container runtime in the VM (`docker`, `nerdctl`, or `podman`; install
e.g. `sudo apt-get install -y podman`). It proves `file_open` enforcement against
a real container. See `docs/release/v0.2-runtime-verification.md`.
