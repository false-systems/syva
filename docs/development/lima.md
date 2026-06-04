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

`xtask ci` runs format check, full workspace check, full workspace tests, and
eBPF object compilation. No Postgres service is required.

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

**eBPF object build verification:** `cargo run -p xtask -- build-ebpf` builds
the `syva-ebpf` object with nightly Rust, `rust-src`, and `bpf-linker`.
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
