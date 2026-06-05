#!/usr/bin/env bash
# Idempotent dependency bootstrap for the Syvä Lima development deployment.
#
# Provisions everything the privileged runtime/deployment gates need that the
# base lima/syva.yaml image does not already install: the nightly toolchain +
# rust-src, bpf-linker, a container runtime, the `syva` socket group, and the
# BPF-LSM boot parameter. Safe to run repeatedly.
#
# Run inside the VM from the repo root:  bash deploy/lima/bootstrap.sh
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"
RUNTIME="${SYVA_CONTAINER_RUNTIME:-podman}"
TEST_IMAGE="${SYVA_TEST_IMAGE:-docker.io/library/busybox}"

say() { printf '\n=== %s ===\n' "$*"; }

say "Rust toolchains (nightly + rust-src for eBPF)"
if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup not found — install the Rust toolchain first (see lima/syva.yaml)." >&2
  exit 1
fi
rustup toolchain install nightly --profile minimal >/dev/null
rustup component add rust-src --toolchain nightly >/dev/null
echo "ok: nightly + rust-src present"

say "bpf-linker (eBPF object linker)"
if ! command -v bpf-linker >/dev/null 2>&1; then
  cargo install bpf-linker >/dev/null
fi
echo "ok: $(command -v bpf-linker)"

say "Container runtime ($RUNTIME)"
if ! command -v "$RUNTIME" >/dev/null 2>&1; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$RUNTIME"
fi
echo "ok: $("$RUNTIME" --version)"
echo "pulling test image $TEST_IMAGE (best effort)"
sudo "$RUNTIME" pull -q "$TEST_IMAGE" >/dev/null 2>&1 || \
  echo "warn: could not pre-pull $TEST_IMAGE; set SYVA_TEST_IMAGE or pull manually"

say "syva socket group"
if ! getent group syva >/dev/null; then
  sudo groupadd --system syva
fi
echo "ok: group $(getent group syva)"

say "BPF LSM availability"
LSM="$(cat /sys/kernel/security/lsm 2>/dev/null || echo '<securityfs not mounted>')"
echo "current: $LSM"
if printf '%s' "$LSM" | tr ',' '\n' | grep -qx bpf; then
  echo "ok: BPF LSM is active"
else
  echo "BPF LSM is NOT active. Enabling it on the kernel command line (requires reboot)."
  if [ -f /etc/default/grub ]; then
    sudo cp -n /etc/default/grub /etc/default/grub.syva-bak || true
    sudo sed -i \
      's|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,apparmor,bpf"|' \
      /etc/default/grub
    sudo update-grub
    cat >&2 <<'EOF'

ACTION REQUIRED: BPF LSM was added to the kernel command line.
Reboot the VM, then re-run bootstrap to confirm:
    limactl stop syva-dev && limactl start syva-dev    # from the host
    # or, inside the VM:  sudo reboot
EOF
    exit 2
  fi
  echo "could not edit /etc/default/grub; enable 'bpf' in the boot lsm= list manually." >&2
  exit 2
fi

say "bootstrap complete"
echo "kernel: $(uname -r)   runtime: $RUNTIME   lsm: $LSM"
