#!/usr/bin/env bash
# Deploy Syvä as a node-local agent inside the Lima development VM.
#
# This is a single-node DEVELOPMENT deployment (managed background process),
# not a production install. It builds the release binary and eBPF object,
# installs them, starts syva-core under sudo, and proves it is healthy with all
# six BPF-LSM hooks attached.
#
# Run inside the VM from the repo root:  bash deploy/lima/deploy.sh
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

SYVA_BIN=/usr/local/bin/syva-core
SYVA_EBPF=/usr/lib/syva/syva-ebpf
SYVA_RUN=/run/syva
SYVA_SOCK="$SYVA_RUN/syva-core.sock"
SYVA_PID="$SYVA_RUN/syva-core.pid"
SYVA_DEPLOY=/tmp/syva-deploy
SYVA_LOG="$SYVA_DEPLOY/logs/syva-core.log"
HEALTH_PORT=9091

say() { printf '\n=== %s ===\n' "$*"; }

# Refuse a double-deploy: undeploy first for a clean rerun.
if [ -f "$SYVA_PID" ] && sudo kill -0 "$(sudo cat "$SYVA_PID")" 2>/dev/null; then
  echo "syva-core already running (pid $(sudo cat "$SYVA_PID")). Run 'make lima-undeploy' first." >&2
  exit 1
fi

say "Preflight"
[ "$(id -u)" = 0 ] && { echo "run as the normal user; the script uses sudo where needed" >&2; exit 1; }
getent group syva >/dev/null || { echo "missing 'syva' group — run 'make lima-bootstrap'" >&2; exit 1; }
LSM="$(cat /sys/kernel/security/lsm 2>/dev/null || true)"
printf '%s' "$LSM" | tr ',' '\n' | grep -qx bpf || {
  echo "BPF LSM not active (lsm=$LSM) — run 'make lima-bootstrap' and reboot" >&2; exit 1; }
echo "kernel: $(uname -r)   lsm: $LSM"

say "Build release artifacts"
cargo build --release -p syva-core
cargo run -p xtask -- build-ebpf
REL_EBPF="$(pwd)/syva-ebpf/target/bpfel-unknown-none/release/syva-ebpf"
[ -f "$REL_EBPF" ] || { echo "release eBPF object not found at $REL_EBPF" >&2; exit 1; }

say "Install"
sudo install -m 0755 target/release/syva-core "$SYVA_BIN"
sudo install -D -m 0644 "$REL_EBPF" "$SYVA_EBPF"
sudo mkdir -p "$SYVA_RUN"
mkdir -p "$SYVA_DEPLOY/logs" "$SYVA_DEPLOY/policies" "$SYVA_DEPLOY/integration"
echo "binary:      $SYVA_BIN"
echo "eBPF object: $SYVA_EBPF"

say "Start syva-core"
sudo bash -c "nohup '$SYVA_BIN' --socket-path '$SYVA_SOCK' --health-port $HEALTH_PORT \
  >'$SYVA_LOG' 2>&1 & echo \$! >'$SYVA_PID'"
sleep 1

# Wait for health: /healthz returns 200 once attached (degraded/healthy), 503 unsafe.
ready=0
for _ in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HEALTH_PORT/healthz" 2>/dev/null || echo 000)"
  if [ "$code" = 200 ] && [ -S "$SYVA_SOCK" ]; then ready=1; break; fi
  sleep 0.5
done
if [ "$ready" != 1 ]; then
  echo "syva-core did not become healthy; last 40 log lines:" >&2
  sudo tail -n 40 "$SYVA_LOG" >&2 || true
  exit 1
fi

say "Syvä deployed"
PID="$(sudo cat "$SYVA_PID")"
HEALTH="$(curl -s "http://127.0.0.1:$HEALTH_PORT/healthz" || true)"
ATTACHED="$(sudo grep -c 'attached LSM program' "$SYVA_LOG" || echo 0)"
echo "core pid:            $PID"
echo "socket:              $SYVA_SOCK"
echo "health port:         $HEALTH_PORT"
echo "log:                 $SYVA_LOG"
echo "release eBPF object: $SYVA_EBPF"
echo "attached hooks:      $ATTACHED"
echo "health:              $HEALTH"
echo "self-tests:"
sudo grep -E 'self-test passed|enforcement active' "$SYVA_LOG" | sed 's/^/  /' || true
echo
echo "verify with:  sudo -E make verify-deployment   (or: make lima-verify-deployment)"
