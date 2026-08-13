#!/usr/bin/env bash
# Stop the node-local Syvä deployment and clean up runtime state created by
# deploy.sh. Safe to run when nothing is deployed (best-effort throughout).
#
# Explicitly disables enforcement before stopping the core. Ordinary SIGTERM
# preserves the active generation for crash-safe restart and upgrade.
#
# Run inside the VM from the repo root:  bash deploy/lima/undeploy.sh
set -uo pipefail

SYVA_RUN=/run/syva
SYVA_SOCK="$SYVA_RUN/syva-core.sock"
SYVA_PID="$SYVA_RUN/syva-core.pid"
SYVA_DEPLOY=/tmp/syva-deploy
RUNTIME="${SYVA_CONTAINER_RUNTIME:-podman}"

say() { printf '\n=== %s ===\n' "$*"; }

say "Stop syva-core"
if [ -S "$SYVA_SOCK" ] && command -v syvactl >/dev/null 2>&1; then
  sudo syvactl --socket "$SYVA_SOCK" enforcement disable || true
fi
if [ -f "$SYVA_PID" ]; then
  PID="$(sudo cat "$SYVA_PID" 2>/dev/null || true)"
  if [ -n "${PID:-}" ] && sudo kill -0 "$PID" 2>/dev/null; then
    sudo kill -TERM "$PID" 2>/dev/null || true
    for _ in $(seq 1 20); do sudo kill -0 "$PID" 2>/dev/null || break; sleep 0.5; done
    sudo kill -KILL "$PID" 2>/dev/null || true
    echo "stopped pid $PID"
  else
    echo "no running core for pid file"
  fi
else
  echo "no pid file; nothing to stop"
fi
if command -v syva-core >/dev/null 2>&1; then
  sudo syva-core cleanup || true
fi

say "Remove runtime state"
sudo rm -f "$SYVA_SOCK" "$SYVA_PID"
sudo rmdir "$SYVA_RUN" 2>/dev/null || true
rm -rf "$SYVA_DEPLOY"
echo "removed socket, pid file, runtime dir, deploy dir"

say "Remove test containers and files"
if command -v "$RUNTIME" >/dev/null 2>&1; then
  ids="$(sudo "$RUNTIME" ps -aq --filter name=syva-it-container 2>/dev/null || true)"
  [ -n "$ids" ] && sudo "$RUNTIME" rm -f $ids >/dev/null 2>&1 || true
fi
rm -rf /tmp/syva-container-it-* /tmp/syva-integration-* 2>/dev/null || true
echo "removed test containers and temp dirs"

say "Undeploy complete"
