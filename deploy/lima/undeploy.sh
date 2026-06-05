#!/usr/bin/env bash
# Stop the node-local Syvä deployment and clean up runtime state created by
# deploy.sh. Safe to run when nothing is deployed (best-effort throughout).
#
# Sends SIGTERM so syva-core unpins its BPF maps gracefully, leaving the kernel
# clean for the next deploy.
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

say "Remove runtime state"
sudo rm -f "$SYVA_SOCK" "$SYVA_PID"
sudo rmdir "$SYVA_RUN" 2>/dev/null || true
# Remove any stale BPF map pins only if the core is gone (graceful exit usually
# already did this; this is the SIGKILL fallback).
if ! pgrep -x syva-core >/dev/null 2>&1; then
  sudo rm -rf /sys/fs/bpf/syva 2>/dev/null || true
fi
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
