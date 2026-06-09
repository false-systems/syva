#!/usr/bin/env bash
set -euo pipefail

PID="$$"
NS="syva-k8s-it-${PID}"
POD="syva-k8s-it-pod-${PID}"
ZONE_A="syva-it-zone-a"
ZONE_B="syva-it-zone-b"
WORKDIR="/tmp/syva-k8s-it-${PID}"
SOCKET="${WORKDIR}/syva-core.sock"
CORE_LOG="${WORKDIR}/syva-core.log"
K8S_LOG="${WORKDIR}/syva-k8s.log"
CORE_HEALTH_PORT="${SYVA_K8S_IT_CORE_HEALTH_PORT:-19091}"
K8S_METRICS_PORT="${SYVA_K8S_IT_METRICS_PORT:-19092}"
IMAGE="${SYVA_K8S_TEST_IMAGE:-docker.io/library/busybox:latest}"
NODE_NAME="${SYVA_K8S_TEST_NODE:-}"
RUNTIME_NAME="kubectl"
CORE_PID=""
K8S_PID=""

die() {
  echo "verify-k8s-membership: $*" >&2
  exit 1
}

have() {
  command -v "$1" >/dev/null 2>&1
}

cleanup() {
  set +e
  if [ -n "${POD:-}" ] && [ -n "${NS:-}" ] && have kubectl; then
    kubectl -n "$NS" delete pod "$POD" --ignore-not-found=true --wait=false >/dev/null 2>&1
    kubectl delete namespace "$NS" --ignore-not-found=true --wait=false >/dev/null 2>&1
  fi
  if [ -n "${K8S_PID:-}" ]; then
    kill "$K8S_PID" >/dev/null 2>&1
    wait "$K8S_PID" >/dev/null 2>&1
  fi
  if [ -n "${CORE_PID:-}" ]; then
    kill "$CORE_PID" >/dev/null 2>&1
    wait "$CORE_PID" >/dev/null 2>&1
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

require_root_linux_bpf() {
  [ "$(uname -s)" = "Linux" ] || die "requires Linux"
  [ "$(id -u)" = "0" ] || die "requires root; run sudo -E make verify-k8s-membership"
  [ -r /sys/kernel/security/lsm ] || die "cannot read /sys/kernel/security/lsm; is securityfs mounted?"
  grep -qw bpf /sys/kernel/security/lsm || die "BPF LSM not active: $(cat /sys/kernel/security/lsm)"
  getent group syva >/dev/null || die "missing syva group for syva-core socket"
}

json_status_field() {
  local field="$1"
  target/debug/syvactl --socket "$SOCKET" --format json status |
    python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["status"][sys.argv[1]])' "$field"
}

file_open_deny() {
  target/debug/syvactl --socket "$SOCKET" --format json status |
    python3 -c 'import json,sys; data=json.load(sys.stdin); hooks=data["status"].get("hooks", []); print(next((h.get("deny", 0) for h in hooks if h.get("hook") == "file_open"), 0))'
}

zones_ready() {
  target/debug/syvactl --socket "$SOCKET" --format json zones list |
    python3 -c 'import json,sys; data=json.load(sys.stdin); names={z.get("name") for z in data.get("zones", [])}; sys.exit(0 if {sys.argv[1], sys.argv[2]}.issubset(names) else 1)' "$ZONE_A" "$ZONE_B"
}

wait_for_file() {
  local path="$1"
  local seconds="$2"
  local deadline=$((SECONDS + seconds))
  while [ "$SECONDS" -lt "$deadline" ]; do
    [ -e "$path" ] && return 0
    sleep 0.2
  done
  die "timed out waiting for file $path"
}

wait_for_cmd() {
  local seconds="$1"
  shift
  local deadline=$((SECONDS + seconds))
  local last=""
  while [ "$SECONDS" -lt "$deadline" ]; do
    if last="$("$@" 2>&1)"; then
      return 0
    fi
    sleep 0.5
  done
  echo "$last" >&2
  die "timed out waiting for command: $*"
}

wait_for_metric() {
  local pattern="$1"
  local seconds="$2"
  local deadline=$((SECONDS + seconds))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if curl -fsS "http://127.0.0.1:${K8S_METRICS_PORT}/metrics" 2>/dev/null | grep -Fq "$pattern"; then
      return 0
    fi
    sleep 0.5
  done
  echo "last metrics scrape:" >&2
  curl -fsS "http://127.0.0.1:${K8S_METRICS_PORT}/metrics" >&2 || true
  die "timed out waiting for metric pattern: $pattern"
}

wait_for_attach_log() {
  local cid="$1"
  local cgroup_id="$2"
  local seconds="$3"
  local deadline=$((SECONDS + seconds))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if [ -r "$K8S_LOG" ] &&
       grep -F "syva.k8s.membership.attach" "$K8S_LOG" |
         grep -F "$cid" |
         grep -F "cgroup_id=${cgroup_id}" |
         grep -Fq "result=\"applied\""; then
      return 0
    fi
    sleep 0.5
  done
  echo "last syva-k8s log:" >&2
  tail -n 80 "$K8S_LOG" >&2 || true
  die "timed out waiting for syva-k8s AttachContainer log for $cid cgroup_id=$cgroup_id"
}

normalize_container_id() {
  local raw="$1"
  raw="${raw#*://}"
  [ -n "$raw" ] || die "container ID is empty"
  printf '%s' "$raw"
}

resolve_host_cgroup() {
  local cid="$1"
  local short="${cid:0:12}"
  local pid_path
  for pid_path in /proc/[0-9]*; do
    [ -r "${pid_path}/cgroup" ] || continue
    if grep -q "$cid\\|$short" "${pid_path}/cgroup" 2>/dev/null ||
       grep -q "$cid\\|$short" "${pid_path}/mountinfo" 2>/dev/null; then
      local pid="${pid_path##*/}"
      local rel
      rel="$(awk -F: '$1 == "0" && $2 == "" {print $3; exit}' "${pid_path}/cgroup")"
      [ -n "$rel" ] || die "found pid $pid for container $cid but no cgroup-v2 path"
      local path="/sys/fs/cgroup${rel}"
      [ -e "$path" ] || die "resolved cgroup path does not exist: $path"
      local ino
      ino="$(stat -c '%i' "$path")"
      printf '%s\t%s\t%s\n' "$pid" "$rel" "$ino"
      return 0
    fi
  done
  die "could not resolve host pid/cgroup for container $cid"
}

wait_pod_running() {
  local deadline=$((SECONDS + 120))
  while [ "$SECONDS" -lt "$deadline" ]; do
    local phase
    phase="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [ "$phase" = "Running" ] && return 0
    sleep 1
  done
  kubectl -n "$NS" describe pod "$POD" >&2 || true
  die "pod $NS/$POD did not become Running"
}

apply_crd() {
  if kubectl get crd syvazonepolicies.syva.dev >/dev/null 2>&1; then
    return 0
  fi
  kubectl apply -f - <<'YAML'
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: syvazonepolicies.syva.dev
spec:
  group: syva.dev
  scope: Namespaced
  names:
    plural: syvazonepolicies
    singular: syvazonepolicy
    kind: SyvaZonePolicy
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              x-kubernetes-preserve-unknown-fields: true
            status:
              type: object
              x-kubernetes-preserve-unknown-fields: true
      subresources:
        status: {}
YAML
}

apply_pod() {
  kubectl -n "$NS" apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
  annotations:
    syva.false.systems/zone: ${ZONE_A}
spec:
  restartPolicy: Never
  nodeName: ${NODE_NAME}
  containers:
    - name: app
      image: ${IMAGE}
      command:
        - sh
        - -c
        - |
          touch /work/ctl/up
          while [ ! -e /work/ctl/go ]; do sleep 0.1; done
          cat /work/zone-a/allowed.txt > /work/ctl/allowed.out 2> /work/ctl/allowed.err
          echo \$? > /work/ctl/allowed.code
          touch /work/ctl/allowed.done
          while [ ! -e /work/ctl/go2 ]; do sleep 0.1; done
          cat /work/zone-b/secret.txt > /work/ctl/secret.out 2> /work/ctl/secret.err
          echo \$? > /work/ctl/secret.code
          touch /work/ctl/secret.done
          sleep 60
      volumeMounts:
        - name: work
          mountPath: /work
  volumes:
    - name: work
      hostPath:
        path: ${WORKDIR}
        type: Directory
YAML
}

apply_zone_policies() {
  kubectl -n "$NS" apply -f - <<YAML
apiVersion: syva.dev/v1alpha1
kind: SyvaZonePolicy
metadata:
  name: ${ZONE_A}
spec:
  filesystem:
    hostPaths:
      - ${WORKDIR}/zone-a/allowed.txt
---
apiVersion: syva.dev/v1alpha1
kind: SyvaZonePolicy
metadata:
  name: ${ZONE_B}
spec:
  filesystem:
    hostPaths:
      - ${WORKDIR}/zone-b/secret.txt
YAML
}

echo "=== syva k8s membership integration contract ==="
echo "PASS: annotated pod in zone-a can read its own zone-a file."
echo "BLOCK: annotated pod in zone-a cannot read protected zone-b file."
echo "ASSIGNMENT: syva.false.systems/zone=zone-a"
echo "HOOK: file_open"
echo "EXPECTED DENIAL: EPERM / Operation not permitted"
echo "EXPECTED KERNEL EVIDENCE: file_open deny_delta=1"

require_root_linux_bpf
for bin in cargo kubectl python3 curl stat awk grep; do
  have "$bin" || die "missing required command: $bin"
done
kubectl version --client >/dev/null || die "kubectl is not functional"
kubectl cluster-info >/dev/null || die "kubectl cannot reach a Kubernetes cluster"

if [ -z "$NODE_NAME" ]; then
  NODE_NAME="$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')"
fi
[ -n "$NODE_NAME" ] || die "could not determine Kubernetes node name"
RUNTIME_NAME="$(kubectl get node "$NODE_NAME" -o jsonpath='{.status.nodeInfo.containerRuntimeVersion}' 2>/dev/null || echo kubernetes)"

mkdir -p "$WORKDIR/zone-a" "$WORKDIR/zone-b" "$WORKDIR/ctl"
echo "ZONE_A_PUBLIC_OK" > "$WORKDIR/zone-a/allowed.txt"
echo "ZONE_B_SECRET_DENYME" > "$WORKDIR/zone-b/secret.txt"
chmod -R a+rX "$WORKDIR"

cargo build -p syva-core -p syva-adapter-k8s -p syvactl

target/debug/syva-core --socket-path "$SOCKET" --health-port "$CORE_HEALTH_PORT" >"$CORE_LOG" 2>&1 &
CORE_PID="$!"
wait_for_cmd 30 target/debug/syvactl --socket "$SOCKET" status

apply_crd
kubectl create namespace "$NS" >/dev/null
apply_zone_policies

RUST_LOG=syva_k8s=info target/debug/syva-k8s \
  --namespace "$NS" \
  --core-socket "$SOCKET" \
  --node-name "$NODE_NAME" \
  --host-proc /proc \
  --host-cgroup /sys/fs/cgroup \
  --metrics-listen "127.0.0.1:${K8S_METRICS_PORT}" >"$K8S_LOG" 2>&1 &
K8S_PID="$!"
wait_for_cmd 30 curl -fsS "http://127.0.0.1:${K8S_METRICS_PORT}/metrics"
wait_for_cmd 30 zones_ready

apply_pod
wait_pod_running
wait_for_file "$WORKDIR/ctl/up" 60

RAW_CONTAINER_ID="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].containerID}')"
CONTAINER_ID="$(normalize_container_id "$RAW_CONTAINER_ID")"
IFS=$'\t' read -r HOST_PID CGROUP_PATH CGROUP_ID < <(resolve_host_cgroup "$CONTAINER_ID")

echo "--- k8s setup ---"
echo "environment: ${RUNTIME_NAME}"
echo "namespace: ${NS}"
echo "node: ${NODE_NAME}"
echo "pod: ${POD}"
echo "container_id: ${CONTAINER_ID}"
echo "host_pid: ${HOST_PID}"
echo "cgroup: host_path=${CGROUP_PATH} cgroup_id=${CGROUP_ID}"

wait_for_metric 'syva_k8s_membership_attach_total{result="applied"}' 60
wait_for_metric 'syva_k8s_memberships_active 1' 60
wait_for_attach_log "$CONTAINER_ID" "$CGROUP_ID" 30
ACTIVE="$(json_status_field containers_active)"
[ "$ACTIVE" = "1" ] || die "expected syva-core containers_active=1, got $ACTIVE"
echo "AttachContainer result: applied (containers_active=${ACTIVE})"

touch "$WORKDIR/ctl/go"
wait_for_file "$WORKDIR/ctl/allowed.done" 30
ALLOWED_CODE="$(tr -d '\n' < "$WORKDIR/ctl/allowed.code")"
ALLOWED_OUT="$(cat "$WORKDIR/ctl/allowed.out" 2>/dev/null || true)"
[ "$ALLOWED_CODE" = "0" ] || die "allowed read failed with exit ${ALLOWED_CODE}: $(cat "$WORKDIR/ctl/allowed.err" 2>/dev/null || true)"
echo "$ALLOWED_OUT" | grep -q "ZONE_A_PUBLIC_OK" || die "allowed read did not return expected content"

DENY_BEFORE="$(file_open_deny)"
touch "$WORKDIR/ctl/go2"
wait_for_file "$WORKDIR/ctl/secret.done" 30
DENY_AFTER="$(file_open_deny)"
DENY_DELTA="$((DENY_AFTER - DENY_BEFORE))"
SECRET_CODE="$(tr -d '\n' < "$WORKDIR/ctl/secret.code")"
SECRET_OUT="$(cat "$WORKDIR/ctl/secret.out" 2>/dev/null || true)"
SECRET_ERR="$(cat "$WORKDIR/ctl/secret.err" 2>/dev/null || true)"

[ "$SECRET_CODE" != "0" ] || die "blocked read exited 0; output=${SECRET_OUT}"
! echo "$SECRET_OUT" | grep -q "ZONE_B_SECRET_DENYME" || die "blocked read leaked secret content"
echo "$SECRET_ERR" | grep -q "Operation not permitted" || die "expected EPERM, got stderr=${SECRET_ERR}"
[ "$DENY_DELTA" = "1" ] || die "expected file_open deny_delta=1, before=${DENY_BEFORE}, after=${DENY_AFTER}, delta=${DENY_DELTA}"

echo "--- allowed operation (zone-a -> zone-a file) ---"
echo "cmd: cat /work/zone-a/allowed.txt"
echo "exit=${ALLOWED_CODE} -> ALLOWED, content present"
echo "--- blocked operation (zone-a -> zone-b file) ---"
echo "cmd: cat /work/zone-b/secret.txt"
echo "exit=${SECRET_CODE} stderr=${SECRET_ERR@Q}"
echo "  -> kernel DENIED the open with EPERM (Operation not permitted); no secret read"
echo "file_open deny: before=${DENY_BEFORE} after=${DENY_AFTER} deny_delta=${DENY_DELTA} (k8s-pod workload attributable)"

kubectl -n "$NS" delete pod "$POD" --wait=true --timeout=60s >/dev/null
wait_for_metric 'syva_k8s_membership_detach_total{result="applied"}' 60
wait_for_metric 'syva_k8s_memberships_active 0' 60
echo "DetachContainer result: applied"
echo "PASS: syva k8s membership integration proof completed"
