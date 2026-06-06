# Syva Monitoring

Syva monitoring is about enforcement confidence, not generic service uptime.
An operator should be able to tell whether `syva-core` is alive, whether the
release eBPF object loaded, whether all supported BPF-LSM hooks attached,
whether mandatory self-tests passed, and whether enforcement has degraded.

## Health

`syva-core` serves health and metrics on the configured health port, default
`9091`.

```sh
curl -s http://127.0.0.1:9091/healthz
```

By default the health server binds `0.0.0.0`. In production deployments, expose
it only to trusted node-local or cluster monitoring paths, for example with a
localhost bind where appropriate or Kubernetes NetworkPolicy around the Syva
DaemonSet.

The health response is JSON:

```json
{
  "state": "healthy",
  "status": "healthy",
  "ebpf_loaded": true,
  "expected_hooks": 6,
  "attached_hooks": 6,
  "attached": true,
  "selftests": {
    "cgroup": "passed",
    "inode": "passed",
    "unix": "passed"
  },
  "zones_loaded": 2,
  "containers_active": 1,
  "uptime_secs": 30,
  "degraded_reasons": [],
  "last_counter_read_ok": true,
  "last_counter_read_success_timestamp_seconds": 1780000000
}
```

States:

- `healthy`: eBPF loaded, all six supported hooks attached, mandatory
  self-tests passed, BPF counter reads are succeeding, and no active degraded
  reasons are known.
- `degraded`: `syva-core` is running but enforcement confidence is reduced.
  Examples include BPF map read/update/delete errors, hook error/lost deltas,
  stale/conflicting membership updates, or failed counter reads.
- `unsafe`: Syva cannot claim enforcement is active. Examples include eBPF
  load failure, fewer than six attached hooks, or failed/pending mandatory
  self-tests.

Fail-open hook errors are not healthy. They keep the node safer operationally,
but they reduce enforcement confidence and should page or warn depending on
policy.

## Metrics

```sh
curl -s http://127.0.0.1:9091/metrics
```

Core metrics:

```text
syva_core_up
syva_core_start_time_seconds
syva_core_build_info{version,git_sha}
syva_ebpf_object_loaded
syva_ebpf_expected_hooks
syva_ebpf_attached_hooks
syva_ebpf_hook_attached{hook}
syva_selftest_passed{test}
syva_health_state{state}
syva_health_degraded_reasons{reason}
syva_health_last_counter_read_success_timestamp_seconds
syva_hook_decisions_total{hook,decision}
syva_bpf_map_errors_total{operation,map}
syva_bpf_counter_read_errors_total
syva_memberships_active
syva_membership_updates_total{result}
syva_membership_generation_stale_total
syva_membership_conflicts_total
```

Supported hook labels:

```text
file_open
bprm_check_security
ptrace_access_check
task_kill
mmap_file
unix_stream_connect
```

Allow counters are global and noisy. Deny counters are stronger evidence that
enforcement is active. Error counters are security-critical because they mean a
hook observed a failure path that may allow an operation to continue.

## Prometheus

Example scrape config:

```yaml
scrape_configs:
  - job_name: syva-core
    static_configs:
      - targets:
          - localhost:9091
```

Alert rules are provided at
`deploy/monitoring/prometheus/syva-alerts.yaml`. Denials are informational by
default because a denial often means enforcement is working.

## Grafana

A starter dashboard is provided at
`deploy/monitoring/grafana/syva-node-enforcement.json`.

## Structured Logs

Set JSON logging with:

```sh
SYVA_LOG_FORMAT=json syva-core
```

Startup and eBPF lifecycle events include:

```json
{"event":"syva.startup.begin","component":"syva-core"}
{"event":"syva.ebpf.object_selected","component":"syva-core","object_path":"syva-ebpf/target/bpfel-unknown-none/release/syva-ebpf","result":"ok"}
{"event":"syva.ebpf.attached","component":"syva-core","program":"syva_file_open","hook":"file_open","result":"ok"}
{"event":"syva.selftest.passed","component":"syva-core","test":"unix","result":"ok"}
{"event":"syva.startup.ready","component":"syva-core","expected_hooks":6,"attached_hooks":6}
```

Membership events include:

```json
{"event":"syva.membership.attach","component":"syva-core","container_id":"abc123","cgroup_id":123,"zone":"zone-a","generation":42,"result":"applied"}
{"event":"syva.membership.stale","component":"syva-core","container_id":"abc123","generation":41,"result":"stale"}
{"event":"syva.membership.conflict","component":"syva-core","container_id":"abc123","zone":"zone-b","existing_zone":"zone-a","result":"conflict"}
```

Health transition logs use events such as `syva.health.degraded` and include a
machine-readable reason.

Rich per-denial events are available through the existing ring-buffer event
stream (`syva-core events --follow --format json` or the `WatchEvents` RPC).
The core process does not consume that ring buffer by default because it is a
single-consumer stream. `/metrics` exposes denial counters without sensitive
file paths.

## Caveats

- File paths can be sensitive and are not logged by default.
- `EPERM` / `Operation not permitted` is expected for blocked operations.
- v0.2 proves `file_open` end to end with process and container workloads. The
  other supported hooks load, attach, and self-test, but are not all
  workload-proven yet.
- Cgroup movement / zone escape protection is out of scope for v0.2 because the
  removed cgroup-movement path is not a supported BPF-LSM hook on mainline
  kernels.
- Kubernetes adapter metrics are not yet exposed separately. Adapter health
  should be added when the Kubernetes end-to-end proof is implemented.
