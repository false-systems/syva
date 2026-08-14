# Syvä Observer: Teko obligations

These obligations are the implementation contract for Observer. They are deliberately
small, independently testable, and ordered by dependency. Observer is not part of the
Syvä syscall decision path.

## Architecture and safety

| ID | Obligation | Acceptance criteria | Depends on |
|---|---|---|---|
| OBS-ARCH-001 | Run Observer as an independently failing, node-local process. | Killing Observer leaves the core daemon and an already-active policy enforcing; a restart can rebuild a read-only view. | — |
| OBS-ARCH-002 | Give Observer read-only authority. | Observer can query approved IPC and inspect required kernel/runtime metadata, but has no policy-write, BPF-load, or BPF-map-write capability. | OBS-ARCH-001 |
| OBS-ARCH-003 | Keep integrations optional. | Syvä starts and reports useful local state without Kubernetes or Vartio; provider/exporter failure is visible as stale/unknown, never as healthy. | OBS-ARCH-001 |

## Evidence, events, and state

| ID | Obligation | Acceptance criteria | Depends on |
|---|---|---|---|
| OBS-EVENT-001 | Define a versioned, bounded observation event schema. | Every event has schema version, stable event ID, subject identity, time, event kind, claim kind (`policy`, `kernel`, `observation`, or `inference`), confidence, and evidence references. | OBS-ARCH-001 |
| OBS-EVENT-002 | Preserve evidence provenance and uncertainty. | Monotonic kernel time and wall-clock observation time are not conflated; stale, unsupported, and dropped observations are explicit; missing evidence cannot become a positive claim. | OBS-EVENT-001 |
| OBS-EVENT-003 | Bound event delivery and retention. | Queue, memory, and recent-event ring have fixed limits; overflow emits a gap marker and never blocks enforcement. | OBS-EVENT-001 |
| OBS-STATE-001 | Materialize reconstructible current state. | After Observer restart, state is rebuilt from a fresh core snapshot plus current proc/cgroup/provider observations; state carries freshness and source. | OBS-EVENT-002 |
| OBS-STATE-002 | Use Syvä identity primitives without stale reuse. | Cgroup identity is the kernel anchor; PID is observational only; container/runtime ID and optional pod UID enrich identity; cgroup reuse or pod recreation invalidates old membership/posture. | OBS-STATE-001 |

## Enforcement and posture

| ID | Obligation | Acceptance criteria | Depends on |
|---|---|---|---|
| OBS-ENF-001 | Introspect enforcement truthfully. | Report BPF-LSM availability, expected/observed hook coverage, self-test/health state, active policy generation, and synchronization state; missing core evidence is `UNKNOWN` or `DEGRADED`. | OBS-STATE-001 |
| OBS-ENF-002 | Separate policy, kernel fact, and operation event. | A configured deny, an attached/enforcing hook, and an observed `EPERM`/deny are represented as distinct claims and are never collapsed. | OBS-ENF-001 |
| OBS-POSTURE-001 | Evaluate semantic posture, not a score. | Only `PROTECTED`, `DEGRADED`, `EXPOSED`, or `UNKNOWN` are emitted; `PROTECTED` requires active coverage, synchronized generation, fresh identity, satisfied mandatory profile requirements, and no known unsafe condition. | OBS-ENF-002 |
| OBS-POSTURE-002 | Make agent-profile capability boundaries explicit. | Each requirement is classified as Syvä-enforceable, observable-only, or unsupported; posture explains the classification and never implies enforcement for observation-only facts. | OBS-POSTURE-001 |
| OBS-POSTURE-003 | Assess metadata endpoints conservatively. | AWS, GCP, and Azure IPv4/IPv6/protocol requirements are represented; result distinguishes blocked, policy-allowed, observed reachable/unreachable, and unknown; no active probe runs in the kernel hook. | OBS-POSTURE-002 |
| OBS-POSTURE-004 | Detect runtime sockets and credential authority without secret scanning. | Detection considers mount/source, inode/socket identity, and runtime context rather than fixed paths alone; reports authority exposure, not file contents. | OBS-POSTURE-002 |

## Interfaces and integrations

| ID | Obligation | Acceptance criteria | Depends on |
|---|---|---|---|
| OBS-API-001 | Provide a small versioned local read API and focused CLI. | Read-only status, workload listing/status, posture, event watch, and explanation are available over the existing Unix IPC pattern; `syvactl` preserves existing commands and adds only justified Observer queries. | OBS-STATE-001 |
| OBS-K8S-001 | Treat Kubernetes as enrichment, not kernel identity. | API loss, malformed metadata, and lifecycle races produce stale/unknown state with retry/backoff; core cgroup truth remains usable standalone. | OBS-STATE-002 |
| OBS-VARTIO-001 | Export optional asynchronous evidence. | Versioned evidence includes identity, event ID/time, policy generation, provenance, confidence, and gap semantics; bounded retry/backpressure never delays enforcement and disconnect is visible locally. | OBS-EVENT-001, OBS-API-001 |

## Performance, security, and tests

| ID | Obligation | Acceptance criteria | Depends on |
|---|---|---|---|
| OBS-PERF-001 | Keep Observer bounded and off the hot path. | No synchronous network/provider call occurs in BPF or core enforcement; per-event work, queues, retention, and persistence (if added) have explicit limits measured in tests/benchmarks. | OBS-EVENT-003 |
| OBS-SEC-001 | Contain Observer compromise. | A compromised Observer cannot activate/deactivate generations, mutate policy/membership, load BPF, or write Syvä maps under the documented privilege model. | OBS-ARCH-002 |
| OBS-TEST-001 | Unit-test pure semantics. | Tests cover event normalization, identity lifecycle/reuse, state transitions, posture evaluation, stale/gap handling, metadata classification, and Vartio serialization. | OBS-POSTURE-004, OBS-VARTIO-001 |
| OBS-TEST-002 | Integration-test lifecycle and failure behavior. | Tests cover Observer↔core IPC, Observer/core restart, policy mismatch, dropped events, Kubernetes loss/recreation, exporter loss, bounded queue overflow, malformed persisted state, unsupported kernels, and detached hooks. | OBS-API-001, OBS-K8S-001, OBS-VARTIO-001 |
| OBS-TEST-003 | Verify claims against a real kernel where supported. | Privileged tests separately demonstrate configured policy, attached enforcement, and actual denial for cross-zone ptrace/signals, metadata, and runtime-socket cases; unsupported environments report skips, not passes. | OBS-ENF-002, OBS-POSTURE-003 |

## Implementation order

Implement in dependency order: architecture/IPC preconditions; bounded state and
enforcement introspection; event stream; optional Kubernetes enrichment; posture and
agent semantics; CLI; optional Vartio export; then hardening and privileged tests.
No stage may make Observer availability a prerequisite for enforcement.
