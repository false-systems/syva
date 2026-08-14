# Syva Observer: staged implementation plan

Each stage must leave Syva enforcement behavior unchanged and end with a
reproducible check. Stages are deliberately small; no stage creates a remote
hot-path dependency.

## Stage 0 — API preconditions

Define the read-only core snapshot seam and socket credential model. Add no
Observer process yet. Specify snapshot contents: status, hooks, generations,
zones, memberships, policy/source revisions, and freshness. Prove that a
read-only client cannot invoke write RPCs.

Checks: protobuf compatibility, Unix peer-credential test, snapshot consistency
under membership churn, stale-generation tests.

## Stage 1 — Observer skeleton

Add a dedicated node-local daemon/library with bounded configuration and a
read-only core client. It should start without Kubernetes or Vartio, expose a
local health/status query, and shut down independently.

Checks: startup with core absent, core restart, Observer kill/restart, no BPF
map access, bounded queue/memory tests.

## Stage 2 — Enforcement introspection

Materialize core status, hook attachment/self-test state, active/staging
generation, mode, counters, map errors, and freshness. Implement semantic
`PROTECTED`, `DEGRADED`, `EXPOSED`, and `UNKNOWN` evaluation with evidence
reasons.

Checks: every health/lifecycle combination; missing hook; detached map;
warming generation; audit mode; stale status; unknown state never protected.

## Stage 3 — Workload/zone state

Add the read-only membership snapshot and identity transition logic. Key
workloads by source-qualified container/pod identity, treat cgroup IDs as
current handles, and mark reuse/restart ambiguity explicitly.

Checks: attach, detach, cgroup change, PID reuse, container restart, pod UID
recreation, stale generations, ambiguous identity, standalone mode.

## Stage 4 — Event stream

Consume the existing Syva denial/escape stream. Normalize it into the
versioned Observer envelope, add event IDs/sequences/gap markers, and keep a
bounded recent-event ring. Do not add allowed-operation event spam.

Checks: deny, would-deny, escape, unknown hook, lagging subscriber, dropped
event, monotonic-to-wall-clock conversion, restart gap.

## Stage 5 — Kubernetes enrichment

Implement an optional read-only provider for pod UID, owner, labels, service
account, namespace, node, security context, host namespaces, and mounts. Core
identity remains authoritative; API loss marks enrichment stale.

Checks: pod create/delete/recreate, annotation change, node filtering, API
outage, malformed object, stale cache, RBAC denial.

## Stage 6 — Agent posture semantics

Define explicit profile requirements and assess each as satisfied, violated,
unknown, or unsupported. Start with existing Syva-enforceable capabilities,
then add passive assessment for namespaces, privileged state, token mounts,
runtime sockets, host paths, and outbound network posture.

Checks: one test per requirement and per evidence class; policy-vs-kernel-vs-
observation distinction; no secret-content scanning.

## Stage 7 — Metadata/runtime/credential semantics

Add provider-aware metadata destination catalogs (AWS, GCP, Azure), inode/
mount-based runtime socket identification, and conservative authority exposure
checks. Keep active reachability probes opt-in.

Checks: IPv4/IPv6 endpoints, proxy ambiguity, host networking, socket path
aliases, inode reuse, projected token mount, unsupported provider.

## Stage 8 — CLI and local API

Expose the smallest useful read-only UX: `syvactl observe`, `posture`, and
`explain`, while preserving existing `status` and raw `events --follow`.

Checks: text/JSON contracts, unavailable core, stale state, event gap, unknown
posture, stable exit codes, no write authority.

## Stage 9 — Optional evidence export

Add a provider-neutral bounded sink interface. Implement Vartio export only as
an optional asynchronous adapter after the local schema and gap semantics are
stable. No Vartio dependency is required to build or run Observer.

Checks: sink unavailable, retry, backpressure, queue full, duplicate event,
schema version, explicit export gap, enforcement unaffected.

## Stage 10 — hardening and rollout

Run privileged real-kernel tests, Kubernetes lifecycle tests, restart/failure
tests, memory/CPU benchmarks, and long-running boundedness tests. Deploy
Observer disabled/read-only first, then enable posture reporting, then enable
optional exports.

Release gate: no `PROTECTED` false-positive in the evidence test matrix;
Observer crash and provider outage leave Syva enforcement unchanged.
