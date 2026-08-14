# Syva Observer: repository assessment

## Current boundary

Syva is a node-local Linux enforcement engine. `syva-core` owns BPF-LSM
loading, attachment, pinned generations, BPF maps, self-tests, health, zone
state, and the local `syva.core.v1` Unix-socket API. The eBPF programs make
the synchronous decision; userspace never calls a remote service from that
path.

Adapters translate sources into core mutations:

```text
TOML files ──► syva-file ──┐
Kubernetes CRDs ─► syva-k8s ├──► syva-core Unix socket ──► BPF-LSM
REST/local API ─► syva-api ──┘
```

`syvactl` is a thin local operator client. The core also exposes health and
Prometheus metrics and a live `WatchEvents` stream.

## Stable invariants

- A missing or failed adapter must not remove the last active enforcement
  generation.
- A new generation is populated disabled, self-tested, and activated only by
  an explicit matching generation ID.
- Existing active pins survive core restart until a replacement is ready.
- BPF read failures follow the documented fail-open/error-counting behavior.
- Zone ID `0` means host/unzoned; zone IDs are monotonic while the process
  lives and are not reused for another name.
- Container membership is keyed by a runtime container ID and carries cgroup
  ID, optional Kubernetes identity, source, generation, observation time, and
  applied state.
- Communication policy is symmetric at the core map boundary. The file and
  Kubernetes adapters derive mutual pairs.
- Event delivery is denial/escape-oriented, enriched once in userspace, and
  broadcast to live subscribers. The core drains the ring buffer even with no
  subscribers.
- `WatchEvents` has no backlog outside the live stream; lagging subscribers
  receive counted gaps.

## Identity facts and races

The authoritative enforcement identity is the kernel-visible cgroup ID used in
`ZONE_MEMBERSHIP`. Container IDs, pod UIDs, names, and PIDs are adapters'
correlation metadata, not the BPF key. PIDs are short-lived and must never be
used as durable workload identity. Cgroup IDs can be reused after teardown,
so an observer must associate them with a fresh container/pod observation and
freshness window rather than treating a numeric cgroup ID as globally unique.

The Kubernetes adapter resolves a running container's cgroup from `/proc` and
the cgroup filesystem, handles nested sub-cgroups, retries failed membership
operations, and uses source generations to reject stale attach/detach events.
Pod recreation and annotation changes can race with process discovery; the
observer must represent unresolved or stale identity explicitly.

## Existing evidence

Strong evidence already available:

- `StatusResponse`: attachment, hook counters, lifecycle, enforcement mode, and
  active/staging generation.
- `WatchEvents`: kernel decision/escape events with hook, zone IDs/names,
  comm, inode/path when indexed, destination, reason template, and monotonic
  kernel timestamp.
- health/metrics: self-tests, hook attachment, BPF map errors, membership
  outcomes, dropped watch subscribers, and zone deny aggregates.
- adapter observations: pod namespace/name/UID, container ID, cgroup ID, source,
  and source generation, currently held inside core rather than exposed by a
  read RPC.

Important evidence gaps for Observer:

- no read-only RPC lists current container memberships or their freshness;
- no explicit policy revision/fingerprint in the core status API;
- no durable event sequence ID or replay cursor;
- no API exposing expected-vs-attached program/link metadata beyond counters;
- no general workload snapshot that joins zone, cgroup, policy, and source
  metadata.

These are API preconditions, not reasons to put observation logic in BPF.

## Test and operational reality

Unit tests cover core state machines, policy translation, event rendering,
health, and adapter lifecycle logic. Evaluation cases cover local API and file
adapter behavior. Privileged tests prove selected real-kernel decisions, but
normal workspace CI marks those tests ignored. Kubernetes end-to-end and
multi-node evidence are separate gates.

Observer must therefore report the difference between configured policy,
observed kernel state, and tested kernel evidence. A successful Observer
process or successful API call alone cannot justify `PROTECTED`.

## Areas not to disturb

- BPF-LSM hook decision code and its fail-open semantics.
- Generation activation and pin cleanup/restart continuity.
- Existing `syva.core.v1` write semantics and adapter retry behavior.
- The single-consumer ring-buffer ownership model.
- Syva's ability to run without Kubernetes or Vartio.
- The separation between policy adapters and the core enforcement engine.

Observer should be a separate read-mostly process with optional enrichment,
not a mode inside `syva-core` and not a replacement for the existing adapters.
