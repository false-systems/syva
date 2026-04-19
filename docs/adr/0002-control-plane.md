# ADR 0002 — syvä control plane

**Status:** accepted (Session 1 lays the foundation, Sessions 2+ extend it)
**Date:** 2026-04-19
**Supersedes:** —
**See also:** [ADR 0003 — transactional write discipline](./0003-transactional-write-discipline.md),
[`docs/v0.3/CONTROL_PLANE.md`](../v0.3/CONTROL_PLANE.md) for the full design.

## Context

Through v0.2, syvä runs as a node-local daemon (`syva-core`) plus a
handful of adapters that push desired state directly into the core over
a Unix-socket gRPC. That shape is fine for a single node or a hand-full
of nodes with a single policy source. It does not scale to the
environments syvä is aimed at: hundreds of nodes, thousands of zones,
dozens of teams, and CI/CD pipelines that rewrite zone membership every
few seconds.

The gaps:

- **No single source of truth.** Each adapter pushes its view of
  desired state directly to whichever node it can reach. Reconciliation
  across adapters is ad-hoc. There's no audit of who changed what.
- **No multi-tenant boundary.** Any adapter with the core socket can
  touch any zone. Team ownership and RBAC cannot be expressed.
- **No history.** Zone policy changes are best-effort — the current
  policy is the one on disk, and there's no structured record of the
  transition from the old to the new version.
- **No fan-out.** Every adapter has to know about every node. A new
  node means a new adapter configuration, not a new subscriber.

## Decision

Introduce a control plane crate, `syva-cp`:

- Single source of truth for teams, zones, policies, assignments,
  containers, and an append-only audit/event log.
- Storage: PostgreSQL as the primary backend. etcd considered and
  deferred — see "Alternatives" below.
- API: gRPC for machine clients (nodes, adapters); a REST gateway on
  the same binary mirrors the surface for human tooling. Both land
  across Session 1–5.
- Node relationship: nodes register, subscribe to a stream of
  `NodeAssignment` messages, and reconcile their local BPF state against
  the desired state the control plane pushes. The node is a dumb
  enforcer; the control plane never issues direct "do X" commands —
  only "here is desired state, make your world match it".
- Adapter relationship: adapters (file, k8s, api, future ci) push
  desired state to the control plane, never to nodes. An adapter that
  goes away does not take its zones with it — they live in Postgres
  until something rewrites them.

The data model, in brief:

- **Team** — ownership boundary and RBAC anchor. Every zone belongs to
  a team; cross-team references require explicit grants.
- **Zone** — the logical isolation unit. Has a `version` for
  optimistic locking and a `current_policy_id` pointing at the
  active policy row.
- **Policy** — immutable, versioned per zone. A zone update creates a
  new policy row and flips `zones.current_policy_id`. Old policies
  are never edited or deleted; the history is the audit trail.
- **Assignment** — which policy version of which zone runs on which
  node. Computed by the control plane from `NodeSelector` rules on
  each zone.
- **Node** — a Linux machine running `syva-core`. Self-registers on
  startup with a persisted `node_id`.
- **Container** — runtime binding of a container ID to a zone on a
  specific node. Ephemeral.
- **EnforcementEvent** — deny/allow observations streamed from each
  node. Partitioned by day; retention measured in weeks, not forever.
- **AuditLog** — every write operation on the control plane. Append
  only, partitioned by month, retained for compliance windows.
- **control_plane_events** — the internal causal spine. Every
  mutation emits an event; every subsequent mutation that depends on
  a prior one cites it via `caused_by_event_id`. See ADR 0003.

## Consequences

**Positive**

- One place to ask "what is the world supposed to look like?"
- RBAC becomes a first-class concept (Session 3).
- Audit is structural, not optional (enforced by ADR 0003).
- Nodes can come and go without operators re-configuring adapters.
- GitOps-style flows (policy-in-git, CI pipes to REST) become a normal
  pattern instead of a bespoke wiring job.

**Negative**

- A new service to run. Kubernetes deployments now need a Postgres
  instance and a `syva-cp` Deployment in addition to the DaemonSet.
- Node ↔ control-plane connectivity becomes a dependency. Nodes
  must keep working during control-plane outages — they enforce
  from the last-known state and reconcile when the connection
  returns. This pattern is enforced by the reconcile loop (Session 6).
- Schema evolution has compounding costs. Once teams and zones are in
  a production database, migrations can't be cavalier. This is why
  ADR 0003 exists.

## Alternatives considered

**etcd as the store.** Fits Kubernetes-native deployments out of the
box; loses when Kubernetes isn't present. Deferred to a future ADR
once the data model is stable and we understand which read patterns
actually matter in production. Postgres wins the first round because
partitioning, indexes, joins, triggers, and SQL-level append-only
enforcement are all mature and familiar.

**Embed the control plane in `syva-core`.** Rejected. The node agent
and the control plane have very different fault tolerance
requirements (node: "always enforce"; CP: "always be consistent"),
very different scaling shapes, and very different blast-radius
properties. Embedding them would couple those concerns forever.

## Scope boundary for Session 1

Session 1 brings up the crate skeleton, the shared tables, the
`TransactionalWriter` module, and `CreateTeam` end-to-end. Zones,
policies, nodes, assignments, RBAC, streaming RPCs, REST — all later
sessions.
