# ADR 0003 — transactional write discipline

**Status:** accepted
**Date:** 2026-04-19
**Supersedes:** —
**See also:** [ADR 0002 — control plane](./0002-control-plane.md)

## Context

syvä's control plane stores more than just current state. It stores a
*causal history* — every mutation ("team created", "zone updated",
"assignment failed on node N") is an append-only event, and every row
of current state cites the event that produced it. This is how we get
auditability, reproducibility, and the ability to stream "what just
changed" to subscribers without walking the whole database.

That design only works if every write upholds the same rules. One
handler that forgets to emit an event, or writes the event after the
state row, or silently skips audit on a failure path, and the spine
breaks. Breaks compound: a handler reading from the spine assumes it's
correct, downstream replays produce wrong history, compliance queries
return plausible-but-wrong answers. These bugs are latent and very
expensive to discover.

The answer is discipline at the point of write, enforced at multiple
layers — human (convention), static (lint), and runtime (DB triggers,
metrics, structural tests).

## Decision

Every mutating operation in `syva-cp` follows ten rules, numbered so
they can be cited in code review and commit messages:

### Rule 1 — one transaction per operation

A single `BEGIN` / `COMMIT` wraps the entire causal write set of an
operation. No partial commits. No "two transactions, compensate on
failure" patterns at this layer.

### Rule 2 — canonical write order

Within a transaction, writes happen in this order:

1. `control_plane_events` — the event row. Gets a fresh UUID
   (`event_id`). Recorded first so every subsequent write in this
   transaction can cite it.
2. Current state (`teams`, `zones`, ...). `caused_by_event_id =
   $event_id`.
3. Version history (`policies`, and future history tables). Same
   `caused_by_event_id`.
4. Derived state (assignments, membership, comms). Same event id.
5. `audit_log`. `control_plane_event_id = $event_id`.

This ordering matters because FK constraints and triggers can make
later steps fail. If audit (step 5) fails, the whole transaction
rolls back and the event from step 1 never becomes visible.

### Rule 3 — no external I/O inside the transaction

HTTP calls, kube-api requests, file reads, DNS lookups — all of these
happen before `BEGIN`. Inside the transaction we do nothing that can
block on the network or the filesystem. This keeps transaction
duration bounded and lets us treat commits as "all fast or rolled
back".

### Rule 4 — optimistic locking on versioned resources

Any resource with a `version BIGINT` column is updated with `WHERE id
= $1 AND version = $2`. Zero rows affected means a concurrent writer
won the race; the handler returns `VersionConflict` and the caller
retries with the current version. No row-level locks, no application
mutexes.

### Rule 5 — advisory locks for zone-scoped serialization

Operations that touch the zone graph (zone create/update/delete,
policy create, assignment recompute) take a Postgres advisory lock
keyed on `zone_id` for the scope of the transaction. Rule 4 handles
single-row races; Rule 5 handles the multi-row case where two writers
would both legitimately succeed but produce divergent derived state.
(Lands with zones in Session 2.)

### Rule 6 — all mutations go through `TransactionalWriter`

No `sqlx::query!(… INSERT …)` or `sqlx::query!(… UPDATE …)` or
`sqlx::query!(… DELETE …)` anywhere except under `syva-cp/src/write/`.
Enforced by `cargo run -p xtask -- check-write-discipline`, which CI
runs before the workspace build.

### Rule 7 — causal predecessor via `caused_by_event_id`

When operation B is triggered by event A, B's event row cites A in
`caused_by_event_id`. Origin events (a user-initiated CreateTeam, for
example) have `caused_by_event_id = NULL`. Replay tools walk this
chain to reconstruct "what caused what".

### Rule 8 — audit is structural, not optional

Every accepted mutation writes a `success` audit row. Every rejected
or failed mutation still writes an audit row — `result = 'denied'` or
`result = 'failed'` — with the request payload and the error. A
missing audit row is itself a bug, and the structural tests from Rule
10 verify presence, not absence.

### Rule 9 — append-only at the database layer

`control_plane_events`, `audit_log`, and `policies` have BEFORE UPDATE
and BEFORE DELETE triggers that raise. A Rust bug that tries to mutate
those rows hits a Postgres error immediately, not a silent corruption.

### Rule 10 — transaction duration is a monitored SLO

Every mutating operation records `syva_cp_transaction_duration_seconds{
operation="..."}`. Long tails surface as budget violations before
they turn into lock contention. Rollbacks are counted separately as
`syva_cp_transaction_rollback_total{operation, reason}` so regressions
in the failure mix show up in metrics rather than in an incident.

## Enforcement

Three layers, and each exists to catch failures the other two miss:

- **Convention:** the module doc in `syva-cp/src/write/mod.rs` lists
  all ten rules. Code review cites them by number.
- **Static:** `cargo run -p xtask -- check-write-discipline` grep-scans
  `syva-cp/src/` for `sqlx::query…INSERT/UPDATE/DELETE` patterns
  outside `write/` and fails CI on any match.
- **Runtime:** the BEFORE UPDATE / BEFORE DELETE triggers on event and
  audit tables; the per-operation structural test that asserts the
  full causal row set lands atomically (and that a rollback leaves no
  orphans).

## Consequences

**Positive**

- Audit is a byproduct of normal writes, not a side channel.
- Failure modes (rollback reason) show up in metrics, so you can see
  "name conflicts doubled" without grepping logs.
- Replay and debugging have a stable spine to walk.
- The pattern is teachable: "read `create_team`, copy it".

**Negative**

- More code per mutation — three writes where a naive handler would
  have one.
- The canonical order constrains schema changes. Adding a new
  dependent table means wiring it into every operation that writes
  through it.
- Advisory locks need care at scale — a handler that forgets to take
  one can cause derived-state drift that passes every other test.

## Consequences for contributors

- Every new mutating operation ships with a structural test that
  asserts the full causal row set and that a rollback leaves no
  orphans. See `syva-cp/tests/create_team_writes_all_causal_rows.rs`.
- New migrations that add tables which should be append-only include
  triggers in the same migration. Don't split it across two files.
- PR title prefix: `feat(write): <operation>` for new mutations.
  Reviewers look for the structural test before the implementation.

## Scope boundary for Session 1

Rules 1, 2, 3, 6, 7, 8, 9, and 10 are in force today. Rule 4
(optimistic locking on updates) and Rule 5 (advisory locks) ship
with the zone/policy work in Session 2 — `CreateTeam` has no update
path and no cross-row invariants to serialize.
