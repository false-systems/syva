# syva-cp — task list (v0.3 control plane)

Source design: `docs/v0.3/CONTROL_PLANE.md` (the design doc this list was extracted from).

53 tasks across 10 waves. Wave dependencies are linear; tasks within a wave are
parallel-safe unless deps say otherwise. Each task is a single PR/commit, sized
~30 min – 1 h. Acceptance signal lives on the `done:` line — no green, no merge.

Conventions for codex (or any picker):
- Branch name: `cp-NNN-short-slug` (e.g. `cp-021-zonestore`).
- PR title: `cp-NNN: <title>`.
- Pick any task whose deps are all merged. Mark in-progress by self-assigning
  the corresponding GitHub issue (`gh issue edit N --add-assignee @me`).
- If a task needs design clarification, comment on the issue rather than
  guessing — keep the task list source-of-truth aligned with the design doc.

──────────────────────────────────────────────────────────────────
## Wave 0 — foundations (sequential, blocks everything)
──────────────────────────────────────────────────────────────────

- [ ] **CP-001  syva-cp crate scaffold** (bin, clap CLI: `--addr`, `--db-url`)
  - done: `cargo run -p syva-cp -- --help` prints usage
  - deps: none

- [ ] **CP-002  syva_control.proto skeleton** — 7 services, no methods
  - done: `cargo build -p syva-proto` generates control client + server traits
  - deps: CP-001

- [ ] **CP-003  syva-cp-store lib crate**, `sqlx::PgPool` wrapper
  - done: `Store::connect(url).await` returns a typed handle
  - deps: CP-001

- [ ] **CP-004  docker-compose.dev.yml**: `postgres:16` + adminer for local dev
  - done: `docker compose -f docker-compose.dev.yml up -d` exposes psql on 5432
  - deps: none

- [ ] **CP-005  sqlx migration runner** wired into syva-cp-store
  - done: `sqlx migrate run` against compose db succeeds on empty migrations dir
  - deps: CP-003, CP-004

- [ ] **CP-006  Migration 0001**: `teams`, `team_members`, `team_grants`
  - done: schema matches design doc; `psql \dt` shows the 3 tables
  - deps: CP-005

- [ ] **CP-007  Migration 0002**: `zones`, `policies` (with `checksum` column)
  - done: `zones.policy_id` FK → `policies.id`; policies has `UNIQUE(zone_id, version)`
  - deps: CP-005

- [ ] **CP-008  Migration 0003**: `nodes`, `node_labels` (separate table for label index)
  - done: `nodes.id` is uuid PK; index on `node_labels(key, value)`
  - deps: CP-005

- [ ] **CP-009  Migration 0004**: `assignments`, `containers`
  - done: `assignments` has `UNIQUE(zone_id, node_id)`; `containers.cgroup_id` non-null
  - deps: CP-007, CP-008

- [ ] **CP-010  Migration 0005**: `enforcement_events` (partition by day)
  - done: parent table + 7-day forward partitions auto-created via pg_partman or cron
  - deps: CP-009

- [ ] **CP-011  Migration 0006**: `audit_log` (partition by month, append-only trigger)
  - done: INSERT works; UPDATE/DELETE raise exception
  - deps: CP-006

──────────────────────────────────────────────────────────────────
## Wave 1 — store layer (8 parallel tracks)
──────────────────────────────────────────────────────────────────

- [ ] **CP-020  TeamStore**: `create`, `get_by_id`, `get_by_name`, `list`, `update`, `delete` + member ops
  - done: integration test against compose db round-trips a team
  - deps: CP-006

- [ ] **CP-021  ZoneStore**: `create`, `get`, `update` (optimistic-lock by `version`), `delete` (drain), `list`
  - done: stale UPDATE returns `ConflictError`; soft-delete sets status=Draining
  - deps: CP-007, CP-020

- [ ] **CP-022  PolicyStore**: `create_version` (auto-bump), `get`, `list_for_zone`; immutable after create
  - done: UPDATE on policies raises (DB trigger); checksum SHA256 of canonical JSON
  - deps: CP-007

- [ ] **CP-023  NodeStore**: `register` (idempotent on node_id), `list`, `decommission`, `set_labels`
  - done: re-registering with same `node_id` returns the existing record
  - deps: CP-008

- [ ] **CP-024  AssignmentStore**: `list_for_node`, `list_for_zone`, `upsert`, `delete`; status updates
  - done: upsert is idempotent; unique on (zone_id, node_id)
  - deps: CP-009, CP-021, CP-023

- [ ] **CP-025  ContainerStore**: `attach`, `detach`, `list_for_zone`, `list_for_node`
  - done: detach sets `detached_at`; double-attach returns existing zone_id
  - deps: CP-009

- [ ] **CP-026  EventStore**: `insert_batch`, `query_paginated`, `stream_since(timestamp)`
  - done: 10k events insert < 100ms; query with zone+time filter uses partition pruning
  - deps: CP-010

- [ ] **CP-027  AuditStore**: `append`, `query_paginated`, `watch_since`
  - done: append never blocks; audit insert is part of the same txn as the write
  - deps: CP-011

──────────────────────────────────────────────────────────────────
## Wave 2 — gRPC services (one per service, parallel-safe)
──────────────────────────────────────────────────────────────────

- [ ] **CP-030  TeamService impl**: `CreateTeam`, `GetTeam`, `ListTeams`, `AddMember`, `RemoveMember`
  - done: tonic server registers; unit tests pass against in-memory store mock
  - deps: CP-020

- [ ] **CP-031  ZoneService unary**: `CreateZone`, `GetZone`, `UpdateZone`, `DeleteZone`, `ListZones`
  - done: `UpdateZone` bumps policy version automatically
  - deps: CP-021, CP-022

- [ ] **CP-032  ZoneService.WatchZones** (server-streaming) — fans out from a tokio broadcast
  - done: 2 clients each get the same `ZoneEvent` on UpdateZone
  - deps: CP-031

- [ ] **CP-033  PolicyService**: `GetPolicy`, `ListPolicies` (history per zone)
  - done: `ListPolicies` returns versions in descending order
  - deps: CP-022

- [ ] **CP-034  NodeService.Register** (issues node_token, persists node)
  - done: returns same node_id on re-register; new token each time
  - deps: CP-023

- [ ] **CP-035  NodeService.Subscribe** (server-streaming desired state for one node)
  - done: on connect emits full state, then incremental ZoneAssignments
  - deps: CP-024, CP-071

- [ ] **CP-036  NodeService.ReportState** — updates `assignments.actual_version`
  - done: drift between desired/actual surfaces in /status
  - deps: CP-024

- [ ] **CP-037  NodeService.Heartbeat** — bumps `last_seen`, returns `resubscribe` flag
  - done: stale node (>30s) flips to Offline; ListNodes reflects it
  - deps: CP-023

- [ ] **CP-038  NodeService.ListNodes + DecommissionNode** (admin only)
  - done: decommission cascades — all assignments for that node deleted
  - deps: CP-023, CP-063

- [ ] **CP-039  ContainerService**: `AttachContainer`, `DetachContainer`, `ListContainers`
  - done: `AttachContainer` resolves zone_name → zone_id, returns zone_bpf_id
  - deps: CP-025, CP-021

- [ ] **CP-040  EventService.WatchEvents** (server-streaming, filter by team/zone/node/hook)
  - done: backpressure handled — slow client doesn't block fast ones
  - deps: CP-026

- [ ] **CP-041  EventService.QueryEvents** (paginated, time-bounded)
  - done: rejects ranges > 24h without explicit zone filter
  - deps: CP-026

- [ ] **CP-042  AuditService**: `QueryAudit`, `WatchAudit`
  - done: queries scoped to caller's team unless admin
  - deps: CP-027, CP-063

──────────────────────────────────────────────────────────────────
## Wave 3 — auth & RBAC (middleware, cross-cutting)
──────────────────────────────────────────────────────────────────

- [ ] **CP-060  JWT (OIDC) validator middleware** — JWKS cache, iss/aud check
  - done: invalid token → UNAUTHENTICATED; valid token populates `Identity` in extensions
  - deps: CP-001

- [ ] **CP-061  API key auth** — random 32-byte token, hashed in db, scoped to team
  - done: rotated keys keep working until `expires_at`
  - deps: CP-001, CP-020

- [ ] **CP-062  Node token issuance + renewal** on heartbeat
  - done: tokens expire 24 h, heartbeat returns refreshed token if < 2 h left
  - deps: CP-034, CP-037

- [ ] **CP-063  RBAC permission matrix middleware** (admin / owner / editor / viewer / grantee)
  - done: matrix from design doc encoded as data; one decision function
  - deps: CP-060, CP-020

- [ ] **CP-064  Optimistic locking enforcement** — 409 on version mismatch in UpdateZone/DeleteZone
  - done: concurrent writes serialise; loser sees clean error
  - deps: CP-021, CP-031

──────────────────────────────────────────────────────────────────
## Wave 4 — engines
──────────────────────────────────────────────────────────────────

- [ ] **CP-070  AssignmentEngine.compute_for_node**(node) → `Vec<ZoneAssignment>`
  - done: pure function over (zones, node); unit-tested with NodeSelector matrix
  - deps: CP-021, CP-023

- [ ] **CP-071  AssignmentEngine.recompute_for_zone** — on zone create/update/delete
  - done: writes to `assignments` table, broadcasts `NodeAssignment` to subscribers
  - deps: CP-070, CP-024, CP-035

- [ ] **CP-072  AssignmentEngine.recompute_for_node** — on node register / label change
  - done: same as above but scoped to one node
  - deps: CP-070, CP-024, CP-035

──────────────────────────────────────────────────────────────────
## Wave 5 — REST gateway (axum)
──────────────────────────────────────────────────────────────────

- [ ] **CP-080  REST router scaffold** + auth middleware (Bearer, API key)
  - done: `GET /status` returns 200 with version + db ping result
  - deps: CP-060, CP-061

- [ ] **CP-081  REST: `/teams/{team}/zones` CRUD** with `If-Match` optimistic locking
  - done: stale `If-Match` returns 409
  - deps: CP-031, CP-064, CP-080

- [ ] **CP-082  REST: `/nodes`** (admin), `/nodes/{id}/decommission`
  - done: non-admin → 403
  - deps: CP-038, CP-080

- [ ] **CP-083  REST: `/events` SSE** — `text/event-stream`, `Last-Event-ID` resume
  - done: `curl -N` receives JSON-encoded `EnforcementEvent` lines
  - deps: CP-040, CP-080

- [ ] **CP-084  REST: `/audit` query** + `/audit/stream` SSE
  - done: scoped to team unless admin
  - deps: CP-042, CP-080

──────────────────────────────────────────────────────────────────
## Wave 6 — syva-core node agent (refactor)
──────────────────────────────────────────────────────────────────

- [ ] **CP-090  CP client**: gRPC over TLS+mTLS to syva-cp; reconnect with backoff
  - done: client builder takes ca/cert/key paths or insecure flag
  - deps: CP-002

- [ ] **CP-091  Persist node_id at `/var/lib/syva/node_id`** (atomic write, 0600)
  - done: second start reuses the same `node_id`
  - deps: CP-090

- [ ] **CP-092  Reconcile loop**: subscribe → for each `ZoneAssignment` apply/remove → `report_state`
  - done: integration test with a fake CP server applies+removes a zone end-to-end
  - deps: CP-090, CP-091, `ebpf::EnforceEbpf` already in tree

- [ ] **CP-093  Heartbeat task** — every 10 s, includes hook counters
  - done: CP marks node Offline within 30 s of heartbeat stop
  - deps: CP-090

- [ ] **CP-094  Push enforcement events**: drain ring buffer → batch → `CP.PublishEvents`
  - done: events show up in CP `/events` SSE stream
  - deps: CP-090, `EventService.PublishEvents` (add to proto)

- [ ] **CP-095  Health gating**: `/healthz` returns 503 until first reconcile applied
  - done: kube readiness probe behaves correctly during cold start
  - deps: CP-092

──────────────────────────────────────────────────────────────────
## Wave 7 — adapters refactor
──────────────────────────────────────────────────────────────────

- [ ] **CP-100  syva-adapter-file → talks to CP** TeamService + ZoneService (not syva-core)
  - done: TOML files become `CreateZone`/`UpdateZone` calls against CP
  - deps: CP-031

- [ ] **CP-101  syva-adapter-k8s → CRD watcher → CP** ZoneService + ContainerService
  - done: SyvaZonePolicy CRD apply lands as a `CreateZone`/`UpdateZone` in CP
  - deps: CP-031, CP-039

- [ ] **CP-102  Delete syva-adapter-api crate**; REST surface lives in syva-cp now
  - done: workspace shrinks; `deploy/v0.2/daemonset-api.yaml` replaced by syva-cp service
  - deps: CP-080..CP-084

──────────────────────────────────────────────────────────────────
## Wave 8 — eval (oracle/harness extension)
──────────────────────────────────────────────────────────────────

- [ ] **CP-110  CI: spin up postgres service** for store tests on Linux job
  - done: `cargo test -p syva-cp-store` runs in GH Actions and passes
  - deps: CP-005

- [ ] **CP-111  Oracle case_010_team_lifecycle** (create, get, list, delete)
  - done: yaml spec + `#[tokio::test]` in `eval/oracle`
  - deps: CP-030

- [ ] **CP-112  Oracle case_011_zone_create_then_list** (against CP, not syva-core)
  - done: same shape as existing oracle cases
  - deps: CP-031

- [ ] **CP-113  Oracle case_012_zone_update_fans_out** — fake node subscriber sees the new policy
  - done: spec proves end-to-end propagation
  - deps: CP-035, CP-071

- [ ] **CP-114  Oracle case_013_optimistic_lock_409** — concurrent UpdateZone, one wins
  - done: loser sees `AlreadyExists` / `FailedPrecondition` with version detail
  - deps: CP-064

- [ ] **CP-115  Oracle case_014_rbac_cross_team_denied** — team-B user can't UpdateZone of team-A
  - done: gRPC `PERMISSION_DENIED`
  - deps: CP-063

- [ ] **CP-116  Oracle case_015_node_offline_after_heartbeat_stop** — kill heartbeat, list shows Offline
  - done: spec asserts state transition < 35 s
  - deps: CP-037

──────────────────────────────────────────────────────────────────
## Wave 9 — docs
──────────────────────────────────────────────────────────────────

- [ ] **CP-120  CLAUDE.md**: add "Control plane vs node agent" section, update commands
  - done: build/run instructions for syva-cp + syva-core both shown
  - deps: CP-001, CP-090

- [ ] **CP-121  README.md**: replace adapter triangle with control-plane diagram
  - done: matches the ASCII diagram from the design doc
  - deps: CP-080

- [ ] **CP-122  docs/adr/0001-postgres-over-etcd.md** — capture the decision and trade-offs
  - done: short ADR (problem, decision, consequences)
  - deps: none

──────────────────────────────────────────────────────────────────

**Total: 53 tasks.** A claimable batch is anything whose deps are all checked.
At any given time several waves can be in flight in parallel — tracking should
be the GitHub issue queue, not this file. Update the checkboxes here as the
issues land so a fresh contributor can see the shape of what's done.
