# syvä Control Plane — Full Design

**version 0.1 — false systems · berlin · 2026**

> Source design for the v0.3 control-plane work. The actionable breakdown is in
> [`TASKS.md`](./TASKS.md). When a task references a section here, link to the
> anchor (e.g. `docs/v0.3/CONTROL_PLANE.md#data-model`) rather than copying the
> spec into the PR description.

---

## The Problem

Thousands of zones. Hundreds of nodes. Dozens of teams. CI/CD changing zones
every few seconds.

A config file doesn't solve this. A daemon with hot-reload doesn't solve this.
You need a control plane.

---

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │         syva-cp (control plane)     │
                    │                                     │
                    │  API server (gRPC + REST)           │
                    │  Zone registry                      │
                    │  Policy engine                      │
                    │  Assignment engine                  │
                    │  RBAC engine                        │
                    │  Audit log                          │
                    │  Event collector                    │
                    │                                     │
                    │  Storage: PostgreSQL or etcd        │
                    └──────────────┬──────────────────────┘
                                   │
                    gRPC (network) │ push-based
                    TLS + mTLS     │ node subscribes to
                                   │ assignment stream
          ┌────────────────────────┼────────────────────┐
          ↓                        ↓                    ↓
  ┌──────────────┐        ┌──────────────┐     ┌──────────────┐
  │ syva-core    │        │ syva-core    │     │ syva-core    │
  │ node-01      │        │ node-02      │     │ node-N       │
  │              │        │              │     │              │
  │ reconcile    │        │ reconcile    │     │ reconcile    │
  │ loop         │        │ loop         │     │ loop         │
  │ BPF maps     │        │ BPF maps     │     │ BPF maps     │
  │ 7 LSM hooks  │        │ 7 LSM hooks  │     │ 7 LSM hooks  │
  └──────────────┘        └──────────────┘     └──────────────┘

          ↑ adapters push desired state to control plane
          ↑ never to nodes directly

  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │ k8s-adapter  │   │ api-adapter  │   │ ci-adapter   │
  │ watches CRDs │   │ REST API     │   │ webhook      │
  └──────────────┘   └──────────────┘   └──────────────┘
```

**The key principle:** adapters talk to the control plane. The control plane
talks to nodes. Nodes are dumb enforcement engines. Nodes never receive commands
from adapters directly.

---

## Data Model

### Team

The top-level ownership unit. Teams own zones. Teams cannot touch each other's
zones without explicit grants.

```
Team {
    id:          UUID          -- stable, never changes
    name:        string        -- "platform", "backend", "security"
    display_name: string
    created_at:  timestamp
    created_by:  string        -- user or service account

    members:     [TeamMember]
    grants:      [TeamGrant]   -- cross-team zone access
}

TeamMember {
    identity:    string        -- user, service account, or OIDC subject
    role:        TeamRole      -- owner | editor | viewer
}

TeamGrant {
    granted_to:  UUID          -- team_id
    zone_pattern: string       -- glob, e.g. "api-*"
    permission:  Permission    -- read | write
}

TeamRole {
    Owner   -- can manage team, manage zones, grant access
    Editor  -- can manage zones
    Viewer  -- read-only
}
```

### Zone

The core entity. Owned by a team. Has a policy. Has a version. Independent of
nodes and containers.

```
Zone {
    id:          UUID          -- stable, never changes
    name:        string        -- "api-prod", "db-prod", "worker-staging"
    team_id:     UUID          -- owner

    policy_id:   UUID          -- current active policy version
    status:      ZoneStatus

    node_selector: NodeSelector -- which nodes this zone runs on

    created_at:  timestamp
    created_by:  string
    updated_at:  timestamp
    updated_by:  string
    version:     u64           -- monotonically increasing, for optimistic locking

    labels:      map<string,string>
    annotations: map<string,string>
}

ZoneStatus {
    Active      -- policy applied, enforcement running
    Pending     -- created, not yet applied to any node
    Draining    -- removal requested, waiting for containers to detach
    Failed      -- policy application failed, see error field
}
```

### Policy

Immutable. You never edit a policy — you create a new version. The zone points
to the current `policy_id`.

```
Policy {
    id:          UUID
    zone_id:     UUID
    version:     u64           -- 1, 2, 3... per zone

    host_paths:  [HostPath]
    allowed_zones: [ZoneRef]
    allow_ptrace: bool
    zone_type:   ZoneType

    created_at:  timestamp
    created_by:  string

    checksum:    string        -- SHA256 of canonical policy JSON
}

HostPath { path: string; recursive: bool; read_only: bool }
ZoneRef  { zone_name: string; team_name: string? }
ZoneType { Standard | Privileged | Isolated }
```

### Assignment

Which zones are active on which nodes. Computed by the assignment engine. Node
agents consume this.

```
Assignment {
    id:          UUID
    zone_id:     UUID
    node_id:     UUID
    policy_id:   UUID

    status:      AssignmentStatus
    assigned_at: timestamp
    applied_at:  timestamp

    desired_version: u64
    actual_version:  u64
    last_error:      string?
}

AssignmentStatus {
    Pending | Applying | Applied | Failed | Removing | Removed
}
```

### Node

A Linux machine running syva-core. Self-registers with the control plane on
startup.

```
Node {
    id:          UUID          -- generated by node on first registration
    name:        string        -- hostname

    labels:      map<string,string>

    status:      NodeStatus
    last_seen:   timestamp

    kernel_version:  string
    btf_available:   bool
    syva_version:    string

    registered_at:   timestamp
}

NodeStatus { Online | Offline | Draining }
```

### NodeSelector

Determines which nodes a zone runs on.

```
NodeSelector {
    match_labels: map<string,string>
    node_names:   [string]
    all_nodes:    bool          -- true is the default if empty
}
```

### Container

Runtime binding. A container joins a zone. Ephemeral.

```
Container {
    id:          string         -- containerd container ID
    zone_id:     UUID
    node_id:     UUID
    cgroup_id:   u64            -- resolved from /proc/{pid}/cgroup

    attached_at: timestamp
    detached_at: timestamp?
    status:      ContainerStatus
}

ContainerStatus { Active | Detached }
```

### Event

Enforcement decision. Flows from node → control plane → audit log + event
stream.

```
EnforcementEvent {
    id:          UUID
    node_id:     UUID
    timestamp:   timestamp

    hook:        string
    action:      Action

    zone_id:     UUID?
    target_zone_id: UUID?

    pid:         u32
    comm:        string
    inode:       u64
    context:     string
}

Action { Allow | Deny }
```

### AuditLog

Every write operation on the control plane. Immutable append-only.

```
AuditEntry {
    id:          UUID
    timestamp:   timestamp

    actor:       string
    team_id:     UUID?

    operation:   AuditOperation
    resource:    string
    before:      JSON?
    after:       JSON?

    request_id:  string
    source_ip:   string
}

AuditOperation {
    ZoneCreate | ZoneUpdate | ZoneDelete
    PolicyCreate
    AssignmentCreate | AssignmentDelete
    TeamCreate | TeamUpdate
    ContainerAttach | ContainerDetach
    NodeRegister | NodeDecommission
}
```

---

## Control Plane API

### gRPC — `syva_control.proto`

Seven services:

- **ZoneService** — `CreateZone`, `UpdateZone`, `DeleteZone`, `GetZone`, `ListZones`, `WatchZones` (server streaming)
- **PolicyService** — `GetPolicy`, `ListPolicies` (history per zone). Policies are created via `UpdateZone`, never directly.
- **NodeService** — `Register`, `Subscribe` (server streaming desired state), `ReportState`, `Heartbeat`, `ListNodes`, `DecommissionNode`
- **ContainerService** — `AttachContainer`, `DetachContainer`, `ListContainers`
- **EventService** — `WatchEvents` (server streaming), `QueryEvents`
- **TeamService** — `CreateTeam`, `GetTeam`, `ListTeams`, `AddMember`, `RemoveMember`, `GrantAccess`
- **AuditService** — `QueryAudit`, `WatchAudit` (server streaming)

The full proto messages are in the design doc; treat the section above as the
contract surface to implement against.

### REST API

The REST API mirrors the gRPC surface for human-facing tooling (CLI,
dashboards, CI/CD webhooks).

```
Base URL: https://syva-cp.your-cluster/api/v1

Auth: Bearer token (JWT, OIDC, or API key)

# Zones
GET    /teams/{team}/zones
POST   /teams/{team}/zones
GET    /teams/{team}/zones/{name}
PUT    /teams/{team}/zones/{name}
DELETE /teams/{team}/zones/{name}
GET    /teams/{team}/zones/{name}/policy
GET    /teams/{team}/zones/{name}/history
GET    /teams/{team}/zones/{name}/containers
GET    /teams/{team}/zones/{name}/events     (SSE)

# Nodes
GET    /nodes
GET    /nodes/{id}
GET    /nodes/{id}/assignments
POST   /nodes/{id}/decommission

# Events
GET    /events                   (SSE)
GET    /teams/{team}/events      (SSE)
POST   /events/query

# Teams
GET    /teams
POST   /teams
GET    /teams/{team}
POST   /teams/{team}/members
DELETE /teams/{team}/members/{identity}
POST   /teams/{team}/grants

# Audit
GET    /audit
GET    /audit/stream             (SSE)

# Status
GET    /status
GET    /status/nodes
```

Key REST behaviours:

- **Optimistic locking:** every PUT includes `If-Match: {version}`. 409 on mismatch.
- **SSE:** `/events` is `text/event-stream`; clients reconnect with `Last-Event-ID`.
- **Pagination:** `?page_size=100&page_token=...` on every list endpoint.
- **Filtering:** `?status=active&label.env=prod&label.team=backend`.

---

## Node Agent Reconcile Loop

This is the heart of the desired state model. Pseudocode (see `syva-core` source
for the real implementation):

```rust
async fn reconcile_loop(node_id: &str, cp: &CpClient, ebpf: &mut EnforceEbpf, reg: &mut ZoneRegistry) {
    loop {
        let mut stream = cp.subscribe(SubscribeRequest {
            node_id: node_id.into(),
            active_zone_ids: reg.active_zone_ids(),
            active_policy_versions: reg.active_policy_versions(),
        }).await;

        while let Some(assignment) = stream.next().await {
            for za in assignment.zones {
                match za.action {
                    AssignmentAction::Apply  => apply_zone(&za, ebpf, reg).await,
                    AssignmentAction::Remove => remove_zone(&za.zone_id, ebpf, reg).await,
                }
            }
            cp.report_state(build_state_report(reg)).await;
        }
        tokio::time::sleep(backoff.next()).await;
    }
}
```

**Self-healing:** crash + restart re-registers, re-subscribes, re-applies. The
control plane sends the full desired state on every new subscription. No manual
intervention.

**Conflict resolution:** the control plane is always right. If actual state
diverges (e.g. BPF map corruption), the reconcile loop detects the diff and
re-applies. There's only one source of truth.

---

## RBAC Model

| Operation       | Admin | Owner | Editor | Viewer | Grantee |
| --------------- | ----- | ----- | ------ | ------ | ------- |
| CreateZone      | ✓     | ✓     | ✓      | ✗      | ✗       |
| UpdateZone      | ✓     | ✓     | ✓      | ✗      | write   |
| DeleteZone      | ✓     | ✓     | ✗      | ✗      | ✗       |
| GetZone         | ✓     | ✓     | ✓      | ✓      | read    |
| ListZones       | ✓     | own   | own    | own    | granted |
| WatchEvents     | ✓     | ✓     | ✓      | ✓      | granted |
| QueryAudit      | ✓     | own   | own    | ✗      | ✗       |
| ManageTeam      | ✓     | ✓     | ✗      | ✗      | ✗       |
| ManageNodes     | ✓     | ✗     | ✗      | ✗      | ✗       |

### Authentication

- **JWT (OIDC)** — preferred for human users. Integrate with Okta, Google, GitHub.
- **API keys** — service accounts and CI. Short-lived (max 90 days), scoped to a team.
- **Node tokens** — issued on registration. Short-lived (24 h), auto-renewed via heartbeat. Scoped to node operations.

---

## Persistence

### Option A: PostgreSQL (recommended for production)

Schema:

```sql
teams, team_members, team_grants
zones, policies
nodes, node_labels
assignments
containers
enforcement_events (partitioned by day)
audit_log (append-only, partitioned by month)

-- Indexes
zones(team_id, status)
zones(name, team_id) UNIQUE
assignments(node_id, zone_id)
assignments(zone_id, status)
containers(zone_id, status)
containers(node_id, status)
enforcement_events(zone_id, timestamp)
enforcement_events(node_id, timestamp)
audit_log(team_id, timestamp)
audit_log(actor, timestamp)
```

PostgreSQL handles millions of enforcement events per day with partitioning.
Zone and assignment tables stay small (thousands of rows). Partition events by
day, retain 90 days, archive to object storage.

### Option B: etcd (Kubernetes-native)

If running inside Kubernetes, use etcd directly (or CRDs as the persistence
layer). The control plane becomes a standard Kubernetes controller. More
complex, fits k8s operational patterns.

For v0.3: **start with PostgreSQL.** etcd support deferred.

---

## Assignment Engine

```rust
pub struct AssignmentEngine {
    zones: Arc<ZoneStore>,
    nodes: Arc<NodeStore>,
}

impl AssignmentEngine {
    pub fn compute_assignments(&self, node: &Node) -> Vec<ZoneAssignment> {
        self.zones.all_active()
            .filter(|z| self.matches_node(z, node))
            .map(|z| ZoneAssignment {
                zone_id: z.id,
                zone_name: z.name.clone(),
                policy_version: z.policy.version,
                policy: z.policy.clone(),
                action: AssignmentAction::Apply,
            })
            .collect()
    }

    fn matches_node(&self, zone: &Zone, node: &Node) -> bool {
        let sel = &zone.node_selector;
        if sel.all_nodes { return true; }
        if sel.node_names.contains(&node.name) { return true; }
        if !sel.match_labels.is_empty() {
            return sel.match_labels.iter().all(|(k, v)| node.labels.get(k) == Some(v));
        }
        false
    }
}
```

**Change propagation:** on zone create/update/delete, the engine recomputes
assignments for all matching nodes and pushes via the subscription stream. Node
agents receive the diff and reconcile.

---

## Crate Structure for v0.3

```
syva/
├── syva-proto/            # syva_control.proto + syva_core.proto
├── syva-cp/               # control plane binary
│   └── src/
│       ├── main.rs
│       ├── api/           # gRPC + REST handlers
│       ├── engine/        # assignment engine, policy engine
│       ├── store/         # PostgreSQL models + queries
│       ├── auth/          # JWT, API keys, node tokens
│       └── audit.rs
├── syva-cp-store/         # sqlx-based persistence layer (split out)
├── syva-core/             # node agent (refactored to talk to syva-cp)
│   └── src/
│       ├── main.rs
│       ├── reconcile.rs
│       ├── btf.rs
│       ├── ebpf.rs
│       ├── zone.rs
│       ├── health.rs
│       └── events.rs
├── syva-adapter-file/     # file/ConfigMap adapter → talks to syva-cp
├── syva-adapter-k8s/      # CRD adapter → talks to syva-cp
├── syva-ebpf-common/      # unchanged
├── syva-ebpf/             # unchanged
└── xtask/                 # unchanged
```

`syva-adapter-api` is removed in v0.3 — the REST surface lives inside `syva-cp`.

---

## Deployment Models

### Model 1: Standalone (single machine)

```
syva-cp     (control plane, embedded mode for single-node)
   ↓ gRPC
syva-core   (node agent)
   ↑
syva-adapter-file  (reads local policy files)
```

### Model 2: Kubernetes cluster

```
syva-cp     (Deployment, 1–3 replicas, PostgreSQL backend)
   ↓ gRPC (network)
syva-core   (DaemonSet, one per node)
   ↑
syva-adapter-k8s  (Deployment, watches CRDs cluster-wide)
```

### Model 3: Multi-cluster (future)

```
syva-cp     (central, manages multiple clusters)
   ↓ gRPC
syva-core   (DaemonSet in cluster A, B, …, N)
```

---

## What This Unlocks

**Platform engineers**

- `kubectl apply` a `SyvaZonePolicy` and it propagates to all matching nodes in seconds.
- GitOps: zone policies in git, CI applies them, control plane propagates.
- RBAC: team A cannot touch team B's zones.
- Audit: every policy change is logged with who, when, and what changed.
- Visibility: one dashboard for enforcement events across all nodes.

**Agents**

- REST API for programmatic zone management.
- Stream enforcement events to detect anomalies.
- Query the audit log to understand what changed and when.

**False Systems**

- Control plane is the commercial product.
- syva-core and adapters are open source.
- Enterprise: multi-cluster, SSO, audit retention, compliance reports.

---

## The Pitch

> "syvä enforces kernel-level container isolation at scale. The node agent
> programs the kernel — it's been doing that since v0.1. The control plane is
> what makes it work across hundreds of nodes, thousands of zones, and dozens
> of teams. Declare your isolation policy once. The control plane propagates it
> everywhere. The kernel enforces it. Nothing in between."

---

*false systems · berlin · 2026 · apache 2.0*
