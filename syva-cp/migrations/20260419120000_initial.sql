-- Teams: ownership boundary and RBAC anchor.
CREATE TABLE teams (
    id                  UUID PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    display_name        TEXT,
    status              TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,
    version             BIGINT NOT NULL,
    caused_by_event_id  UUID NULL
);

-- Zones: logical isolation unit (schema only; writes land in Session 2).
CREATE TABLE zones (
    id                  UUID PRIMARY KEY,
    team_id             UUID NOT NULL REFERENCES teams(id),
    name                TEXT NOT NULL,
    display_name        TEXT,
    status              TEXT NOT NULL CHECK (status IN ('pending', 'active', 'draining', 'deleted')),
    current_policy_id   UUID NULL,
    selector_json       JSONB NULL,
    metadata_json       JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,
    deleted_at          TIMESTAMPTZ NULL,
    version             BIGINT NOT NULL,
    caused_by_event_id  UUID NULL,
    UNIQUE (team_id, name)
);

-- Policies: immutable, versioned per zone.
CREATE TABLE policies (
    id                  UUID PRIMARY KEY,
    zone_id             UUID NOT NULL REFERENCES zones(id),
    version             BIGINT NOT NULL,
    checksum            TEXT NOT NULL,
    policy_json         JSONB NOT NULL,
    summary_json        JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL,
    created_by_subject  TEXT NULL,
    caused_by_event_id  UUID NOT NULL,
    UNIQUE (zone_id, version),
    UNIQUE (zone_id, checksum)
);

-- Late-bound FK: zones.current_policy_id → policies.id. Needs both tables
-- to exist before the constraint can be added.
ALTER TABLE zones
    ADD CONSTRAINT zones_current_policy_id_fkey
    FOREIGN KEY (current_policy_id) REFERENCES policies(id);

-- Control plane events: the local causal spine (ADR 0003 Rule 7).
CREATE TABLE control_plane_events (
    id                  UUID PRIMARY KEY,
    event_type          TEXT NOT NULL,
    source              TEXT NOT NULL,
    subject_type        TEXT NULL,
    subject_id          TEXT NULL,
    team_id             UUID NULL REFERENCES teams(id),
    resource_type       TEXT NULL,
    resource_id         UUID NULL,
    correlation_id      TEXT NULL,
    idempotency_key     TEXT NULL,
    occurred_at         TIMESTAMPTZ NOT NULL,
    caused_by_event_id  UUID NULL REFERENCES control_plane_events(id),
    payload_json        JSONB NOT NULL DEFAULT '{}',
    summary_json        JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_cp_events_resource    ON control_plane_events(resource_type, resource_id);
CREATE INDEX idx_cp_events_team        ON control_plane_events(team_id, occurred_at DESC);
CREATE INDEX idx_cp_events_type        ON control_plane_events(event_type, occurred_at DESC);
CREATE INDEX idx_cp_events_correlation ON control_plane_events(correlation_id)
    WHERE correlation_id IS NOT NULL;

-- Audit log: compliance record; append-only via trigger in the next migration.
CREATE TABLE audit_log (
    id                      UUID PRIMARY KEY,
    occurred_at             TIMESTAMPTZ NOT NULL,
    actor_type              TEXT NOT NULL,
    actor_id                TEXT NOT NULL,
    team_id                 UUID NULL REFERENCES teams(id),
    action                  TEXT NOT NULL,
    resource_type           TEXT NOT NULL,
    resource_id             UUID NOT NULL,
    result                  TEXT NOT NULL CHECK (result IN ('success', 'denied', 'failed')),
    request_json            JSONB NOT NULL,
    response_json           JSONB NULL,
    control_plane_event_id  UUID NULL REFERENCES control_plane_events(id)
);

CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id, occurred_at DESC);
CREATE INDEX idx_audit_team     ON audit_log(team_id, occurred_at DESC);
CREATE INDEX idx_audit_actor    ON audit_log(actor_type, actor_id, occurred_at DESC);
