-- Nodes: registered node agents
CREATE TABLE nodes (
    id UUID PRIMARY KEY,
    node_name TEXT UNIQUE NOT NULL,
    cluster_id TEXT NULL,
    status TEXT NOT NULL CHECK (status IN ('online', 'offline', 'decommissioning', 'decommissioned')),
    fingerprint TEXT NULL,
    last_seen_at TIMESTAMPTZ NULL,
    last_heartbeat_event_id UUID NULL REFERENCES control_plane_events(id),
    current_token_expires_at TIMESTAMPTZ NULL,
    capabilities_json JSONB NOT NULL DEFAULT '{}',
    metadata_json JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL,
    caused_by_event_id UUID NULL REFERENCES control_plane_events(id)
);

CREATE INDEX idx_nodes_status ON nodes(status) WHERE status IN ('online', 'offline');
CREATE INDEX idx_nodes_last_seen ON nodes(last_seen_at DESC);
CREATE UNIQUE INDEX idx_nodes_fingerprint ON nodes(fingerprint) WHERE fingerprint IS NOT NULL;

-- Node labels: key/value pairs used by selector matching.
CREATE TABLE node_labels (
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (node_id, key)
);

CREATE INDEX idx_node_labels_key_value ON node_labels(key, value);

-- Assignments: desired state, which zones should be present on which nodes.
CREATE TABLE assignments (
    id UUID PRIMARY KEY,
    zone_id UUID NOT NULL REFERENCES zones(id),
    node_id UUID NOT NULL REFERENCES nodes(id),
    status TEXT NOT NULL CHECK (status IN (
        'desired', 'applying', 'applied', 'drifted', 'removing', 'removed', 'failed'
    )),
    desired_policy_id UUID NOT NULL REFERENCES policies(id),
    desired_zone_version BIGINT NOT NULL,
    actual_policy_id UUID NULL REFERENCES policies(id),
    actual_zone_version BIGINT NULL,
    last_reported_at TIMESTAMPTZ NULL,
    error_json JSONB NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL,
    caused_by_event_id UUID NOT NULL REFERENCES control_plane_events(id),
    UNIQUE (zone_id, node_id)
);

CREATE INDEX idx_assignments_node_status ON assignments(node_id, status);
CREATE INDEX idx_assignments_zone ON assignments(zone_id);
CREATE INDEX idx_assignments_status ON assignments(status)
    WHERE status IN ('desired', 'applying', 'drifted', 'failed');

-- assignment_versions: append-only history snapshots.
CREATE TABLE assignment_versions (
    id UUID PRIMARY KEY,
    assignment_id UUID NOT NULL REFERENCES assignments(id),
    version BIGINT NOT NULL,
    snapshot_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    caused_by_event_id UUID NOT NULL REFERENCES control_plane_events(id),
    UNIQUE (assignment_id, version)
);

CREATE INDEX idx_assignment_versions_assignment_version
    ON assignment_versions(assignment_id, version DESC);

CREATE TRIGGER assignment_versions_no_update
    BEFORE UPDATE ON assignment_versions
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE TRIGGER assignment_versions_no_delete
    BEFORE DELETE ON assignment_versions
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();
