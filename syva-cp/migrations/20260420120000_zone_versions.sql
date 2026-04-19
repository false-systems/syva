-- Zone version history: one snapshot per mutation (ADR 0003 Rule 2 step 4)
CREATE TABLE zone_versions (
    id UUID PRIMARY KEY,
    zone_id UUID NOT NULL REFERENCES zones(id),
    version BIGINT NOT NULL,
    snapshot_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    caused_by_event_id UUID NOT NULL REFERENCES control_plane_events(id),
    UNIQUE (zone_id, version)
);

CREATE INDEX idx_zone_versions_zone_created
    ON zone_versions(zone_id, created_at DESC);

-- zone_versions is append-only per ADR 0003 Rule 9
CREATE TRIGGER zone_versions_no_update
    BEFORE UPDATE ON zone_versions
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE TRIGGER zone_versions_no_delete
    BEFORE DELETE ON zone_versions
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- Indexes on existing zones table that session 1 did not add
CREATE INDEX idx_zones_team_status ON zones(team_id, status)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_zones_status_updated ON zones(status, updated_at DESC)
    WHERE deleted_at IS NULL;

-- Index on policies for rollout queries (used in later session, add now)
CREATE INDEX idx_policies_zone_version ON policies(zone_id, version DESC);
