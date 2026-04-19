-- ADR 0003 Rule 9: the database enforces append-only on event and audit
-- tables, and immutability on policies once created. A bug in the Rust
-- layer that tries to UPDATE/DELETE these rows fails loudly at the DB
-- rather than silently corrupting the causal spine.

CREATE OR REPLACE FUNCTION reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'table % is append-only, % not allowed',
        TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql;

-- control_plane_events: immutable log of causal events.
CREATE TRIGGER control_plane_events_no_update
    BEFORE UPDATE ON control_plane_events
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE TRIGGER control_plane_events_no_delete
    BEFORE DELETE ON control_plane_events
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- audit_log: compliance record. Never edit, never delete.
CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE TRIGGER audit_log_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- policies: ADR 0002 — a new version is a new row, never an edit.
CREATE TRIGGER policies_no_update
    BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE TRIGGER policies_no_delete
    BEFORE DELETE ON policies
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();
