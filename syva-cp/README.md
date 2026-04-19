# syva-cp

Control plane for syvä. Stores desired state, computes assignments,
audits every mutation.

Architecture: [`docs/adr/0002-control-plane.md`](../docs/adr/0002-control-plane.md).
Write rules: [`docs/adr/0003-transactional-write-discipline.md`](../docs/adr/0003-transactional-write-discipline.md).

## Local development

```sh
# Start postgres (podman or docker)
podman run -d --name syva-cp-pg \
    -e POSTGRES_PASSWORD=dev \
    -e POSTGRES_DB=syva_cp \
    -p 5432:5432 \
    docker.io/library/postgres:16

export SYVA_CP_DATABASE_URL=postgres://postgres:dev@localhost:5432/syva_cp

# Run migrations + start the server
cargo run --bin syva-cp
```

In another shell:

```sh
# Health endpoint
curl -s http://localhost:9092/healthz
# ready

# Metrics
curl -s http://localhost:9092/metrics | grep syva_cp_

# gRPC — create, get, list a team
grpcurl -plaintext -d '{"name":"payments","display_name":"Payments Team"}' \
    localhost:50051 syva.control.v1.TeamService/CreateTeam
grpcurl -plaintext -d '{"name":"payments"}' \
    localhost:50051 syva.control.v1.TeamService/GetTeam
grpcurl -plaintext -d '{"limit":50}' \
    localhost:50051 syva.control.v1.TeamService/ListTeams
```

## Tests

`#[sqlx::test]` creates a freshly-migrated database per test. A
running Postgres plus a `DATABASE_URL` pointing at it are required:

```sh
DATABASE_URL=postgres://postgres:dev@localhost:5432/syva_cp \
    cargo test -p syva-cp
```

## Write discipline

All mutating database writes go through `TransactionalWriter` under
`src/write/`. Writes outside this module fail CI via the
`check-write-discipline` xtask:

```sh
cargo run -p xtask -- check-write-discipline
```

The check is documented in ADR 0003 Rule 6 and wired into the Linux
CI job ahead of the workspace build so violations fail fast.

## E2E Smoke Test (Session 2)

```bash
# 1. Start postgres
docker run -d --name syva-cp-pg \
    -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=syva_cp \
    -p 5432:5432 postgres:16
sleep 2

# 2. Run syva-cp
export SYVA_CP_DATABASE_URL=postgres://postgres:dev@localhost:5432/syva_cp
cargo run --bin syva-cp &
sleep 2

# 3. Create a team
grpcurl -plaintext -d '{"name":"payments","display_name":"Payments"}' \
    localhost:50051 syva.control.v1.TeamService/CreateTeam
# returns team JSON; note the id as $TEAM_ID

# 4. Create a zone
grpcurl -plaintext -d "{
    \"team_id\":\"$TEAM_ID\",
    \"name\":\"api-prod\",
    \"policy_json\":\"{\\\"allowed_zones\\\":[]}\"
}" localhost:50051 syva.control.v1.ZoneService/CreateZone
# returns zone JSON with version=1; note the id as $ZONE_ID

# 5. Update the zone (new policy version)
grpcurl -plaintext -d "{
    \"zone_id\":\"$ZONE_ID\",
    \"if_version\":1,
    \"policy_json\":\"{\\\"allowed_zones\\\":[\\\"db\\\"]}\"
}" localhost:50051 syva.control.v1.ZoneService/UpdateZone
# returns zone with version=2 and new_policy with version=2

# 6. Get zone history
grpcurl -plaintext -d "{\"zone_id\":\"$ZONE_ID\"}" \
    localhost:50051 syva.control.v1.ZoneService/GetZoneHistory
# returns 2 entries (version 1 and 2)

# 7. Delete (drain mode)
grpcurl -plaintext -d "{
    \"zone_id\":\"$ZONE_ID\",
    \"if_version\":2,
    \"drain\":true
}" localhost:50051 syva.control.v1.ZoneService/DeleteZone
# returns zone with status='draining'

# Clean up
kill %1
docker rm -f syva-cp-pg
```

### Installing grpcurl

```bash
# macOS
brew install grpcurl

# Linux
curl -L https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_x86_64.tar.gz \
  | tar xz -C /tmp && sudo mv /tmp/grpcurl /usr/local/bin/
```
