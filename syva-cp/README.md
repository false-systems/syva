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
