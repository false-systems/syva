# API Compatibility Policy

## Source Of Truth

The canonical Syva v0.2 control API is the local protobuf/gRPC API:

```text
syva.core.v1
```

The REST API is partial and documented separately in
`docs/api/syva-api.openapi.yaml`. `syvactl` is an operator convenience client
over the gRPC API, not a second source of truth. Its command compatibility
surface is documented in `docs/api/syvactl-command-contract.md`.

## Versioning

- gRPC API package: `syva.core.v1`.
- REST API path prefix: `/v1`.
- CLI: `syvactl`, with the draft command contract `syvactl/v0.1`.

## v0.2.x Compatibility Expectations

For v0.2 patch releases:

- Do not reuse or change existing protobuf field numbers.
- Do not rename existing RPCs.
- Do not change `AttachContainer` or `DetachContainer` generation semantics.
- Do not change existing `ok: false` versus gRPC status behavior without an
  explicit release note.
- New optional protobuf fields are allowed.
- New RPCs are allowed if additive.
- REST additions are allowed if OpenAPI is updated.
- Machine-readable CLI output should use `--format json`.
- Stable `syvactl` command names, global flags, JSON top-level keys, and
  exit-code categories should follow the current command contract.
- OpenAPI docs must match implemented REST endpoints.

## Breaking Changes

Breaking changes require at least one of:

- a protobuf package/version bump,
- an explicit release note and migration note,
- compatibility tests or oracle expectations updated in the same change.

Examples of breaking changes:

- changing protobuf field numbers or meanings,
- removing an RPC,
- changing generation semantics,
- changing a successful application-level rejection into a transport error
  without a compatibility note,
- changing JSON output intended for automation without a compatibility note.
- changing a stable `syvactl` command name, required positional argument,
  global flag, JSON top-level key, or exit-code category without a contract
  version bump.

## Documentation Requirements

Changes to the control surface should update:

- `syva-proto/proto/syva_core.proto`
- `docs/api/grpc.md`
- `docs/api/api-compatibility.md` if policy changes
- `docs/api/syva-api.openapi.yaml` for REST changes
- `docs/api/cli.md` for CLI changes
- `docs/api/syvactl-command-contract.md` for CLI compatibility changes

The `check-api-docs` and `check-openapi` guardrails are intentionally light:
they prevent missing or obviously stale API docs, but they are not a substitute
for review.
