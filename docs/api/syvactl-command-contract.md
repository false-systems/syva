# syvactl Command Contract

Contract: `syvactl/v0.1`
Status: Draft
Source of truth: `syva.core.v1` gRPC API

This document defines the intended operator-facing command surface for
`syvactl`. It is a compatibility contract for command names, flags,
machine-readable output, and exit-code behavior. The gRPC/protobuf API remains
the canonical control API.

## Principles

1. `syvactl` is a thin local operator client over `syva.core.v1`.
2. `syvactl` is not a remote control plane.
3. gRPC/protobuf remains the canonical control API.
4. `syvactl` commands must not invent semantics that are not present in gRPC.
5. Declarative adapters remain the normal policy-management path.
6. `syvactl` writes are for local inspection, debugging, tests, break-glass,
   and targeted node-local operations.
7. Machine-readable JSON output is part of the compatibility surface.
8. Text output is for humans and may evolve more freely.
9. Exit-code behavior must be documented and stable.

## Global Options

Command shape:

```sh
syvactl [GLOBAL OPTIONS] <COMMAND>
```

Supported global options:

```sh
--socket <path>
```

Default:

```text
/run/syva/syva-core.sock
```

```sh
--format <text|json>
```

Default:

```text
text
```

Future global options should be added only when they are intended to be
implemented soon. Good candidates are:

```sh
--timeout <duration>
--verbose
--quiet
```

## Remote Operation

`syvactl/v0.1` is node-local.

The default and canonical transport is the local Unix socket exposed by
`syva-core` on the same node:

```text
/run/syva/syva-core.sock
```

Remote operation is not part of the `v0.1` contract.

Operators may run `syvactl` on a remote node through an external transport such
as SSH:

```sh
ssh node-a 'sudo syvactl status --format json'
```

This does not change the Syva API model. The command still executes on the node
and talks to the node-local Unix socket.

`syvactl/v0.1` does not define:

- direct TCP access to `syva-core`,
- remote gRPC endpoints,
- cluster-wide control,
- multi-node fanout,
- a central Syva control plane.

A future version may add an explicit SSH convenience mode, for example:

```sh
syvactl --ssh node-a status
```

If added, it must be specified as an operator transport wrapper around
node-local execution, not as a new remote Syva control API.

## Exit Codes

`syvactl/v0.1` uses these exit-code categories:

```text
0  success / applied / unchanged / read command succeeded
1  domain-level rejection, such as stale generation, conflict, zone not found, or server contract denial
2  invalid CLI usage or argument parsing failure
3  connection or transport failure
4  server or internal failure
```

Rules:

- gRPC transport success with application-level `ok: false` must not exit `0`.
- Domain rejection must print a structured reason and exit non-zero.
- JSON output for application-level results must include `ok`, `operation`,
  `result`, and `reason` when relevant.
- Argument parsing errors use the CLI framework's usage error behavior and exit
  category `2`.

## Output Contract

JSON output is the stable scripting interface. Text output is human-readable and
may change as long as it preserves the important facts.

Common JSON envelope for write commands:

```json
{
  "operation": "attach_container",
  "ok": true,
  "result": "applied",
  "reason": null
}
```

For rejection:

```json
{
  "operation": "attach_container",
  "ok": false,
  "result": "stale",
  "reason": "existing generation is newer"
}
```

For read commands:

```json
{
  "operation": "status",
  "ok": true,
  "status": {}
}
```

Commands may add fields, but they must not remove or rename stable top-level
keys without a contract version bump.

## Command Groups

### 1. Status

Implemented:

```sh
syvactl status
```

RPC:

```text
Status
```

Output includes:

- health or attachment state exposed by the API,
- expected hooks when exposed,
- attached hooks when exposed,
- self-test state when exposed,
- degraded reasons when exposed,
- counters summary where available.

Recommended JSON shape:

```json
{
  "operation": "status",
  "ok": true,
  "health": {},
  "hooks": {},
  "selftests": {},
  "counters": {}
}
```

### 2. Zones

Implemented:

```sh
syvactl zones list
syvactl zones register <zone-id> [--type <type>]
syvactl zones remove <zone-id>
```

RPC:

```text
ListZones
```

RPCs:

```text
RegisterZone
RemoveZone
```

Semantics:

- `zone-id` is a logical Syva zone identifier.
- Path-like zone IDs follow the server contract.
- Remove output must clearly report whether the zone was removed or rejected.
- If active memberships block removal and the server exposes that reason, the
  CLI must print it clearly.
- `--force` should be added only if server behavior supports it; the client must
  not invent force semantics.

### 3. Host Paths

Implemented:

```sh
syvactl host-paths register <zone-id> <path>
```

RPC:

```text
RegisterHostPath
```

Semantics:

- The canonical group name is `host-paths`.
- `host-path` may be considered later as a compatibility alias.
- The path must be absolute unless the server contract permits otherwise.
- The command registers the path/inode mapping used for file enforcement.
- Output must include the zone, path, and result.
- The CLI must not log or print sensitive path content beyond the path supplied
  by the operator.

### 4. Communications

Implemented:

```sh
syvactl comms list
syvactl comms allow <source-zone> <target-zone>
syvactl comms deny <source-zone> <target-zone>
```

RPC:

```text
ListComms
```

RPCs:

```text
AllowComm
DenyComm
```

Canonical shape:

```sh
syvactl comms allow zone-a zone-b
syvactl comms deny zone-a zone-b
```

Short aliases such as `syvactl allow` and `syvactl deny` may be considered
later, but the canonical `v0.1` group is `comms`.

Output must clearly show:

```text
source-zone -> target-zone
result: applied
```

### 5. Containers / Memberships

Planned:

```sh
syvactl containers attach <container-id> <zone-id> --cgroup-id <id> [--generation <n>] [--metadata key=value ...]
syvactl containers detach <container-id> [--generation <n>]
```

RPCs:

```text
AttachContainer
DetachContainer
```

This group is higher risk than zones and communications because it directly
affects live membership. Declarative adapters are preferred for normal
operation.

Attach generation semantics:

- Omitted generation defaults to `0`.
- `0` means the caller has no source generation / ungenerated local update.
- `0` must not be treated as stale merely because existing generated state
  exists.
- Non-zero generations are monotonic.
- Stale non-zero attach returns a structured rejection.

Detach generation semantics:

- Omitted generation defaults to `0`.
- `0` means unconditional detach.
- Non-zero generation is checked.
- Stale non-zero detach returns a structured rejection.

Output must include:

- `container_id`,
- `zone_id`,
- `cgroup_id` for attach,
- `generation`,
- `result`,
- `reason` if rejected.

Examples:

```sh
syvactl containers attach ctr-123 zone-a --cgroup-id 12628
syvactl containers attach ctr-123 zone-a --cgroup-id 12628 --generation 42
syvactl containers detach ctr-123
syvactl containers detach ctr-123 --generation 42
```

### 6. Events

Implemented:

```sh
syvactl events --follow
```

RPC:

```text
WatchEvents
```

Semantics:

- `--follow` is required by the CLI because the event stream is a single
  ring-buffer consumer.
- JSON streaming output is newline-delimited JSON.
- Events are enforcement events. In v0.1, the exposed stream is denial-focused.
- Paths may be omitted or redacted depending on privacy settings and available
  kernel/user-space event fields.

Suggested JSON streaming format:

```json
{"event":"syva.enforcement.denied","hook":"file_open","errno":"EPERM"}
```

## syvactl/v0.1 Compatibility

Stable in `syvactl/v0.1`:

- command group names,
- required positional arguments,
- global flags,
- JSON output top-level keys,
- exit-code categories.

May evolve without a contract bump:

- human text formatting,
- additional JSON fields,
- additional optional flags,
- aliases.

Breaking changes require:

- a contract version bump,
- a release note,
- a migration note.

## Implementation Phases

### Phase 1 - Already Implemented

```sh
syvactl status
syvactl zones list
syvactl comms list
syvactl events --follow
```

### Phase 2A - Low-Risk Writes Implemented

```sh
syvactl zones register
syvactl zones remove
syvactl host-paths register
syvactl comms allow
syvactl comms deny
```

### Phase 2B - Membership Writes

```sh
syvactl containers attach
syvactl containers detach
```

Attach and detach require careful generation and cgroup identity semantics, so
they should come after the lower-risk write commands.
