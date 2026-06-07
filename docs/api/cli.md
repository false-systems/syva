# syvactl

`syvactl` is a thin local operator client over the `syva.core.v1` gRPC API. It
does not run a daemon, manage policy, or replace adapters. It is for inspecting
and operating the local `syva-core` instance through the same Unix socket used
by adapters.

Default socket:

```text
/run/syva/syva-core.sock
```

Global flags:

```sh
syvactl --socket /run/syva/syva-core.sock --format text
syvactl --socket /run/syva/syva-core.sock --format json
```

Use `--format json` for automation.

## Commands

### syvactl status

Calls gRPC `Status`.

```sh
syvactl status
syvactl status --format json
```

Shows attachment state, zone count, active memberships, uptime, max zone
capacity, and per-hook counters.

### syvactl zones list

Calls gRPC `ListZones`.

```sh
syvactl zones list
syvactl zones list --format json
```

### syvactl comms list

Calls gRPC `ListComms`.

```sh
syvactl comms list
syvactl comms list --zone zone-a
syvactl comms list --format json
```

### syvactl events --follow

Calls gRPC `WatchEvents`.

```sh
syvactl events --follow
syvactl events --follow --format json
```

The event stream consumes the existing single-consumer ring buffer. If another
client has already taken the stream, the command reports the gRPC error from
`syva-core`.

## Relationship To Other Surfaces

- `syva-core status` now tries the same gRPC `Status` RPC first and falls back
  to pinned BPF counters only when the socket is unavailable.
- `syva-file` and `syva-k8s` are reconciling adapters, not inspection tools.
- `syva-api` is a partial REST surface for zones and health. The gRPC API
  remains canonical for control semantics.

## Write Commands

This initial `syvactl` surface is intentionally read-only:

```text
status
zones list
comms list
events --follow
```

Write commands such as zone registration, attach/detach, and communication
updates should be added only as thin wrappers over existing gRPC requests, with
JSON output for automation and no duplicated adapter logic.
