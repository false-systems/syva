# syvactl

`syvactl` is a thin local operator client over the `syva.core.v1` gRPC API. It
does not run a daemon, manage policy, or replace adapters. It is for inspecting
and operating the local `syva-core` instance through the same Unix socket used
by adapters.

The versioned command compatibility contract is
[`syvactl-command-contract.md`](syvactl-command-contract.md). This guide shows
current usage; the contract defines stable command names, flags, JSON output,
and exit-code categories.

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

### syvactl zones register

Calls gRPC `RegisterZone`.

```sh
syvactl zones register zone-a
syvactl zones register zone-a --type privileged --format json
```

Supported `--type` values are `standard`, `privileged`, and `isolated`. The
server remains responsible for accepting or rejecting the requested type.

### syvactl zones remove

Calls gRPC `RemoveZone` with `drain=false`.

```sh
syvactl zones remove zone-a
syvactl zones remove zone-a --format json
```

If the server rejects removal, for example because active memberships remain,
the command prints the server reason and exits with the domain-rejection code.

### syvactl host-paths register

Calls gRPC `RegisterHostPath`.

```sh
syvactl host-paths register zone-a /srv/zone-a/secret.txt
syvactl host-paths register zone-a /srv/zone-a/secret.txt --format json
```

This registers the path/inode mapping used by file enforcement. The command
prints only the path supplied by the operator.

### syvactl comms list

Calls gRPC `ListComms`.

```sh
syvactl comms list
syvactl comms list --zone zone-a
syvactl comms list --format json
```

### syvactl comms allow

Calls gRPC `AllowComm`.

```sh
syvactl comms allow zone-a zone-b
syvactl comms allow zone-a zone-b --format json
```

### syvactl comms deny

Calls gRPC `DenyComm`.

```sh
syvactl comms deny zone-a zone-b
syvactl comms deny zone-a zone-b --format json
```

### syvactl events --follow

Calls gRPC `WatchEvents`. `--follow` is **required**: `WatchEvents` is a live
stream and syva-core hands out a single ring-buffer consumer, so a non-follow
call would drain and release it. `syvactl events` without `--follow` exits with
an error rather than consuming the stream.

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

`syvactl` now includes the Phase 2A low-risk local write commands. The current
surface is:

```text
status
zones list
zones register
zones remove
host-paths register
comms list
comms allow
comms deny
events --follow
```

Container attach/detach is intentionally not implemented yet. Those commands
directly affect live membership and need the stricter generation/cgroup handling
defined in the command contract.
