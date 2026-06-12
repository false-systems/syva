# syva.core.v1 gRPC API

`syva.core.v1` is the canonical Syva v0.2 control API. It is served by
`syva-core` on a node-local Unix socket, default:

```text
/run/syva/syva-core.sock
```

Intended users are local adapters, `syvactl`, and node-local automation. This is
not a remote control-plane API.

For the operator CLI command compatibility surface, see
[`syvactl-command-contract.md`](syvactl-command-contract.md). `syvactl` maps to
the RPCs documented here and must not invent separate control semantics.

## Error Model

Syva uses two layers of errors:

- gRPC status errors for invalid requests, transport failures, missing objects
  where the RPC contract says so, and internal BPF/core failures.
- Application responses with `ok: false` where the v0.2 API intentionally keeps
  the RPC transport successful but rejects the requested state transition.

Common gRPC statuses:

- `InvalidArgument`: malformed request, empty required names, invalid cgroup ID.
- `NotFound`: unknown zone in selected RPCs.
- `Internal`: BPF map failures or unexpected core errors.
- `Unavailable`: event stream already taken or socket unavailable.

Kernel denials are not gRPC errors. A denied workload operation is returned to
the workload as `EPERM` and appears through counters or `WatchEvents`.

## RPCs

### RegisterZone

Registers or updates a local zone and optional policy.

Request:

- `zone_name`: logical zone identifier.
- `policy.host_paths`: host paths whose inodes should belong to the zone.
- `policy.allowed_zones`: currently reconciled by adapters into `AllowComm`.
- `policy.allow_ptrace`: sets ptrace policy capability.
- `policy.zone_type`: standard or privileged. Isolated currently maps to the
  standard local enforcement type.
- `policy.network_mode`: the per-zone network lock/open switch (`NetworkMode`).
  `NETWORK_MODE_ISOLATED` (default, `0`) is network-locked — the zone reaches
  loopback only (`socket_connect`/`socket_sendmsg`/`socket_bind` deny
  non-loopback). `NETWORK_MODE_BRIDGED` / `NETWORK_MODE_HOST` open network
  access.
- `policy.allowed_egress_cidrs`: egress CIDR allowlist for a network-locked
  zone. Each entry is an IPv4 or IPv6 CIDR, or a bare address treated as `/32`
  for IPv4 and `/128` for IPv6. A bare CIDR allows any destination port
  (`10.0.0.0/8`, `2001:db8::/32`); IPv4 may append a port as `CIDR:port`
  (`10.0.0.0/8:5432`); IPv6 ports require brackets (`[2001:db8::/32]:443`).
  A locked zone may still reach destinations these prefixes cover when the
  optional port matches. Invalid entries are skipped with a warning. Limitation:
  one exact CIDR prefix stores either one port or any-port; repeating the same
  exact prefix with another port overwrites the previous value.

Response:

- `zone_id`: non-zero local BPF zone ID.

Errors:

- `InvalidArgument` for invalid zone names.
- `Internal` for BPF/core failures.

### RemoveZone

Removes a zone or marks it draining.

Request:

- `zone_name`: registered zone name.
- `drain`: if true, mark active zones draining and remove once memberships are
  gone; if false, reject active zones.

Response:

- `ok`: whether the remove/drain operation was accepted.
- `message`: reason when `ok: false`.

Errors:

- `InvalidArgument` for invalid zone names.
- `NotFound` if the zone is absent.

### ListZones

Lists registered zones.

Response items:

- `name`
- `zone_id`
- `state`: `pending`, `active`, or `draining`.
- `containers_active`

### AttachContainer

Attaches a container/cgroup membership to a zone and produces a BPF membership
map update.

Request:

- `container_id`: stable local container/workload identifier.
- `zone_name`: target zone.
- `cgroup_id`: non-zero cgroup ID observed by the adapter.
- `pod_namespace`, `pod_name`, `pod_uid`: optional Kubernetes identity.
- `source`: adapter/source label such as `file`, `kubernetes`, or `api`.
- `generation`: monotonic source generation.

Generation semantics:

- generation `0` means the caller has no source generation; it must not be
  treated as stale only because generated state already exists.
- Non-zero generations are monotonic.
- Stale non-zero updates return `ok: false`.
- Metadata-only reattach for the same container, zone, and cgroup is
  idempotent and preserves the stored non-zero generation.

Response:

- `ok`
- `message`

Errors and application failures:

- Invalid container IDs or zero cgroup IDs return gRPC `InvalidArgument`.
- Unknown zone returns `ok: false`.
- Stale generation returns `ok: false`.
- Conflicting assignment returns `ok: false`.
- BPF/core failures return gRPC `Internal` and degrade health.

### DetachContainer

Removes a container/cgroup membership.

Request:

- `container_id`
- `source`
- `generation`

Generation semantics:

- generation `0` means unconditional detach for callers that do not track source
  revisions.
- Non-zero generation is checked against known state.
- Stale non-zero detach returns `ok: false`.

Response:

- `ok`
- `message`

Errors:

- Missing container ID returns gRPC `InvalidArgument`.
- BPF cleanup failure degrades health and is surfaced through health/metrics.

### AllowComm

Allows communication between two registered zones. The current implementation
writes both directions.

Request:

- `zone_a`
- `zone_b`

Semantics:

- Empty names return gRPC `InvalidArgument`.
- `zone_a == zone_b` is an idempotent no-op with `ok: true`.
- Unknown zones return gRPC `NotFound`.
- BPF/core failures return gRPC `Internal`.

### DenyComm

Removes an allowed communication pair between two registered zones.

Request:

- `zone_a`
- `zone_b`

Errors:

- Empty names return gRPC `InvalidArgument`.
- Unknown zones return gRPC `NotFound`.
- BPF/core failures return gRPC `Internal`.

### ListComms

Lists allowed zone communication pairs.

Request:

- `zone_name`: optional filter. Empty returns all pairs.

Errors:

- Unknown filter zone returns gRPC `NotFound`.

### SetIpZone

Maps one exact IPv4 pod IP to a zone for socket-level zone-pair enforcement.
This is used by `syva-k8s` from its cluster-wide pod-IP watch; direct callers
must remove stale mappings promptly when an IP is reused.

Request:

- `ip`: IPv4 address in dotted decimal form. IPv6 IP-to-zone enforcement is not
  implemented yet and returns `InvalidArgument`.
- `zone_name`: registered zone that owns this pod IP.

Response:

- `ok`: true when the BPF map update completed.

Errors:

- Invalid IPv4 or zone-name syntax returns gRPC `InvalidArgument`.
- Unknown zone returns gRPC `NotFound`.
- BPF/core failures return gRPC `Internal`.

### RemoveIpZone

Removes one exact IPv4 pod-IP mapping. Removing an absent IP is idempotent.

Request:

- `ip`: IPv4 address in dotted decimal form.

Response:

- `ok`: true when the remove operation completed.

Errors:

- Invalid IPv4 syntax returns gRPC `InvalidArgument`.
- BPF/core failures return gRPC `Internal`.

### RegisterHostPath

Registers one host path or a recursive set of path inodes into
`INODE_ZONE_MAP`.

Request:

- `zone_name`
- `path`
- `recursive`

Response:

- `inodes_registered`

Notes:

- File paths may be sensitive; Syva does not log file paths in denial events by
  default.
- The inode map is keyed by composite `(dev, ino)` identity. The kernel-side
  device (`s_dev`) is resolved through an in-kernel probe at registration
  time, so registration requires the `file_open` hook to be attached (it is —
  hooks attach before the gRPC server starts). Filesystems whose subvolumes
  share a superblock (btrfs) still alias same-ino files within one filesystem.

### Status

Returns the gRPC status snapshot used by `syvactl status` and preferred by
`syva-core status`.

Response:

- `attached`
- `zones_active`
- `containers_active`
- `uptime_secs`
- `hooks[]`: per-hook `allow`, `deny`, `error`, `lost` counters.
- `max_zones`

For full enforcement confidence state, use `/healthz` and `/metrics` on the
health server.

### WatchEvents

Streams enforcement deny events from the existing ring buffer.

Request:

- `follow`: if true, continue streaming future events after draining current
  events; if false, return after the current drain.

Response stream:

- `timestamp_ns`
- `hook`
- `zone_id`
- `target_zone_id`
- `pid`
- `comm`
- `inode`
- `context`

Limitations:

- The event ring buffer is single-consumer. If another client has taken it,
  `WatchEvents` returns gRPC `Unavailable`.
- Rich per-denial events are best-effort operational evidence; counters remain
  the low-cardinality monitoring signal.
