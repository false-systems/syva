# syva-core

`syva-core` is the node-local Linux/eBPF enforcement engine. It loads and
attaches Syva's six supported eBPF LSM programs, owns the BPF maps, runs startup
self-tests, serves health/metrics, and exposes the local `syva.core.v1`
Unix-socket API.

Start on Linux with BPF privileges:

```bash
syva-core --socket-path /run/syva/syva-core.sock
```

Adapters connect to that socket and call `RegisterZone`, `RegisterHostPath`,
`AllowComm`, `AttachContainer`, and related RPCs. The core does not know about
teams, clusters, or an external control plane.

Health states:

- `healthy`: BPF is attached and no active degradation is known.
- `degraded`: enforcement is active but confidence is reduced, for example
  fail-open hook counters or membership conflicts.
- `unsafe`: BPF is not attached or startup self-tests failed.

Known v0.2 gap: cgroup movement / zone escape protection is not enforced
through BPF-LSM because `cgroup_attach_task` is not a BPF-LSM hook on supported
mainline kernels.

Membership reconciliation lives in `src/membership.rs` and is idempotent,
generation-aware, conflict-aware, and explicit about BPF map update intent.
`AttachContainer` returns application-level `ok=false` for unknown zones, stale
generations, and conflicts; validation failures may use gRPC
`InvalidArgument`, and core/BPF failures may use gRPC `Internal`. Generation
`0` means an ungenerated local attach and does not rewind stored non-zero
generations on metadata-only refresh. `DetachContainer` generation `0` is an
unconditional detach.
