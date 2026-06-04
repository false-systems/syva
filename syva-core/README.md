# syva-core

`syva-core` is the node-local Linux/eBPF enforcement engine. It loads and
attaches Syva's eBPF LSM programs, owns the BPF maps, runs startup self-tests,
serves health/metrics, and exposes the local `syva.core.v1` Unix-socket API.

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

Membership reconciliation lives in `src/membership.rs` and is idempotent,
generation-aware, conflict-aware, and explicit about BPF map update intent.
