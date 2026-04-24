# syva-core

Kernel enforcement engine for Syva. `syva-core` owns the in-process
`ZoneRegistry` and `EnforceEbpf` state and exposes a local gRPC surface for
adapters.

## Operational Modes

`syva-core` runs in one of two modes:

### Legacy Mode

Adapters (`syva-adapter-file`, `syva-adapter-k8s`, `syva-adapter-api`) connect
to the local gRPC surface and push zones directly.

Start:

```bash
syva-core --socket-path /run/syva/syva-core.sock
```

### CP Mode

`syva-core` connects to a remote `syva-cp`, registers as a node, subscribes to
assignment updates, and reconciles its BPF maps to match desired state. Legacy
adapters can still push to the local gRPC surface in addition.

Start:

```bash
syva-core \
    --cp-endpoint http://syva-cp.cluster.local:50051 \
    --node-name "$(hostname)" \
    --node-labels "tier=prod,region=eu" \
    --fingerprint-path /etc/machine-id \
    --node-id-path /var/lib/syva/node-id
```

The node ID is persisted to `--node-id-path` so restarts appear as
re-registration of the same node rather than fresh registration.
