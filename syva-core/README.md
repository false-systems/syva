# syva-core

Kernel enforcement engine for Syva. After session 4b, `syva-core` has one
ingestion path only: it connects to `syva-cp`, registers as a node, subscribes
to `NodeAssignmentUpdate`, and reconciles its BPF maps to the desired state.

## CP Mode

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

There is no local adapter-facing gRPC surface anymore. Adapters now push zones
to `syva-cp` directly.
