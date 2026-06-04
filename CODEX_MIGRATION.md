# Syva v0.2 cleanup note

The v0.3 `syva-cp` control-plane experiment has been removed from the active
repository. Syva's active architecture is:

```text
syva-file ──┐
syva-k8s  ──┼── syva.core.v1 over Unix socket ──► syva-core ──► eBPF LSM hooks
syva-api  ──┘
```

Removed from the active workspace:

- `syva-cp`
- `syva-cp-client`
- `syva-core/src/cp_reconcile`
- `syva-proto/proto/syva_control.proto`
- `deploy/v0.3`
- legacy monolithic `syva`
- Postgres/sqlx CI requirements

Historical control-plane docs are archived under `docs/archive/`. They are kept
as context only and should not be treated as active architecture.

Current follow-up work:

1. Wire file/k8s pod/container watchers into `syva.core.v1 AttachContainer` and
   `DetachContainer`.
2. Change file identity from inode-only to `(dev, ino)`.
3. Add privileged Linux runtime load/attach blackbox verification.
4. Add Kubernetes finalizers/status/leader-election if the CRD adapter becomes
   production load-bearing.
