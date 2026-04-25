# syva-adapter-file

`syva-file` reconciles a directory of TOML policies into zones in `syva-cp`.
Each `*.toml` filename becomes the zone name within one configured team.

Start:

```bash
syva-file \
    --policy-dir /etc/syva/policies \
    --cp-endpoint http://syva-cp.syva-system.svc:50051 \
    --team-id 00000000-0000-0000-0000-000000000000
```

Notes:
- `verify` still works as a dry-run parser and validator.
- Reconcile is polling-based in session 4b.
- Containerd watcher / container membership sync is deferred until `ContainerService` exists end to end.
