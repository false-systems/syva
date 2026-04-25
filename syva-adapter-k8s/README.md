# syva-adapter-k8s

`syva-k8s` watches `SyvaZonePolicy` CRDs in one namespace and reconciles them
into zones in `syva-cp` for one configured team.

Start:

```bash
syva-k8s \
    --namespace syva-system \
    --cp-endpoint http://syva-cp.syva-system.svc:50051 \
    --team-id 00000000-0000-0000-0000-000000000000
```

Notes:
- The CRD remains the source of truth; direct API edits will be overwritten by the watcher.
- Pod annotation / container membership sync is deferred until `ContainerService` exists end to end.
