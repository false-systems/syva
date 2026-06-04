# syva-adapter-k8s

`syva-k8s` watches `SyvaZonePolicy` CRDs in one namespace and reconciles them
into the local `syva-core` Unix-socket API.

Start:

```bash
syva-k8s \
  --namespace syva-system \
  --core-socket /run/syva/syva-core.sock
```

Notes:

- The CRD is the source of truth for zone policy on the node.
- The adapter reconciles zones and mutual communication pairs.
- Automatic pod/container membership watching is not wired yet. Pods must be
  attached through `syva.core.v1 AttachContainer` until that integration lands.
