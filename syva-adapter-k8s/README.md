# syva-adapter-k8s

`syva-k8s` watches `SyvaZonePolicy` CRDs in one namespace and reconciles them
into the local `syva-core` Unix-socket API.

Start:

```bash
syva-k8s \
  --namespace syva-system \
  --core-socket /run/syva/syva-core.sock \
  --node-name "$NODE_NAME" \
  --host-proc /host/proc \
  --host-cgroup /sys/fs/cgroup
```

Notes:

- The CRD is the source of truth for zone policy on the node.
- The adapter reconciles zones and mutual communication pairs.
- Pod membership uses the annotation `syva.false.systems/zone: <zone>`.
- Only pods scheduled to `--node-name` are reconciled; the pod watch itself is
  scoped to the node with a `spec.nodeName` field selector.
- Running containers are attached only after the adapter resolves a real
  container runtime ID and host cgroup-v2 inode from host `/proc` and
  `/sys/fs/cgroup`. The resolved path is truncated at the container scope
  component, so nested sub-cgroups resolve to the scope enforcement keys on.
- If cgroup resolution fails, the pod is not attached; the adapter logs the
  error and increments `syva_k8s_reconcile_errors_total`.
- Attach/detach generations are seeded from the clock at startup so the core's
  stale-generation fencing survives adapter restarts. Unconfirmed attaches are
  rolled back and retried on the next pod event; unconfirmed detaches are
  retried with every event batch until the core acknowledges them.
- If the pod membership watcher fails, the adapter exits (the DaemonSet
  restarts it) instead of running without membership reconciliation.
- Metrics are exposed on `--metrics-listen` (default `0.0.0.0:9092`) at
  `/metrics`; the DaemonSet binds it to the pod IP.

Privileged end-to-end proof:

```bash
sudo -E make verify-k8s-membership
```

The proof expects `kubectl` to target a single-node Kubernetes cluster on the
same Linux host/VM. It creates an annotated pod, waits for `AttachContainer`,
verifies `syva_k8s_memberships_active 1`, proves a zone-a read succeeds, proves
a zone-b read fails with `EPERM`, and asserts `file_open deny_delta=1`.
