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
- Only pods scheduled to `--node-name` are reconciled.
- Running containers are attached only after the adapter resolves a real
  container runtime ID and host cgroup-v2 inode from host `/proc` and
  `/sys/fs/cgroup`.
- If cgroup resolution fails, the pod is not attached; the adapter logs the
  error and increments `syva_k8s_reconcile_errors_total`.
- Metrics are exposed on `--metrics-listen` (default `0.0.0.0:9092`) at
  `/metrics`.

Privileged end-to-end proof:

```bash
sudo -E make verify-k8s-membership
```

The proof expects `kubectl` to target a single-node Kubernetes cluster on the
same Linux host/VM. It creates an annotated pod, waits for `AttachContainer`,
verifies `syva_k8s_memberships_active 1`, proves a zone-a read succeeds, proves
a zone-b read fails with `EPERM`, and asserts `file_open deny_delta=1`.
