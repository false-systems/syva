# Changelog

## v0.4.0 — 2026-06-13

The first complete release. Everything below is proven by privileged kernel
gates (`make verify-*`); the full evidence run lives in
[docs/release/v0.4.0-runtime-verification.md](docs/release/v0.4.0-runtime-verification.md).

### Enforcement

- **Network lock**: an Isolated zone (the default) reaches loopback only —
  `socket_connect` / `socket_sendmsg` / `socket_bind` deny non-loopback
  AF_INET/AF_INET6 operations. Per-zone `network_mode` switch
  (Isolated/Bridged/Host). *(gate: verify-network-lock)*
- **Egress CIDR allowlists**: a locked zone may reach allowlisted IPv4/IPv6
  CIDRs, optionally pinned to a destination port. *(verify-egress-cidr)*
- **Cross-zone TCP by pod IP**: exact IPv4 destination IPs map to zones; the
  zone-pair rule (`AllowComm`) applies even for network-open zones and takes
  precedence over the CIDR allowlist. *(verify-cross-zone-tcp, including a
  Bridged-caller scenario)*
- **Composite `(dev, ino)` file identity**: cross-filesystem inode collisions
  no longer cause zone confusion. The kernel-side device is learned through
  an in-kernel inode probe (correct on btrfs, where `stat` lies); the startup
  self-test validates the full file→inode→superblock chain plus the dev
  encoding. *(verify-inode-identity)*
- **Cgroup-escape detection** (best-effort fentry; detection, not
  prevention). *(verify-cgroup-escape)*
- **Audit mode** (`--mode audit`): would-deny recorded, operation proceeds —
  the observe-only rollout path. *(verify-audit-mode)*

### Observability — deny events that explain themselves

- Kernel events carry the process `comm` and, for socket hooks, the
  destination address + port.
- The core owns the event drain (always-on pump): every event is enriched —
  zone **names**, registered host **path** + inode for file denials,
  `dst_ip:port` for network denials, a decision label, and stable
  `what_failed` / `why_it_matters` / `possible_causes` reason fields — and
  fanned out to the `WatchEvents` stream (multiple concurrent subscribers),
  the core log (constant event names, JSON-shippable), and per-zone metrics
  (`syva_zone_deny_total{zone,hook}`). Deny events are never sampled.
  *(gate: verify-events)*
- `syvactl events --follow`: compact human projection; `--format json` for
  full fidelity.

### Install

- **One-apply Kubernetes install**: `kubectl apply -f deploy/k8s/` (CRD,
  namespace + RBAC, DaemonSet: core + adapter per node), proven on a live
  k3s cluster including a real-container denial through the deployed
  DaemonSet. *(verify-deployment)*
- Kubernetes pod membership by annotation (`syva.false.systems/zone`),
  cluster-wide pod-IP→zone reconciliation with IP-reuse safety.

### Project

- Dual-licensed **MIT OR Apache-2.0**.
- Kernel floor pinned: **Linux ≥ 5.10**.
- Eleven privileged verification gates; `make ci` reproduces CI locally.

### Upgrade notes

- `INODE_ZONE_MAP`'s key grew 8 → 16 bytes and the enforcement event struct
  48 → 64 bytes: core, eBPF object, and CLI binaries must ship together
  (they do — same tree and images). If an older core crashed without
  unpinning, clear `/sys/fs/bpf/syva`; the new core refuses stale pins and
  prints this instruction.
- `WatchEvents` is now a broadcast: multiple subscribers are supported and
  `follow=false` returns an empty stream (there is no drainable backlog).

### Known limits (honest)

- `/proc` and `/sys` coverage incomplete; cgroup escape detected, not
  prevented; btrfs sibling subvolumes of one filesystem share a superblock
  dev; IPv6 pod-IP mapping not implemented; K8s adapter
  status/finalizers/leader election pending. See README → Limitations.

## v0.3.0 — 2026-06-08

Kubernetes membership watcher: annotation-based pod→zone attachment via
`syva-k8s`, proven by `verify-k8s-membership`. v0.2 kernel-enforcement
contract unchanged.

## v0.2.x — 2026-06

Local enforcement core: zones, membership, file/exec/mmap/ptrace/signal/Unix
hooks, health/metrics, file + k8s + REST adapters, Lima development
deployment, runtime verification gates.
