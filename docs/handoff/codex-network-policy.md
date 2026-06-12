# Codex Implementation Brief — Syva Network Policy (Phase 2)

You are **Codex**, an autonomous coding agent working in the `syva` repository
(`/Users/yair/projects/syva`, Rust + eBPF/BPF-LSM kernel enforcement). Your job
is to implement **two network-policy features** on top of the already-merged
egress lockdown, to the same bar as everything else in this repo: **every
enforcement claim is proven by a privileged kernel gate, and no capability is
ever over-claimed in docs.**

Read this entire brief before writing code. Then read the repo's own rules.

---

## 0. Operating doctrine (non-negotiable — this is how this repo works)

1. **Read first.** Before touching anything, read `CLAUDE.md` (active
   architecture + the exact map/hook list), `AGENT.md` (working practices), and
   `SKILLS.md` (security-model invariants). They override your priors.
2. **Proof, not assertion.** A feature is not done when it compiles. It is done
   when a **privileged Lima gate** loads real eBPF, exercises the kernel, and
   prints attributable evidence (`EPERM`, `deny_delta=1`, a metric delta). If
   you cannot write a gate that *fails when the feature is broken*, you do not
   understand the feature yet.
3. **Honesty over completeness.** Document residual holes in the PR, the code,
   and `CLAUDE.md` "Known Limits" rather than papering over them. The
   release-doc guardrail (`cargo run -p xtask -- check-release-docs`) enforces
   parts of this; the culture enforces the rest. Do not write "the network is
   closed." Write exactly what is and isn't enforced, with caveats.
4. **Apply the methodologies below** (eBPF / rust-infra / kubernetes / eval).
   They are distilled from the skills this repo was built with. Follow them.
5. **One feature, one branch, one PR, fully green.** Never stack unproven work.

### Skill methodologies to apply (you must follow these)

- **eBPF.** The verifier rejects unbounded loops, large stack (>512B), and
  unproven pointer reads. Use `bpf_probe_read_kernel` via the existing
  `read_kernel_u16/u32/u64` helpers; never deref raw kernel pointers. Keep hot
  paths to a few map lookups. Prefer `LpmTrie` for prefix/CIDR matching and
  `HashMap` for exact keys. Resolve kernel struct offsets from **BTF at
  startup** (see `btf.rs` / `OFFSET_DEFS` in `syva-core/src/ebpf.rs`) — never
  hardcode an offset that varies by kernel. eBPF bytecode is little-endian
  (`bpfel`); reason about **memory byte order** when keys cross the
  eBPF/userspace boundary (the egress-CIDR key is the worked example — see §1).
- **rust-infra.** Validate at the gRPC boundary and map errors to `Status`;
  keep the tokio/tonic patterns already in `syva-core`. Best-effort, optional
  subsystems must degrade (log + metric) without taking down enforcement (see
  the cgroup-escape detector for the pattern).
- **kubernetes.** The adapter (`syva-k8s`) is node-local and declarative. It
  already has cluster-wide `pods: get/list/watch` RBAC and a node-scoped
  membership watcher. For IP→zone you will add a **cluster-wide** pod-IP watch
  (a pod on node A may connect to a pod on node B, so every node needs the full
  IP→zone view). Watch `status.podIP`, skip host-network pods (no distinct IP),
  and handle IP churn (reuse on restart) by keying reconciliation on pod UID.
- **eval.** Layer your verification: unit tests for pure logic (CIDR/port
  parsing), then a **privileged integration gate** that is the ground truth.
  Gates are numbered/named `verify-*`, fail red (never skip silently) when
  prerequisites are missing, and print a declared contract before running. The
  gate *is* the spec.

---

## 1. Current state you are extending (study this — it is the template)

The network lock is already merged. There are **nine BPF-LSM hooks**; the three
network ones live in `syva-ebpf/src/socket_guard.rs`:

- `socket_connect` — outbound TCP / connected UDP
- `socket_sendmsg` — outbound unconnected UDP (`sendto`)
- `socket_bind` — non-loopback bind (local listener)

Decision shape (all three share it): a non-global zoned caller whose zone lacks
`POLICY_FLAG_ALLOW_NETWORK` is **network-locked** → non-loopback AF_INET/AF_INET6
ops are denied; loopback / NULL / non-IP families / network-open zones pass.
`gate_remote(addr_ptr, caller_zone, hook, egress)` is the choke point;
`network_locked_caller` resolves whether the caller is locked.

The **egress CIDR allowlist** (your direct precedent) is:
- Map `EGRESS_CIDR_MAP: LpmTrie<EgressCidrKey, u8>` in `syva-ebpf/src/main.rs`.
- Key `EgressCidrKey { zone_id: u32, addr: u32 }` in `syva-ebpf-common`. `addr`
  is the IPv4 in **network byte order**: eBPF reads raw `sin_addr` via
  `read_kernel_u32`; userspace writes `u32::from(ip).to_be()`. Both land as
  network-order bytes in memory, which is what the kernel LPM trie compares.
  `zone_id` is matched exactly (prefix always covers its 32 bits). Lookup uses
  `Key::new(64, ...)`; insert uses `Key::new(32 + cidr_bits, ...)`.
- `socket_connect`/`socket_sendmsg` call `egress_cidr_allows(zone, addr)` before
  denying; `socket_bind` does **not** (it governs local listeners).
- Userspace: `set_zone_egress_cidrs` / `remove_zone_egress_cidrs` /
  `parse_ipv4_cidr` in `syva-core/src/ebpf.rs`; sourced from
  `network.allowed_egress`; proto field `ZonePolicy.allowed_egress_cidrs = 6`;
  wired through file adapter (TOML), k8s CRD (`network.allowedEgress`), REST.
- Gate `verify-egress-cidr` → `syva-core/tests/integration_egress_cidr.rs`.

The gate pattern (copy it): spawn a core, register a zone, create a cgroup-v2
leaf, attach it via `AttachContainer`, run a workload inside the cgroup
(`echo $$ > cgroup.procs && exec python3 -c …`), and assert kernel verdicts +
per-hook `deny` counter deltas read over the `Status` RPC. `host_egress_ip()`
(UDP-connect trick) yields a non-loopback host IP; `192.0.2.1` (TEST-NET-1) is a
guaranteed-not-the-host blocked target. Tests are `#[ignore]`d and driven by
`verify-*` → `xtask` → `make`.

---

## 2. FEATURE A — Port + IPv6 granularity for the egress allowlist

**Goal:** turn the IPv4-CIDR allowlist into real per-destination policy: support
`CIDR:port` and IPv6. Today an allowlist entry is `10.0.0.0/8` (any port, IPv4
only). After this feature an operator can write `10.0.0.0/8:5432`,
`2001:db8::/32`, and `2001:db8::/32:443`.

### A.1 Design

- **Port granularity.** Extend matching so an entry may pin a destination port.
  Keep it backward compatible: a bare CIDR means "any port". Options (pick and
  justify in the PR):
  - **Recommended:** make the LPM value carry the port. Change
    `EGRESS_CIDR_MAP` value from `u8` to a small struct `{ port: u16 }` where
    `port == 0` means "any". The hook reads `sin_port` (network order, offset 2
    in `sockaddr_in`) and, on a trie hit, allows iff `entry.port == 0 ||
    entry.port == dst_port`. This keeps the single-trie design. Limitation:
    one CIDR entry → one port (or any). If you need multiple ports for the same
    CIDR, the operator adds multiple entries with distinct CIDRs, OR you widen
    the value to a small fixed port set — **do not** silently support only one
    port without documenting it.
  - The hook still must do a single LPM lookup (hot path). Do the port compare
    in-kernel after the lookup; do not add a second map round-trip per packet
    for `sendmsg`.
- **IPv6.** IPv6 needs a separate LPM trie (`EGRESS_CIDR6_MAP`) keyed by
  `{ zone_id: u32, addr: [u8; 16] }` (network order, read as a 16-byte array via
  `bpf_probe_read_kernel::<[u8;16]>` from `sin6_addr` at offset 8). Prefix =
  `32 + cidr_bits` (0..=128). `gate_remote` must branch on `family`: AF_INET →
  v4 trie, AF_INET6 → v6 trie. Loopback `::1` is already allowed by the existing
  carve-out.
- **Parsing.** Replace `parse_ipv4_cidr` with a parser that returns a typed
  entry: `{ family, addr, prefix_bits, port: Option<u16> }`. Accept
  `A.B.C.D[/N][:P]`, `[v6]:P` or `v6/N` (be careful: `:` is ambiguous in IPv6 —
  require brackets for `[2001:db8::1]:443`, or only accept ports on the
  `CIDR:port` form for v4 and `CIDR%port` / a separate field for v6 — choose a
  syntax, document it, and unit-test every shape including rejects).

### A.2 Surface + wiring

- The source field stays `network.allowed_egress` (proto `allowed_egress_cidrs`,
  CRD `network.allowedEgress`, file TOML). No new proto field needed if entries
  are strings; the richer grammar lives in the string. (If you prefer a
  structured proto message, that is a breaking-ish change — prefer strings for
  v2, document the grammar in `docs/api/grpc.md`.)
- Update `set_zone_egress_cidrs` to populate both tries and carry ports.
- Skip-with-warning remains the rule for unparseable entries (never fail the
  whole zone).

### A.3 Gate — extend `verify-egress-cidr` (or add `verify-egress-policy`)

Prove, on the real kernel:
- `CIDR:port` — connect to the allowed IP on the **allowed port** succeeds
  (not `EPERM`); connect to the **same IP on a different port** is `EPERM`
  with `socket_connect deny_delta=1`.
- IPv6 — a locked zone allowed `<v6-cidr>` reaches a v6 destination in range
  (not `EPERM`) but is denied a v6 destination out of range (`EPERM`,
  `deny_delta=1`). Use a non-loopback IPv6 (e.g. a `::1`-adjacent ULA you add to
  `lo`/a dummy iface, or the host's v6 if present; if the Lima box has no IPv6,
  the gate must **fail red with a clear skip reason**, per doctrine — do not
  silently pass).
- Regression: the existing IPv4-any-port behavior still holds.

### A.4 Acceptance (Feature A)

- [ ] `cargo run -p xtask -- build-ebpf` green; verifier accepts both tries +
      the port compare.
- [ ] Unit tests for the parser cover v4/v6 × {bare, /N, :port} × rejects.
- [ ] `sudo -E make verify-egress-policy` (or extended `verify-egress-cidr`)
      passes in Lima with port + IPv6 evidence printed.
- [ ] `verify-runtime`, `verify-network-lock` unchanged (9/9 hooks, base lock
      un-regressed).
- [ ] Docs updated: `CLAUDE.md` network section, `docs/api/grpc.md`, the
      runtime-verification gate section, `README` gate bullet. State the exact
      grammar and any one-port-per-CIDR limitation.

---

## 3. FEATURE B — IP→zone (true cross-zone TCP)

**Goal:** make the *destination's zone* matter. Today a locked zone's outbound
is governed only by lock/CIDR. This feature resolves the destination IP to a
zone and applies the existing **zone-pair rule** (`ZONE_ALLOWED_COMMS`): a
zone-a pod may reach a zone-b pod only if an `AllowComm(a,b)` exists; same-zone
always allowed; an unzoned destination falls back to the lock/CIDR logic. This
is the literal "cross-zone TCP" — the unix-socket `ZONE_ALLOWED_COMMS` semantics
extended to IP.

This is the **bigger lift** and has genuine correctness hazards. Treat the
hazards as first-class; the honest deliverable may be "node-local pods + a
documented cluster-wide-IP caveat" rather than a perfect global map. Decide and
document.

### B.1 Design

- **New BPF map `IP_ZONE_MAP`.** Start with `HashMap<u32, u32>` (IPv4 net-order
  → zone_id) for exact pod `/32`s; consider `LpmTrie` if you also want
  Service-CIDR→zone. (IPv6: a parallel `[u8;16] → u32` map, or defer IPv6
  cross-zone to a follow-up and document it.)
- **Hook logic** (in `socket_connect`, and `socket_sendmsg` for UDP): after
  resolving `caller_zone`, if the destination is non-loopback IPv4:
  1. look up `dst_ip` in `IP_ZONE_MAP`.
  2. if `dst_zone` found → apply the zone-pair rule via the existing
     `is_cross_zone_allowed(caller_zone, dst_zone)` (same zone or an explicit
     `ZONE_ALLOWED_COMMS` pair → allow; else **deny with a deny event**). This
     path applies **even to network-open zones** if you want cross-zone
     isolation to hold regardless of egress posture — decide and document the
     interaction with `network_mode`.
  3. if `dst_zone` not found → fall through to the existing locked/CIDR logic
     (external/unzoned destinations are governed by lock + allowlist as today).
- **Keep it one extra lookup** on the hot path. `is_cross_zone_allowed` is
  already a map lookup; the IP→zone lookup is one more. Acceptable.

### B.2 Userspace + the hard parts

- **Populate `IP_ZONE_MAP` from pod IPs.** Extend `syva-k8s`: watch pod
  `status.podIP` cluster-wide (RBAC already allows it). When a zoned pod (annot.
  `syva.false.systems/zone`) has an IP, map `ip → zone`; on IP change / pod
  delete, remove. Add a core RPC — either a dedicated `SetIpZone {ip, zone}` /
  `RemoveIpZone {ip}`, or carry `pod_ip` on `AttachContainer`/`DetachContainer`
  and have the core maintain the map. Prefer a **separate RPC** so IP→zone is
  decoupled from cgroup membership (a pod's IP and its cgroup are observed at
  different times). Reconcile keyed by **pod UID** to survive IP reuse.
- **The cluster-wide hazard (document, don't hide).** Cross-zone enforcement on
  node X must know the zone of destination IPs of pods on *other* nodes. So the
  IP→zone view must be **cluster-wide**, not node-local — every `syva-k8s`
  instance watches all pods and writes the full IP→zone map into its node's
  `IP_ZONE_MAP`. State the consistency window (a pod's IP is enforced only after
  every node's adapter has observed it; until then it is treated as unzoned →
  falls back to lock/CIDR). This is a real eventual-consistency caveat — put it
  in the PR and `CLAUDE.md`.
- **Host-network pods** have the node IP, not a distinct pod IP — skip them
  (cannot be zoned by IP) and document it.
- **Churn / staleness:** stale IP→zone entries are a *correctness* risk (an IP
  reused by a new pod in a different zone). Remove on delete promptly; consider a
  generation/known-set reconcile like the membership watcher already does.

### B.3 Gate — `verify-cross-zone-tcp` (model on `verify-k8s-membership`)

The honest end-to-end proof needs two zoned destinations with real IPs. Two
options:
- **Process-based** (`integration_cross_zone_tcp.rs`): register zone-a and
  zone-b; add two non-loopback IPs to a dummy interface (`ip link add dummy0
  type dummy; ip addr add 10.123.0.2/32 dev dummy0; …`) with listeners; map
  `10.123.0.2→zone-a`, `10.123.0.3→zone-b` via the new RPC; attach a workload
  cgroup to zone-a. Assert: connect to the zone-b IP → `EPERM`
  (`socket_connect deny_delta=1`); `AllowComm(zone-a, zone-b)`; connect again →
  allowed; connect to the zone-a IP (same zone) → allowed throughout.
- **k8s-based** (preferred for end-to-end honesty, like `verify-k8s-membership`):
  two annotated pods (zone-a, zone-b) on the single-node cluster; the zone-a pod
  connects to the zone-b pod IP → denied; create the allow-comm; connect →
  allowed. Heavier but proves the watcher path.

Implement at least the process-based gate; add the k8s gate if time allows and
mark it clearly.

### B.4 Acceptance (Feature B)

- [ ] `IP_ZONE_MAP` populated/cleared correctly; unit tests for the
      reconciler (IP add/change/remove, host-network skip, UID keying).
- [ ] `sudo -E make verify-cross-zone-tcp` passes: cross-zone connect denied
      (`deny_delta=1`), allow-comm flips it to allowed, same-zone always allowed.
- [ ] Hot path stays bounded (one extra lookup); `verify-runtime` healthy.
- [ ] Full regression: `verify-integration`, `verify-container-integration`,
      `verify-k8s-membership`, `verify-audit-mode`, `verify-network-lock`,
      `verify-egress-*`, `verify-cgroup-escape` all pass with the change live.
- [ ] `CLAUDE.md` Known Limits documents the cluster-wide consistency window,
      host-network pods, IPv6 status, and churn/staleness behavior. The PR is
      explicit that this is "zone-pair enforcement on resolvable pod IPs," not
      "all network closed."

---

## 4. Verification environment & exact workflow

- **Lima VM `syva-dev`** has the privileged kernel (6.8, BPF LSM). Run gates as:
  `limactl shell syva-dev bash -lc 'export PATH="$HOME/.cargo/bin:$PATH"; cd
  /Users/yair/projects/syva; sudo -E env PATH="$PATH" make verify-<gate>'`.
  The repo is mounted in the VM; build there for Linux/eBPF.
- **Per-feature loop:** branch from `main` → implement → in Lima:
  `cargo fmt --all && cargo fmt --manifest-path syva-ebpf/Cargo.toml` →
  `cargo run -p xtask -- build-ebpf` →
  `cargo clippy --workspace --all-targets -- -D warnings` →
  `cargo test --workspace` →
  `cargo run -p xtask -- check-release-docs check-api-docs check-openapi
  check-syvactl-contract check-proto` (run each) →
  the new gate + full regression → commit → push → PR → green CI → merge.
- **macOS host** can run `make macos-check` and the `check-*` xtask commands
  (the aya/libc Linux bits don't build on macOS — that's expected; use Lima for
  clippy/test/gates).

### CI gotchas that have bitten every prior PR (avoid them)

1. **`syva-ebpf` is a separate nightly workspace** — `cargo fmt --all` does NOT
   format it. Run `cargo fmt --manifest-path syva-ebpf/Cargo.toml` too, or
   rustfmt CI fails.
2. **The release-doc guardrail scans git-*tracked* files.** New files pass a
   local check only after `git add`. Commit before relying on
   `check-release-docs`. The guardrail also rejects stale hook counts and the
   `cgroup_attach_task` symbol unless a nearby phrase frames it as a known gap
   (`detection only`, `detected`, `not prevented`, `cannot block`,
   `best-effort`) — keep counts correct and always describe that symbol as
   detection only, not prevented. `xtask/src/main.rs` is exempt (it stores the
   trigger literals).
3. **`eval/oracle` is OUT of the workspace** with its own manifest. If you
   change the proto `ZonePolicy` shape, its `ZonePolicy {…}` literal in
   `eval/oracle/src/main.rs` breaks the `build eval crates` CI job — update it.
   (Feature A keeps strings, so likely fine; Feature B may add a field.)
4. **clippy `doc_overindented_list_items`** — keep `//!`/`///` list items at one
   space of indent.
5. If you grow the hook set, bump the "nine" invariant everywhere (guardrail
   counts, `HOOK_NAMES`-derived metrics tests, all docs). Features A and B do
   **not** add LSM hooks (A extends maps; B adds a map + reuses socket_connect),
   so the count stays nine — do not change it.

### PR conventions

- Commit messages: imperative, explain the *why* and the honest residual; end
  with `Co-Authored-By: Codex <noreply@openai.com>` (or your identity).
- PR body: what changed, **Lima evidence** (paste the gate's printed lines:
  `… DENIED EPERM, socket_connect deny_delta=1`, etc.), and an explicit
  **"Honest residual / not closed"** section.
- Two PRs (A then B). Do not bundle. Each green before the next.

---

## 5. Definition of done (both features)

- Both gates pass on the real kernel in Lima, and the full `verify-*` regression
  is green with both changes live.
- No over-claim survives in any doc; every new capability has a caveat list.
- `main` builds, all CI checks pass, both PRs merged.
- `CLAUDE.md` Network section + Known Limits reflect reality:
  egress allowlist = IPv4/IPv6 CIDR with optional port; cross-zone TCP =
  zone-pair enforcement on resolvable pod IPs with a stated consistency window.

If something here turns out to be kernel-impossible (as cgroup-escape
*prevention* was), **stop and report the finding** with the honest alternative —
do not ship a fake. That instinct is the most important thing in this repo.
