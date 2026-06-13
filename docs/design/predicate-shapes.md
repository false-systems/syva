# Predicate Shapes — the frozen mechanism surface

Syva's architecture splits cleanly in two:

- **Mechanism** — a small, fixed set of *decision shapes* compiled into the
  eBPF programs. This surface is deliberately frozen: fixed shapes are what
  make the programs pass the verifier at all, and a small audited mechanism is
  what makes Syva a *substrate* rather than a policy engine.
- **Policy** — the data that fills the BPF maps, supplied at runtime over the
  `syva.core.v1` gRPC API. This surface is open and hot-swappable: an
  `AllowComm` call flips a live kernel denial to an allow with no redeploy
  (proven by `verify-cross-zone-tcp` and `verify-allow`).

A control plane (e.g. Vartio) is therefore "just another client": it composes
data over a fixed, audited mechanism — it never ships new kernel semantics.
The question this document answers: **does the shape set converge (a moat) or
sprawl (a roadmap tax that scales with adoption)?**

## The shapes that exist today

Every hook reduces to one of a handful of decision shapes. Counting distinct
*shapes*, not hooks:

| # | Shape | Hooks using it | Policy data (maps) |
| --- | --- | --- | --- |
| 1 | **Caller-zone vs target-zone** identity/pair | `file_open`, `bprm_check_security`, `mmap_file` (target = file inode's zone); `ptrace_access_check`, `task_kill`, `unix_stream_connect` (target = peer task/sock zone) | `ZONE_MEMBERSHIP`, `INODE_ZONE_MAP`, `ZONE_ALLOWED_COMMS` |
| 2 | **Caller-zone network lock** (no target; deny non-loopback unless the zone is network-open) | `socket_connect`, `socket_sendmsg`, `socket_bind` | `ZONE_POLICY` flag |
| 3 | **Destination allowlist** (LPM CIDR + optional port) layered under shape 2 | `socket_connect`, `socket_sendmsg` | `EGRESS_CIDR_MAP` / `EGRESS_CIDR6_MAP` |
| 4 | **Destination-zone pair** (resolve dst IP → zone, then shape 1's pair rule) layered under shape 2 | `socket_connect`, `socket_sendmsg` | `IP_ZONE_MAP` + `ZONE_ALLOWED_COMMS` |
| — | **Detection-only** (record, never block) | `cgroup_attach_task` fentry | `CGROUP_ESCAPE_COUNT` |

Plus two global modifiers that apply to all blocking shapes without adding new
ones: the **enforce/audit** switch (`ENFORCEMENT_MODE`) and the always-allow
carve-outs (loopback, unzoned caller, global zone).

So: **four blocking shapes**, three of them (2–4) composing as layers on the
same socket hooks rather than multiplying. Adding the nine hooks cost only
those four shapes — strong evidence the shape↔hook ratio is sublinear.

## Foreseeable shapes (do they converge?)

Candidate future capabilities, classified by whether they need a *new shape*
(new eBPF object) or just *new data/hooks reusing an existing shape*:

| Capability | New shape? | Why |
| --- | --- | --- |
| More file-ish hooks (`inode_rename`, `inode_unlink`, `file_lock`) | No | Shape 1 — caller-zone vs inode-zone |
| More process hooks (`ptrace_traceme`, `task_setnice`) | No | Shape 1 — caller vs target task |
| `setns` / namespace-entry control | No | Shape 1 — caller-zone vs target-namespace-owner |
| IPv6 pod-IP cross-zone | No | Shape 4 — already IPv6-ready in the map type |
| Per-zone allowed **destination ports** without CIDR | No | Shape 3 with a wildcard prefix |
| **Time-windowed** policy (allow only during a window) | Maybe | If the window predicate lives in userspace (flip map entries on a timer) → no new shape; if evaluated in-kernel → new shape |
| **Rate / quota** (deny after N ops) | Yes | Stateful per-(zone,target) counter compared to a threshold — a genuinely new in-kernel predicate |
| **DNS-name** egress policy | No (at this layer) | Names resolve to IPs in userspace → fills shape 3/4 maps; the kernel never sees names |
| **L7 / payload** matching | Yes (and out of scope) | Requires content inspection — a different mechanism class, not an LSM allow/deny shape |

The pattern: the overwhelming majority of foreseeable policy is **new data or
new hooks reusing shapes 1–4**, because the shapes are defined over the two
primitives every LSM hook already gives us — *who is acting* (caller zone) and
*what is being acted on* (an inode zone, a task zone, or a destination
address/zone). Policies that stay expressible as "relate caller-zone to
target-zone/address" never need a new object.

Genuinely new shapes appear only when policy needs **in-kernel state**
(rate/quota) or **a new primitive** (L7 payload) — and the latter is a
different product, not a Syva predicate. That is a converging set, not a
sprawling one: the moat holds.

## The honest edge

- "New shape per object" is real for the stateful cases (rate/quota). If
  customer demand clusters there, that is a design conversation (a generic
  in-kernel counter-compare shape could absorb a whole class at once) — to be
  had before it is a fundraising claim, not after.
- The mechanism being frozen is a *feature* for audit and verifier
  tractability, but it does mean Syva cannot express arbitrary policy the way
  a userspace proxy can. The trade is deliberate: kernel-enforced, provable,
  small — versus expressive but bypassable. Lead with that framing.

## How to talk about it

The one-liner: **the mechanism surface is small and frozen, the policy surface
is open, and the boundary between them is a gRPC API already proven
hot-swappable live.** Demo the `AllowComm` runtime flip
(`verify-cross-zone-tcp`), not the deny test — the flip is what proves "Syva
can be *told* what to block," which is the line a control plane plugs into.
