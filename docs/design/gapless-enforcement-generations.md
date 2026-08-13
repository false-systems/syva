# Gapless enforcement generations

Status: implemented; privileged verification is recorded by the gates below.

## Decision

Syva will keep the last known-good eBPF generation pinned and enforcing while
the core constructs and populates a fresh generation. The new generation is
activated with one map update only after every hook, self-test, and
authoritative adapter snapshot has completed. The old generation is detached
only after that activation succeeds.

This is the smallest design that closes the core crash and upgrade gap. It
does not add a database, a supervisor, program pins, map-in-map dispatch, or a
second policy format.

## Why the current lifecycle has a gap

The current core owns ordinary process-lifetime maps and links:

- map declarations use unpinned constructors, so `map_pin_path` does not make
  them persistent;
- dropping `EnforceEbpf` detaches the nine LSM links;
- a crash closes the same file descriptors without running cleanup;
- the Kubernetes init container removes `/sys/fs/bpf/syva` on every start;
- the core attaches hooks before its membership state is rebuilt;
- a surviving Kubernetes adapter does not replay a full snapshot after a
  core-only container restart; and
- a stale Unix socket can prevent the restarted core from binding.

There is also a separate chaining bug. Every BPF-LSM hook receives the return
value from earlier BPF-LSM programs as its final argument. Syva currently
ignores it. Syva must return a non-zero prior result unchanged, before
self-tests, counters, events, or policy evaluation. Otherwise a later Syva
program can erase another LSM program's denial, and two Syva generations
cannot safely overlap.

## Guarantees

The lifecycle provides these guarantees:

1. A core crash, graceful restart, or binary upgrade does not remove the last
   known-good policy from the kernel.
2. A partial replacement never becomes active.
3. A replacement uses fresh maps, so map layout and zone ID changes cannot
   corrupt the active generation.
4. A crash at any cutover instruction leaves either the old generation, the
   new generation, or both enforcing.
5. Restart recovery is derived from pinned kernel objects, not a userspace
   snapshot that can disagree with them.
6. Disabling enforcement is an explicit operation, not a side effect of
   stopping the daemon.

"Gapless" is deliberately limited to workloads represented by the last
active generation. Syva cannot classify a workload created while both core
and authoritative adapter are unavailable. Closing that node-bootstrap gap
requires admission or scheduling coordination outside this node agent.
Pinned objects also do not survive a host reboot.

## Kernel layout

Each generation owns fresh maps and one pinned link per hook:

```text
/sys/fs/bpf/syva/
  gen-v1-41/
    maps/
      ENFORCEMENT_MODE
      ZONE_MEMBERSHIP
      ...
    links/
      file_open
      bprm_check_security
      ptrace_access_check
      task_kill
      mmap_file
      unix_stream_connect
      socket_connect
      socket_sendmsg
      socket_bind
```

`v1` is the generation-layout version, not the Syva release. The numeric ID
is `max(existing IDs) + 1`; no wall clock or persistent sequence file is
needed. A pinned link retains its program. Separate program pins add no
recovery value and are omitted.

The mode map is a single-entry array:

| Value | Meaning |
| --- | --- |
| `0` | disabled staging generation |
| `1` | enforce |
| `2` | audit |

Missing and unknown values mean disabled. This changes the current constants,
where zero means enforce, so old and new layouts must have different layout
versions.

A generation is complete only when all expected map and link pins reopen as
kernel BPF objects and the typed mode map is readable. Fresh-map dimensions
are enforced by the compiled eBPF object at load time. A generation is active
only when it is complete and its mode is known non-zero; directory presence
alone never means active.

## Required invariants

These invariants are the implementation contract:

1. **Preserve prior LSM decisions.** Each hook reads its final `ret` argument
   and immediately returns it when non-zero.
2. **Create disabled.** Every fresh generation starts with mode `0` before
   any link is attached.
3. **Populate fresh maps.** Active maps are never cleared or repurposed for a
   replacement.
4. **Activate once.** The only activation point is one update of
   `ENFORCEMENT_MODE[0]` after all readiness predicates are true.
5. **Activate before detach.** No old link is detached until the new mode
   update succeeds.
6. **Persist on shutdown.** Normal shutdown closes userspace handles but does
   not unpin active links or maps.
7. **Delete exact objects.** Cleanup removes validated generation paths and
   known pins; production code never recursively deletes the bpffs root.
8. **One core writer.** An exclusive `flock` on `/run/syva/core.lock`
   serializes recovery, staging, activation, and cleanup. A crash releases the
   lock automatically.

The prior-return argument indices are fixed by each LSM hook prototype:

| Hook | `ret` argument index |
| --- | ---: |
| `file_open` | 1 |
| `bprm_check_security` | 1 |
| `ptrace_access_check` | 2 |
| `task_kill` | 4 |
| `mmap_file` | 4 |
| `unix_stream_connect` | 3 |
| `socket_connect` | 3 |
| `socket_sendmsg` | 3 |
| `socket_bind` | 3 |

The check belongs in the nine eBPF entry points so all Syva side effects are
skipped after an earlier LSM denial.

## Startup and cutover protocol

```text
old active generation       new core                 authoritative adapter
          |                    |                              |
          |<-- recover pins ---|                              |
          |                    |-- create disabled gen ------>|
          |                    |-- attach + pin 9 links        |
          |                    |-- run 3 self-tests            |
          |                    |-- serve staging API ----------|
          |                    |<----- full snapshot replay ---|
          |                    |<----- activate(gen ID) -------|
          |        still active|-- mode: disabled -> desired   |
          |<----- overlap ---->|                              |
          |                    |-- unpin old links              |
          X                    |-- remove old map pins          |
```

The concrete sequence is:

1. Acquire the core lock.
2. Inspect, classify, and validate existing generation directories.
3. Keep the highest complete active generation. If several are active, keep
   them until a higher generation is confirmed; multiple active generations
   are safe after prior-return chaining is fixed.
4. Remove an old gRPC path only when `symlink_metadata` proves it is a Unix
   socket. Refuse a regular file or symlink.
5. Create a fresh generation with mode disabled.
6. Load programs against its fresh maps, attach all nine hooks, and pin every
   link. Any failure removes only this disabled generation.
7. Run the cgroup, inode, and Unix-socket offset self-tests. Self-test writes
   occur while the generation is disabled.
8. Start gRPC. During bootstrap, policy mutations target the staging
   generation.
9. Wait for the authoritative adapter to finish a full snapshot and request
   activation with the exact staging generation ID.
10. Revalidate the generation ID, links, maps, and self-test results. Update
    its mode to the configured enforce or audit value.
11. Detach and unpin older links, then remove their map pins and empty
    directories.

Activation is idempotent for the current generation and rejects stale or
future IDs. The local Unix socket remains the trust boundary; a second token
or lease protocol adds no security when callers already have permission to
mutate all policy.

`GenerationBuilder::drop`, if used, may clean only a generation that has
never been activated. Active-generation deletion must be an explicit method
whose preconditions can be audited.

## Why overlap is safe

Linux chains attached BPF-LSM programs. Once every program preserves a
non-zero prior result, two enforcing generations combine as an intersection:
an operation proceeds only if both allow it. During the short overlap this
can over-block when policy changed, but it cannot create an allow gap.

This also makes a mid-cutover crash safe. If both generations remain pinned,
the next core keeps the highest complete active generation and cleans the
older one. Events may be duplicated during overlap; enforcement correctness
does not require a deduplication subsystem.

LSM links do not support `BPF_LINK_UPDATE`, so there is no atomic program
retarget operation to use instead. The overlap is the kernel-native handover.

## Crash recovery table

| Crash point | Kernel result | Recovery |
| --- | --- | --- |
| Before new links | old active | create a new staging generation |
| Some new links pinned, mode `0` | old active | delete incomplete disabled generation |
| All new links pinned, mode `0` | old active | resume population only if explicitly supported; otherwise rebuild fresh |
| New mode enabled, old links present | both active | keep highest active, remove older links |
| Old links removed, old maps remain | new active | remove old map pins |
| First install before activation | none active | report unsafe; never pretend enforcement exists |

Recovery should prefer rebuilding an abandoned disabled generation. Resuming
its partially populated userspace transaction would require a journal, which
is more machinery than creating fresh maps.

An enabled but incomplete generation is invalid. Disable and clean it only
when a lower complete generation is still active; otherwise report unsafe and
require operator-visible recovery rather than guessing that partial coverage
is acceptable.

## Adapter activation barrier

The core needs one new RPC:

```proto
rpc ActivateGeneration(ActivateGenerationRequest) returns (StatusResponse);

message ActivateGenerationRequest {
  uint64 generation = 1;
}
```

Status exposes `active_generation`, `staging_generation`, and the lifecycle
state. Existing mutation RPCs do not gain transaction IDs: while staging
exists they target staging; after activation they target active. The single
core lock and one staging generation make an extra transaction abstraction
unnecessary.

The Kubernetes adapter activates only after all of these are true:

1. zones and communication rules have completed their initial list/replay;
2. the node-local pod membership watch reached `InitDone` with no pending
   attach failures; and
3. the cluster-wide pod-IP watch reached `InitDone` with no pending updates.

Failed initial attaches must remain pending and retry; rolling back and
waiting for another pod event can leave bootstrap stuck forever. Zone replay
finishes before pod membership begins, avoiding the common missing-zone race.

The adapter also needs an outer resync loop. It polls status, and whenever the
core disconnects or advertises a different staging generation it cancels its
current watchers, reconnects, performs a complete snapshot, and activates the
new ID. This handles a core-only container restart where the adapter process
survives.

The file adapter activates after its first successful full reconcile. Because
it has no workload-membership source, its health must not claim Kubernetes
workload coverage. API/manual operation requires an explicit
`syvactl generation activate` after policy setup.

## Health and observability

Health separates kernel protection from controller freshness:

| State | Meaning |
| --- | --- |
| `unsafe` | no complete active generation |
| `active` | one complete active generation, no staging work |
| `warming` | old generation active, replacement staging |
| `degraded` | multiple active generations, opaque old schema, or cleanup pending |

`warming` is still protected by last-known-good policy. It must not be
reported as fully reconciled. An old generation whose layout can be validated
but whose event schema cannot be decoded still enforces; report degraded
observability rather than unsafe enforcement.

When the old layout is understood, the core reopens its ring buffer and
counters during bootstrap. Otherwise the old ring may fill and lose events,
but enforcement remains intact. Old path-enrichment state is userspace-only,
so buffered events may temporarily fall back to zone IDs and inode numbers.

Two full generations briefly double kernel map memory. Allocation failure
leaves the old generation active and reports degraded status. Syva must never
delete the old generation merely to make staging allocation succeed.

## Shutdown, uninstall, and deployment

Stopping or upgrading the core preserves active pins. Therefore uninstall
needs an explicit operation:

```text
syvactl enforcement disable
```

The core first sets every active mode to disabled, then unpins links, then
maps. An offline cleanup form may acquire the same `flock` when the core is
absent. Both forms validate and remove exact generation objects.

The Kubernetes `cleanup-stale-bpf-pins` init container must be removed. A
pre-stop hook must not disable enforcement because Kubernetes uses the same
path for upgrades and ordinary restarts. Cluster deletion tooling should run
the explicit cleanup command before removing the DaemonSet. Lima teardown
should do the same.

## Residual limits

- A workload created while no authoritative adapter can reach the core is not
  present in the old membership map. Last-known-good enforcement cannot infer
  its zone.
- Policy and IP membership can be stale during an outage. Full replay repairs
  them before cutover.
- bpffs pins survive process exit, not host reboot. Eliminating cold-boot
  exposure requires starting Syva before workloads or gating node readiness.
- A privileged node administrator with BPF or bpffs access can alter the
  objects. The design assumes the node root boundary is trusted.
- Cgroup ID reuse during a long outage remains a kernel-identity risk. Do not
  add a cleanup probe until a reproducible test shows it is material; the
  generation replay already bounds it at the next activation.

## Rejected alternatives

| Alternative | Why it does not hold |
| --- | --- |
| Delay hook attach until replay | leaves enforcement absent while core is down |
| Persist policy as JSON or a database | does not keep kernel links alive and creates a second source of truth |
| Reuse singleton pinned maps | couples upgrades to old layouts and exposes partial clearing/population |
| Map-in-map generation selector | adds hot-path lookups but cannot atomically replace LSM programs |
| Separate supervisor/enforcer daemon | moves the same lifecycle problem into another privileged process |
| Pin programs separately | pinned links already retain their programs |
| `BPF_LINK_UPDATE` | tracing/LSM link operations do not implement program update |

## Implementation order

1. Fix prior LSM return chaining and add a privileged chaining regression
   gate. Do not permit overlapping generations before this lands.
2. Add generation layout, pinned maps/links, mode `0` staging, recovery,
   `flock`, safe socket cleanup, and explicit disable.
3. Add activation/status RPCs and the Kubernetes/file/manual activation
   barriers.
4. Remove deployment-time pin deletion and add restart-continuity gates.

The production branch must not ship step 2 without step 3: a persistent but
automatically activated partial generation would be worse than the current
fail-fast lifecycle.

## Validation gates

The smallest convincing checks are privileged integration gates:

1. **LSM chain:** an earlier test LSM denies an operation; Syva attaches after
   it; the denial remains unchanged.
2. **Restart continuity:** configure a denied operation, `SIGKILL` the core,
   verify the operation remains denied while the process is absent, restart,
   replay and activate, and assert a tight background probe observed zero
   successful operations.
3. **Cutover crash matrix:** kill after partial link pinning, after all links,
   after activation, and during old cleanup; every restart reaches the state
   in the recovery table.
4. **Core-only restart:** leave the Kubernetes adapter running, restart only
   core, and prove the adapter notices the new staging ID and replays.
5. **Explicit uninstall:** disable removes known pins and the formerly denied
   operation succeeds.

Unit tests cover only generation-name parsing, object classification, and
recovery selection. Mocking the kernel lifecycle would add confidence-shaped
code without testing the property that matters.

## Kernel references

- [Linux BPF LSM documentation](https://docs.kernel.org/bpf/prog_lsm.html)
  defines the final prior-return argument and requires preserving a non-zero
  result.
- [Linux `kernel/bpf/syscall.c`](https://github.com/torvalds/linux/blob/master/kernel/bpf/syscall.c)
  shows that tracing link operations, used by LSM links, do not provide an
  `update_prog` operation.
