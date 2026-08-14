# Syva Observer: implementation-blocking questions

These are the only questions that can materially change the first
implementation. Everything else is specified in
[the Observer design](syva-observer.md).

1. **Core read seam:** should Observer receive a new read-only snapshot RPC
   from `syva-core`, or should a small read-only sidecar API expose current
   memberships and policy metadata without widening the core write API?

2. **Socket credentials:** can deployment guarantee a Unix-socket group/peer
   credential that permits Observer reads while rejecting all core mutations?
   If not, the API must split read and write sockets or add RPC-level
   authorization before Observer implementation.

3. **Workload source of truth outside Kubernetes:** for standalone/file mode,
   which process/container lifecycle source is authoritative enough to mark a
   workload removed, rather than relying only on cgroup polling?

4. **Freshness defaults:** what operational freshness window is acceptable for
   `PROTECTED` posture on a node, and should it be configurable per deployment?

5. **Metadata reachability probes:** are active cloud-metadata probes allowed
   in the target environments, or must the first release remain passive and
   classify route reachability as `UNKNOWN` without a controlled probe?

6. **Vartio transport:** which existing False Systems evidence envelope and
   sink contract should Observer target, if any? This must not block the local
   daemon or define the enforcement API.

7. **Persistence requirement:** is restart continuity of recent observations a
   product requirement, or is bounded memory plus explicit `UNKNOWN`/gap state
   sufficient for the first release?
