# eBPF + Infra Logs / Observability — Best Practices

> **How this document relates to the Syva in this repository.** These are
> research notes written at the False Systems suite level, where Syvä is
> framed as an observe-only event core fed by external producers (jälki,
> TAPIO) with enforcement living downstream (Vartio). The Syva in this repo
> answers the §10 boundary questions differently: it **owns its in-kernel
> code** (nine BPF-LSM hooks + a fentry detector), it **enforces** (denies
> with EPERM in the kernel), it does **not persist**, its event path is
> **real-time**, and its kernel floor is **5.10**. Read §§3–6 as the playbook
> for this repo's event pipeline (implemented in v0.4.0: the always-on event
> pump, one canonical enriched event with machine/human projections, constant
> event names, FALSE-protocol reason fields, the `EventSink` fan-out seam,
> and the never-sample-evidence rule). Read §§0, 8's observe-only framing,
> and the jälki/TAPIO/Vartio split as suite-level direction, not a
> description of this product.

---

## 0. Scope and framing

**For now, Syvä is treated standalone.** It is "core + adapters," sitting alongside **jälki** (the eBPF SDK) and **TAPIO** (the kernel observer). Its job today: receive events from kernel-side producers and other sources, give them a stable, verbose-but-readable shape, and emit them across a clean output boundary.

**The downstream consumer is a later decision.** Eventually Syvä will send to **Vartio**, or to AHTI, or to a third-party backend. The design goal that makes that painless: the destination is a **pluggable sink** behind a stable wire contract (FALSE Protocol, with an OTLP mapping). Get the event schema and the output boundary right now, and "send to Vartio later" is a new sink implementation, not a rearchitecture. Everything in this doc optimizes for that: a self-contained observability core with a swappable exit.

Syvä's own best practices live in §3–§6 (data path, event modeling, readability, pipeline + output). §1–§2 and §8 are upstream/operational constraints its adapters must understand even where Syvä doesn't own the probes.

---

## 1. The layer map — where each decision lives

1. **Probe** (in-kernel eBPF) — portability, verifier limits, map hygiene. *(jälki / TAPIO)*
2. **Data path** (kernel → userspace) — ring buffer choice, loss, backpressure, in-kernel filtering. *(boundary jälki ↔ Syvä)*
3. **Pipeline** (normalize / enrich / render / route) — stable schema, verbosity, cardinality, correlation. *(Syvä core)*
4. **Output boundary** — pluggable sinks (stdout / file / OTLP today; Vartio / AHTI / third-party later). *(Syvä's exit, future routing)*

The single cross-cutting rule, recurring at every layer: **do the reduction as deep as possible** — filter in-kernel, cut cardinality at ingest, render verbosity lazily. This is what separates sub-1% overhead tools from agents nobody runs.

---

## 2. Probe layer — portability and discipline

**CO-RE is non-negotiable for anything you distribute.** Compile the eBPF object once against BTF type information, and let the loader relocate field offsets against the *running* kernel's types at load (exposed at `/sys/kernel/btf/vmlinux`). Generate `vmlinux.h` with `bpftool btf dump`. This removes the dependency on target-host kernel headers entirely.

- The old-world alternatives are unacceptable for a shipped product: BCC compiles on the target at runtime (needs LLVM/Clang + headers on every host), and per-kernel precompiled binaries are a maintenance swamp.
- CO-RE **requires a BTF-enabled kernel** (`CONFIG_DEBUG_INFO_BTF`). Modern distros ship it; for older fleets, **BTFHub** supplies BTF blobs. Decide your kernel floor early.
- Portability has a hard edge: CO-RE relocates fields that *moved or were renamed*, but can't conjure a field that doesn't exist in the target kernel. Feature-detect and degrade.

**Verifier discipline.** The program must prove safety: bounded loops, bounded complexity. Practical consequence — **keep the in-kernel program thin.** Capture and filter; all real logic belongs in userspace.

**Map hygiene.** Maps have size limits and long-running programs leak without reclaim. Build cleanup/eviction into any map accumulating per-PID / per-connection state.

**Rust toolchain.** **aya** is pure-Rust (no libbpf/bcc, only `libc` for syscalls); with BTF + musl it yields a single self-contained CO-RE binary deployable across distros and kernel versions, with async via tokio. **libbpf-rs** wraps battle-tested libbpf (still pulls in the C library) and is the choice if you want to share C eBPF code or lean on libbpf directly. For a Rust shop wanting one static binary, aya is the default; kernel-side code is `no_std`.

---

## 3. Data path — getting events out of the kernel

The jälki ↔ Syvä contract, and the place most production pain originates.

**Default to the ring buffer (`BPF_MAP_TYPE_RINGBUF`, kernel ≥ 5.8), not the perf buffer.** Perf buffer is per-CPU: wastes memory, reorders events across CPUs. Ring buffer is a single MPSC buffer shared across all CPUs — correct ordering, better memory scaling (16→32 CPUs doesn't double RAM), and one big buffer absorbs bursts that per-CPU buffers drop. Benchmarks put it at par-or-better than perfbuf in nearly all cases.

**Use the reserve/submit API** — write directly into the buffer, no intermediate copy.

**Tune wakeups deliberately** (submit flag):
- default = adaptive (wakes only when the consumer keeps up — usually right),
- `BPF_RB_NO_WAKEUP` = batch, avoid the context switch (high-throughput, latency-tolerant),
- `BPF_RB_FORCE_WAKEUP` = immediate (latency-critical events).
Pick per event class.

**Plan for loss explicitly.** A lagging consumer fills the buffer and you drop. So:
- size the buffer for your *burst*, not your average (sizing for steady-state then losing the spike is the classic failure);
- expose a **drop counter** — drops are a first-class signal, never a silent failure;
- choose overflow semantics — drop-newest vs overwrite-oldest — per event class. For evidence/audit data, silent drops are the worst outcome.

**Shard the buffer at high volume.** Multiple ring buffers (one per source/producer, the Inspektor Gadget pattern) beats one contended buffer — an obvious knob for Syvä's adapters.

**Filter in the kernel.** Only forward matching events. Sub-1% overhead tools achieve it precisely because matching happens in-kernel and only matches cross into userspace. Anything Syvä can push *down* into jälki/TAPIO is overhead it never pays.

---

## 4. Event / log modeling — the shape Syvä imposes

**"Structured" means a stable schema, not merely JSON.** What makes a log structured is consistent field names, types, and semantics downstream systems can rely on — JSON with arbitrary keys is still unstructured in every way that matters. Syvä's value is partly that it *enforces* one stable schema across heterogeneous adapters.

**Anchor on the OpenTelemetry log data model + semantic conventions**, even with an internal representation:
- **Resource attributes** identify the producer (host, pod, service, actor), separate from the event body.
- Naming: lowercase, dotted namespaces (`db.system`, not `db_system` / `dbSystem`).
- This is where **FALSE Protocol** earns its keep. `what_failed`, `why_it_matters`, `possible_causes` are semantic-convention fields by another name — a controlled vocabulary on the event body. Treat FALSE Protocol as your convention set and define its OTel mapping explicitly, so a Syvä event round-trips to any OTLP-native consumer without losing meaning. This is also exactly the wire contract that makes the future Vartio sink trivial.

**Cardinality decides your cost.**
- High-cardinality identifiers (actor ID, connection ID, request ID) belong **in logs / events / span-events**, where they answer "everyone, or just this actor?"
- They must **not** become metric label values — that's what blows up a metrics backend.
- Canonical example: parameterized `http.route` (`/users/{id}`), not raw `http.target`. Apply the same instinct to actor identity — bucket where you can, keep the raw ID on the event only.

**Correlation is the payoff.** Carry a correlation key on every event. For your domain the key is the **Actor / delegation chain** — Syvä should stamp the actor-identity correspondence onto every event at ingest, because that's the join key any downstream (Vartio, AHTI) reasons over later. It is also, per §5, the spine of stream readability.

---

## 5. Verbosity & readability — structuring logs to be both

Verbosity and readability are usually treated as a slider you trade along. They aren't. The resolution is to stop emitting *one* thing and emit **one canonical event rendered into multiple projections**. That single decision is most of the answer.

### 5.1 One event, two (or three) projections

Capture one richly-structured event. Then project it:
- **Machine form** — full-fidelity FALSE/JSON record → storage and the output sink.
- **Human form** — a curated, compact console rendering for tailing / dev / incident view.
- optionally an **expanded form** — the full tree, on demand, for incident drill-down.

Verbose lives in the structured record; readable lives in the projection. You never choose between them. In Rust, `tracing` + `tracing-subscriber` give this for free: attach a JSON layer *and* a console layer to the same events, each level-filtered independently.

### 5.2 Constant message, variable fields — never interpolate

The "message" is a **stable event name**, not a sentence with values baked in.

- ✗ `"actor ci-job:build-1421 denied access to secret prod/db-password"`
- ✓ event `actor.access.denied`, with `actor.id` and `resource` as fields.

The constant name makes a verbose stream scannable — the eye locks onto a consistent column of event types — keeps grep/filter working, and keeps cardinality out of the message. All variance goes to fields, where verbosity is cheap and queryable. Humans read the names; machines read the fields.

### 5.3 Verbosity is a dial (levels) and a tree (spans), not a firehose

Two mechanisms keep "verbose" from meaning "unreadable":
- **Severity levels** make verbosity *selectable* — TRACE/DEBUG off by default, on when debugging.
- **Hierarchical spans** make detail *nested* not flat: a span carries context (actor, delegation chain, request) once, and child events inherit it instead of repeating it per line. Default view stays collapsed and clean; you expand into the full tree only when needed.

That's verbosity-on-demand — the only kind that stays readable.

### 5.4 The same event, three projections

```text
# machine (stored / FALSE Protocol → output sink)
{ "ts":"2026-06-13T14:22:01.481Z", "level":"WARN", "event":"actor.access.denied",
  "actor": {"id":"ci-job:build-1421", "delegation":["oauth-app:deploy-bot","svc:deployer"]},
  "resource":"secret:prod/db-password", "trace_id":"…",
  "what_failed":"read on prod secret outside declared scope",
  "why_it_matters":"credential used beyond CI's normal envelope",
  "possible_causes":["scope drift","leaked token","misconfigured job"] }

# console compact (human tail)
14:22:01  WARN  actor.access.denied   ci-job:build-1421 → secret:prod/db-password
                read outside declared scope · credential beyond CI envelope

# expanded (incident view, on demand)
14:22:01  WARN  actor.access.denied
  actor         ci-job:build-1421
  delegation    oauth-app:deploy-bot → svc:deployer → ci-job:build-1421
  resource      secret:prod/db-password
  why           credential used beyond CI's normal envelope
  causes        scope drift | leaked token | misconfigured job
```

Same event, full fidelity preserved, three levels of readability.

### 5.5 FALSE Protocol fields *are* the readability mechanism

Most systems make a log verbose by dumping more raw fields — verbose into noise. You make it verbose by carrying structured, human- and LLM-actionable interpretation (`what_failed` / `why_it_matters` / `possible_causes`) alongside the raw data — verbose into meaning. That's a genuinely better answer to "verbose but readable" than the industry default. Discipline: keep those fields short, declarative, and **templated per event type** (one stable phrasing per `event` name), so they read consistently rather than as ad-hoc prose.

### 5.6 Stream readability = filtering, not formatting

A clean single line is necessary but not sufficient. At volume, readable means "I can collapse to one actor or one delegation chain and read it as a story." So the correlation work in §4 is also a *readability* feature: the human view should let you pivot to one chain and watch the narrative unfold.

### 5.7 Craft details that matter

- RFC3339 timestamps **with timezone**.
- **Units in field names** (`duration_ms`, `bytes`) — no one should guess.
- Consistent field ordering across event types.
- **Bound/truncate large values** so one event can't swamp the view.
- **Redact secrets at emit, not at render.**
- Color in the console projection may *aid* but must never *carry* meaning (colorblind + non-TTY).
- Keep pretty-printing strictly in the userspace renderer — never multi-line / string-format in the hot path.

### 5.8 The overhead caveat

"Verbose and readable" is a human/debug-time concern and must not leak into capture. Keep the kernel side and ingest path terse and structured; rely on lazy field evaluation so disabled verbose levels cost nothing; sample high-frequency events. Rich human rendering is computed *when a person is looking*, not on every event at line rate.

---

## 6. Pipeline (Syvä core) — normalize, enrich, route, emit

- **Normalize at the edge.** Each adapter maps its source's quirks into the one internal schema immediately; nothing downstream sees source-specific shapes. This is the whole reason "core + adapters" is right — adapters absorb the mess so the core stays clean.
- **Speak OTLP at the boundaries.** Accept OTLP in, emit OTLP out alongside the native/FALSE format. Imitate the Collector model: ingest legacy formats next to native data, so adoption is incremental.
- **Reduce before export, not after.** Cardinality reduction, redaction, and dropping belong in the pipeline before storage — far cheaper than post-ingestion cleanup.
- **Sampling.** Tail-based (keep error/slow/anomalous, sample the boring) beats head-based. But for *evidence* data, sampling away the rare event is the failure mode that hurts a governance product — **sample telemetry, keep evidence.**
- **Backpressure end-to-end.** The drop problem from §3 doesn't stop at the buffer; the whole pipeline needs bounded queues, a load-shedding policy, and a counter so shedding is visible. Decide *what* you shed under load deliberately.

### 6.1 The output boundary — pluggable sinks

Define one sink abstraction; every destination is an implementation of it. The **wire contract is FALSE Protocol** (with the OTel mapping from §4). Support **fan-out** from day one: stdout *and* a real sink during development, and later Vartio *and* an archive sink simultaneously. Make the sink the place for transport concerns — batching, retry, at-least-once vs best-effort — so the core stays a pure event producer.

---

## 7. Store + query — a possible downstream (later)

Syvä standalone needn't own storage. *If/when* it persists or hands to a store, these apply:

- **Columnar** for write-heavy, occasionally-analyzed event data; Parquet on disk + Arrow at query time as baseline; Vortex as the escape hatch when random-access-by-key latency over object storage becomes the bottleneck.
- **Dynamic columns** — observability/evidence data has a varying, sparse attribute set per row. Don't force a fixed wide schema; let the column set be dynamic per write. This is the one storage-design decision worth making now, because it shapes the event schema in §4.
- **Object storage, single-binary-friendly** — avoid operational dependencies (Kafka-in-front, disk-state) that become full-time jobs for a small team.

---

## 8. Production & security posture

**Overhead budget: aim <1%, and measure it.**
- Enable `kernel.bpf_stats_enabled=1`; read `run_cnt` / `run_time_ns` per program via `bpftool prog show`. Publish the real per-event cost.
- A public, reproducible overhead benchmark is also a credibility artifact. Worth standing up early.

**Privilege posture.**
- Prefer **CAP_BPF** (narrower) over CAP_SYS_ADMIN where the kernel allows.
- On newer kernels, **BPF tokens** enable safer delegated/unprivileged loading.
- Loading eBPF still requires elevation — be explicit in the threat model.

**Kernel-version matrix is a real maintenance surface.**
- LSM/security hooks get renamed across versions. Handle both, ignore-if-not-found, rather than branching the program.
- Pin a **minimum kernel** and state it — it determines whether you can assume BTF, ring buffer (5.8), BPF tokens. Set it once; it simplifies everything above.

---

## 9. Suggested defaults (the short version)

- Ring buffer, reserve/submit, adaptive wakeup default; force-wakeup only for latency-critical classes.
- Drop counters as first-class metrics.
- Stable internal schema; FALSE Protocol as the semantic-convention vocabulary with an explicit OTel mapping.
- **One canonical event, multiple projections**: JSON sink + compact console, filtered independently.
- **Constant event names in the message position; all variance in fields.**
- High-cardinality IDs on events only, never on metric labels.
- Reduce/redact in the pipeline before storage; **keep evidence, sample telemetry.**
- One `EventSink` abstraction, fan-out capable.
- Filter in-kernel wherever possible; measure overhead with bpf_stats; publish the number.
- Minimum kernel pinned and documented.

---

## 10. Open questions to pin Syvä's boundary — answered for this repo

1. **Does Syvä own any in-kernel code?** Yes — nine BPF-LSM hooks plus the
   cgroup-escape fentry detector. §2 is ours (BTF offset resolution with
   startup self-tests is the implemented portability mechanism).
2. **Does Syvä persist?** No — pure producer; the event pump hands enriched
   events to sinks (gRPC broadcast, log, metrics today).
3. **Real-time path or batch?** Real-time (100ms drain ticks).
4. **Kernel-version floor?** Linux ≥ 5.10 (BPF-LSM, ring buffer, BTF).
