# Archive — frozen historical design

These documents describe the abandoned **v0.3 `syva-cp` control-plane**
experiment. They are kept as historical context only and are **not** the active
architecture. For what Syva actually is today, see
[`CLAUDE.md`](../../CLAUDE.md) (Current State) and the
[README](../../README.md).

Do **not** reintroduce anything from these docs — no `syva-cp`,
`syva_control.proto`, `cp_reconcile`, Postgres, node heartbeats, team ownership,
or CP assignment streams. The release-doc guardrail
(`cargo run -p xtask -- check-release-docs`) skips this directory precisely
because it is frozen.

## Contents

| Document | What it is |
| --- | --- |
| [`0002-control-plane.md`](0002-control-plane.md) | ADR 0002 — the control-plane decision, since reversed |
| [`0003-transactional-write-discipline.md`](0003-transactional-write-discipline.md) | ADR 0003 — transactional write discipline (CP-era) |
| [`v0.3-control-plane/CONTROL_PLANE.md`](v0.3-control-plane/CONTROL_PLANE.md) | Full v0.3 control-plane design |
| [`v0.3-control-plane/TASKS.md`](v0.3-control-plane/TASKS.md) | v0.3 `syva-cp` task list |

The walkback from this design to the v0.2 core+adapters architecture is recorded
in [`CLAUDE.md`](../../CLAUDE.md) (Current State).
