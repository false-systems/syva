# syva eval

Spec-driven oracle suite. Pattern borrowed from `ahti/eval`.

Two standalone crates (not in the root workspace):

- **`oracle/`** — blackbox test binary. Each `#[tokio::test] async fn case_NNN_*`
  talks to a running `syva-core` over its Unix-socket gRPC surface and
  asserts on public contracts. Imports only `syva-proto`; never core
  internals.
- **`harness/`** — spec-driven runner. Loads `harness/cases/*.yaml`,
  dispatches each spec to the oracle's matching test name, and emits a
  JSON report at `results/report.json`.

## Running against a live core

```sh
# 1. Start syva-core with a non-default socket path so the oracle doesn't
#    race with a production socket.
SYVA_SOCKET=/tmp/syva-oracle.sock \
  cargo run -p syva-core -- --socket-path /tmp/syva-oracle.sock

# 2. In another shell, run the oracle directly (single case):
SYVA_SOCKET=/tmp/syva-oracle.sock \
  cargo test --manifest-path eval/oracle/Cargo.toml -- case_003 --exact --nocapture

# 3. Or run every spec through the harness:
SYVA_SOCKET=/tmp/syva-oracle.sock \
  cargo run --manifest-path eval/harness/Cargo.toml
```

If the core isn't reachable, every oracle case skips with a `SKIP:` line.
The harness treats a skip as a pass (exit 0 from `cargo test`), so
specs stay green in environments that can't run BPF. Use `cargo test
... -- --nocapture` to see skip reasons.

## Adding a new case

1. Pick the next free number (`case_NNN_short_snake_case`).
2. Drop a YAML spec in `harness/cases/` with the behavioural contract in
   prose. Do not include assertion code — that belongs in the oracle.
3. Add a matching `#[tokio::test] async fn case_NNN_short_snake_case()`
   in `oracle/src/main.rs`. Use only `syva-proto` types.
4. Update the case-inventory comment at the bottom of `oracle/src/main.rs`.

Numbers are stable — never renumber. A deleted case leaves a gap.
