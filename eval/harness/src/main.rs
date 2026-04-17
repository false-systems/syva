//! syva-harness — spec-driven test runner.
//!
//! Loads every `cases/*.yaml` spec, dispatches to the matching oracle case
//! (`cargo test --manifest-path eval/oracle/Cargo.toml -- <id>`), and emits a
//! JSON report. Pattern borrowed from AHTI's `eval/harness`.
//!
//! The spec is the source of truth for *what* must work; the oracle case is
//! the executable check. When the oracle is missing the named case, the
//! harness records the spec as failed — unimplemented specs show up as gaps,
//! not silent passes.
//!
//! Invocation:
//!
//! ```text
//! cargo run --manifest-path eval/harness/Cargo.toml
//! cargo run --manifest-path eval/harness/Cargo.toml -- --cases-dir eval/harness/cases
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "syva-harness", about = "Spec-driven oracle runner for syva")]
struct Cli {
    /// Directory containing YAML spec files (`cases/*.yaml`).
    #[arg(long, default_value = "eval/harness/cases")]
    cases_dir: PathBuf,

    /// Path to the oracle's Cargo.toml.
    #[arg(long, default_value = "eval/oracle/Cargo.toml")]
    oracle_manifest: PathBuf,

    /// Where to write the JSON report. Parent dirs are created on demand.
    #[arg(long, default_value = "eval/results/report.json")]
    report: PathBuf,

    /// Only run specs whose `id` starts with this prefix.
    #[arg(long)]
    filter: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // `spec` and `timeout_secs` are read from YAML but not yet used by the runner.
struct Spec {
    /// Stable ID — must match the `#[tokio::test] async fn <id>` in the oracle.
    id: String,
    /// Human-readable one-line statement of what must work.
    description: String,
    /// The behavioural spec, in prose. Never interpreted by the harness —
    /// this is what a contributor or a coding agent reads to implement the case.
    #[serde(default)]
    spec: String,
    /// Hard ceiling for this case's oracle run, in seconds. Informational
    /// today; v2 of the harness will kill the subprocess when it's exceeded.
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
}

fn default_timeout() -> u64 { 60 }

#[derive(Debug, Serialize)]
struct CaseResult {
    id: String,
    description: String,
    passed: bool,
    oracle_exit_code: i32,
    duration_ms: u128,
    stderr_tail: String,
}

#[derive(Debug, Serialize)]
struct Report {
    timestamp: String,
    total: usize,
    passed: usize,
    failed: usize,
    results: Vec<CaseResult>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let specs = load_specs(&cli.cases_dir, cli.filter.as_deref())?;
    if specs.is_empty() {
        eprintln!("no specs found in {}", cli.cases_dir.display());
        std::process::exit(2);
    }

    eprintln!("syva-harness: running {} spec(s)", specs.len());

    let mut results = Vec::with_capacity(specs.len());
    for spec in &specs {
        eprintln!("─ {} — {}", spec.id, spec.description);
        results.push(run_one(spec, &cli.oracle_manifest));
    }

    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.len() - passed;

    let report = Report {
        timestamp: chrono::Utc::now().to_rfc3339(),
        total: results.len(),
        passed,
        failed,
        results,
    };

    if let Some(parent) = cli.report.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&cli.report, serde_json::to_vec_pretty(&report)?)?;

    eprintln!(
        "\nsyva-harness: {}/{} passed — report at {}",
        passed,
        report.total,
        cli.report.display(),
    );

    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn load_specs(dir: &Path, filter: Option<&str>) -> anyhow::Result<Vec<Spec>> {
    let mut specs = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let raw = std::fs::read_to_string(&path)?;
        let spec: Spec = serde_yaml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", path.display()))?;
        if let Some(prefix) = filter {
            if !spec.id.starts_with(prefix) {
                continue;
            }
        }
        specs.push(spec);
    }
    // Sorted by id — stable case order in the report.
    specs.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(specs)
}

fn run_one(spec: &Spec, oracle_manifest: &Path) -> CaseResult {
    let start = Instant::now();

    // `cargo test ... -- <id>` uses the test-name filter. Combined with
    // `--exact`, it runs one case even when another case's name is a prefix.
    let output = Command::new("cargo")
        .args([
            "test",
            "--manifest-path",
            oracle_manifest.to_str().expect("manifest path UTF-8"),
            "--",
            &spec.id,
            "--exact",
            "--nocapture",
        ])
        .output();

    let duration_ms = start.elapsed().as_millis();

    match output {
        Ok(out) => {
            let exit = out.status.code().unwrap_or(-1);
            let passed = out.status.success();
            // Keep the last 1KB of stderr so the report stays compact.
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stderr_tail = tail_kb(&stderr, 1024);
            CaseResult {
                id: spec.id.clone(),
                description: spec.description.clone(),
                passed,
                oracle_exit_code: exit,
                duration_ms,
                stderr_tail,
            }
        }
        Err(e) => CaseResult {
            id: spec.id.clone(),
            description: spec.description.clone(),
            passed: false,
            oracle_exit_code: -1,
            duration_ms,
            stderr_tail: format!("failed to spawn cargo test: {e}"),
        },
    }
}

fn tail_kb(s: &str, limit: usize) -> String {
    if s.len() <= limit {
        return s.to_string();
    }
    // Walk forward until we land on a UTF-8 char boundary. Slicing a `str`
    // mid-codepoint would panic — `s.len() - limit` is a byte offset and
    // has no guarantee of aligning with one.
    let mut boundary = s.len() - limit;
    while boundary < s.len() && !s.is_char_boundary(boundary) {
        boundary += 1;
    }
    format!("…{}", &s[boundary..])
}
