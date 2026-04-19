use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
enum Cli {
    /// Build the eBPF programs for syva-ebpf.
    BuildEbpf {
        /// Build in release mode.
        #[clap(long)]
        release: bool,
    },
    /// Enforce ADR 0003 Rule 6: mutating sqlx queries only inside
    /// `syva-cp/src/write/`. Fails the build if any are found elsewhere.
    CheckWriteDiscipline,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli {
        Cli::BuildEbpf { release } => build_ebpf(release),
        Cli::CheckWriteDiscipline => check_write_discipline(),
    }
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is in project root")
        .to_path_buf()
}

fn build_ebpf(release: bool) -> Result<()> {
    let root = project_root();
    let ebpf_dir = root.join("syva-ebpf");

    if !ebpf_dir.exists() {
        bail!(
            "syva-ebpf directory not found at {}. Create it first.",
            ebpf_dir.display()
        );
    }

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args([
            "+nightly",
            "build",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to run cargo build for eBPF")?;
    if !status.success() {
        bail!("eBPF build failed");
    }

    let profile = if release { "release" } else { "debug" };
    let artifact = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("syva-ebpf");

    println!("eBPF object built: {}", artifact.display());
    Ok(())
}

/// Regex-based enforcement of ADR 0003 Rule 6.
///
/// A full clippy lint was considered overkill for a single rule and
/// would force every contributor to install a custom cargo-plugin. A
/// recursive regex scan of the working tree is fast, portable, and
/// catches uncommitted edits — which matters for local "save and run"
/// flow. CI runs the same check on the freshly checked-out branch so
/// it still fails on committed violations.
fn check_write_discipline() -> Result<()> {
    let root = project_root();
    let search_root = root.join("syva-cp").join("src");
    let allowed_dir = root.join("syva-cp").join("src").join("write");

    // Forbidden patterns: any sqlx query-ish entry point that contains
    // INSERT / UPDATE / DELETE in the following SQL text. We scan the
    // whole file (not line-by-line) so multi-line raw strings are
    // caught too.
    let forbidden = regex::Regex::new(
        r#"(?is)sqlx::query(?:_as|_scalar)?!?\s*\(.*?\b(insert|update|delete)\b"#,
    )
    .context("failed to compile forbidden pattern")?;

    let mut violations = Vec::new();

    for entry in walkdir::WalkDir::new(&search_root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if path.starts_with(&allowed_dir) {
            continue;
        }

        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };

        for m in forbidden.find_iter(&content) {
            let lineno = content[..m.start()].bytes().filter(|b| *b == b'\n').count() + 1;
            let snippet = content[m.start()..m.end()]
                .lines()
                .next()
                .unwrap_or_default()
                .trim();
            let rel = path.strip_prefix(&root).unwrap_or(path);
            violations.push(format!("{}:{}: {}", rel.display(), lineno, snippet));
        }
    }

    if !violations.is_empty() {
        eprintln!(
            "ADR 0003 Rule 6 violation: mutating sqlx queries outside \
             syva-cp/src/write/"
        );
        for v in &violations {
            eprintln!("  {v}");
        }
        eprintln!();
        eprintln!("All mutating DB writes must go through TransactionalWriter.");
        eprintln!("Move the offending call into syva-cp/src/write/<resource>.rs.");
        bail!("write discipline check failed");
    }

    println!("write discipline check passed");
    Ok(())
}
