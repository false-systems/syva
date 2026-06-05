use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
enum Cli {
    /// Build the eBPF programs for syva-ebpf.
    BuildEbpf {
        /// Build in release mode. This is the default runtime artifact.
        #[clap(long)]
        release: bool,
        /// Build the development debug object instead of the runtime artifact.
        #[clap(long, conflicts_with = "release")]
        debug: bool,
    },
    /// Check Rust formatting.
    Fmt,
    /// Run clippy for the active workspace.
    Lint,
    /// Check the active Rust workspace.
    Check,
    /// Run workspace tests.
    Test,
    /// Run the Linux/eBPF compile check.
    LinuxBpfCheck,
    /// Build eval/oracle and eval/harness so contract tests do not bitrot.
    EvalBuild,
    /// Check syva-proto builds from the checked-in .proto definitions.
    CheckProto,
    /// Check release-critical docs do not drift from v0.2 runtime guarantees.
    CheckReleaseDocs,
    /// Check the runtime eBPF artifact policy: release build by default.
    CheckEbpfArtifactPolicy,
    /// Run the non-privileged pre-commit gate.
    Precommit,
    /// Run ignored privileged runtime verification tests.
    VerifyRuntime,
    /// Run the privileged BPF-LSM integration test that proves the kernel
    /// blocks a forbidden cross-zone action.
    VerifyIntegration,
    /// Run the privileged BPF-LSM **container** integration test: a real
    /// container in zone-a is blocked from reading a zone-b file.
    VerifyContainerIntegration,
    /// Run the standard active-project CI sequence.
    Ci,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli {
        Cli::BuildEbpf { release, debug } => build_ebpf(release || !debug),
        Cli::Fmt => fmt(),
        Cli::Lint => lint(),
        Cli::Check => run_root_command("cargo", &["check", "--workspace"]),
        Cli::Test => run_root_command("cargo", &["test", "--workspace"]),
        Cli::LinuxBpfCheck => check_ebpf_artifact_policy(),
        Cli::EvalBuild => build_eval_crates(),
        Cli::CheckProto => check_proto(),
        Cli::CheckReleaseDocs => check_release_docs(),
        Cli::CheckEbpfArtifactPolicy => check_ebpf_artifact_policy(),
        Cli::Precommit => precommit(),
        Cli::VerifyRuntime => verify_runtime(),
        Cli::VerifyIntegration => verify_integration(),
        Cli::VerifyContainerIntegration => verify_container_integration(),
        Cli::Ci => ci(),
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

fn fmt() -> Result<()> {
    run_root_command("cargo", &["fmt", "--all", "--", "--check"])?;
    run_root_command(
        "cargo",
        &[
            "fmt",
            "--manifest-path",
            "syva-ebpf/Cargo.toml",
            "--",
            "--check",
        ],
    )
}

fn lint() -> Result<()> {
    run_root_command(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )
}

fn check_proto() -> Result<()> {
    run_root_command("cargo", &["check", "-p", "syva-proto"])
}

fn precommit() -> Result<()> {
    fmt()?;
    lint()?;
    run_root_command("cargo", &["test", "--workspace"])?;
    check_proto()?;
    check_release_docs()?;
    check_ebpf_artifact_policy()
}

fn ci() -> Result<()> {
    fmt()?;
    lint()?;
    run_root_command("cargo", &["check", "--workspace"])?;
    run_root_command("cargo", &["test", "--workspace"])?;
    build_eval_crates()?;
    check_proto()?;
    check_release_docs()?;
    check_ebpf_artifact_policy()
}

fn check_ebpf_artifact_policy() -> Result<()> {
    build_ebpf(true)?;

    let root = project_root();
    let release = root.join("syva-ebpf/target/bpfel-unknown-none/release/syva-ebpf");
    if !release.exists() {
        bail!("release eBPF object was not built at {}", release.display());
    }

    let loader = fs::read_to_string(root.join("syva-core/src/ebpf.rs"))
        .context("failed to read syva-core/src/ebpf.rs")?;
    let release_idx = loader
        .find("bpfel-unknown-none/release/syva-ebpf")
        .context("loader does not mention the release eBPF object")?;
    let debug_idx = loader
        .find("bpfel-unknown-none/debug/syva-ebpf")
        .context("loader does not mention the debug eBPF object fallback")?;
    if release_idx > debug_idx {
        bail!("loader must prefer release eBPF object before debug fallback");
    }

    println!("release eBPF artifact policy ok: {}", release.display());
    Ok(())
}

fn check_release_docs() -> Result<()> {
    let root = project_root();
    let files = tracked_files()?;
    let mut failures = Vec::new();

    for file in &files {
        if !is_release_checked_file(file) {
            continue;
        }
        if file == "xtask/src/main.rs" {
            continue;
        }
        let path = root.join(file);
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let lines: Vec<&str> = content.lines().collect();
        let mut in_fence = false;
        for (idx, line) in lines.iter().enumerate() {
            let lower = line.to_ascii_lowercase();
            if lower.trim_start().starts_with("```") {
                in_fence = !in_fence;
                continue;
            }
            if in_fence
                || lower.contains("release-doc drift check")
                || lower.contains("stale active claims")
                || lower.trim_start().starts_with("active `")
                || lower.trim_start().starts_with("claims that lima")
            {
                continue;
            }
            if lower.contains("7 hooks")
                || lower.contains("7 lsm")
                || lower.contains("seven hooks")
                || lower.contains("seven lsm")
            {
                failures.push(format!("{file}:{} stale hook-count claim: {line}", idx + 1));
            }
            if lower.contains("syva_cgroup_attach") {
                failures.push(format!(
                    "{file}:{} active removed hook symbol: {line}",
                    idx + 1
                ));
            }
            if lower.contains("cgroup_attach_task") {
                let start = idx.saturating_sub(2);
                let end = usize::min(idx + 3, lines.len());
                let window = lines[start..end].join(" ").to_ascii_lowercase();
                let allowed = [
                    "not a bpf-lsm hook",
                    "not enforced",
                    "known gap",
                    "out of v0.2 scope",
                    "does not attach",
                    "do not reintroduce",
                    "assert!",
                ]
                .iter()
                .any(|phrase| window.contains(phrase));
                if !allowed {
                    failures.push(format!(
                        "{file}:{} cgroup_attach_task must only appear as an explicit known gap: {line}",
                        idx + 1
                    ));
                }
            }
            if (lower.contains("lima proves runtime")
                || lower.contains("lima verifies runtime")
                || lower.contains("lima proves enforcement")
                || lower.contains("lima verifies enforcement"))
                && !(lower.contains("not") || lower.contains("unless"))
            {
                failures.push(format!(
                    "{file}:{} Lima runtime claim needs privileged BPF-LSM caveat: {line}",
                    idx + 1
                ));
            }
            if lower.contains("debug ebpf")
                && (lower.contains("default") || lower.contains("runtime artifact"))
            {
                let start = idx.saturating_sub(1);
                let end = usize::min(idx + 2, lines.len());
                let window = lines[start..end].join(" ").to_ascii_lowercase();
                if !window.contains("development") {
                    failures.push(format!(
                        "{file}:{} debug eBPF must not be described as the runtime default: {line}",
                        idx + 1
                    ));
                }
            }
        }
    }

    for file in [
        "README.md",
        "CLAUDE.md",
        "AGENT.md",
        "SKILLS.md",
        "docs/release/v0.2-runtime-verification.md",
    ] {
        let path = root.join(file);
        if !path.exists() {
            continue;
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read release gate doc {file}"))?;
        for gate in [
            "verify-runtime",
            "verify-integration",
            "verify-container-integration",
        ] {
            if !content.contains(gate) {
                failures.push(format!("{file} must mention release gate `{gate}`"));
            }
        }
    }

    if !failures.is_empty() {
        for failure in &failures {
            eprintln!("{failure}");
        }
        bail!("release documentation drift check failed");
    }

    println!("release documentation drift check ok");
    Ok(())
}

fn tracked_files() -> Result<Vec<String>> {
    let output = Command::new("git")
        .args(["ls-files"])
        .current_dir(project_root())
        .output()
        .context("failed to list tracked files")?;
    if !output.status.success() {
        bail!("git ls-files failed");
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect())
}

fn is_release_checked_file(file: &str) -> bool {
    if file.starts_with("docs/archive/") {
        return false;
    }
    matches!(
        file.rsplit('.').next(),
        Some("md" | "rs" | "proto" | "toml" | "yaml" | "yml")
    ) || matches!(
        file,
        "Makefile" | "AGENT.md" | "CLAUDE.md" | "README.md" | "SKILLS.md"
    )
}

fn build_eval_crates() -> Result<()> {
    run_root_command(
        "cargo",
        &["build", "--manifest-path", "eval/oracle/Cargo.toml"],
    )?;
    run_root_command(
        "cargo",
        &["build", "--manifest-path", "eval/harness/Cargo.toml"],
    )
}

/// Shared preflight for privileged runtime checks: Linux, root, `syva` group,
/// and an active BPF LSM. `context` names the check in error messages.
fn privileged_runtime_preflight(context: &str) -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("{context} requires Linux with BPF LSM support; macOS/Lima build checks are not runtime enforcement evidence");
    }

    let uid_output = Command::new("id")
        .arg("-u")
        .output()
        .context("failed to check current uid with id -u")?;
    let uid = String::from_utf8_lossy(&uid_output.stdout);
    if uid.trim() != "0" {
        bail!("{context} must be run as root so syva-core can load and attach BPF LSM programs");
    }

    let group_status = Command::new("getent")
        .args(["group", "syva"])
        .status()
        .context("failed to check for required syva group")?;
    if !group_status.success() {
        bail!("{context} requires a 'syva' group for the syva-core Unix socket");
    }

    let lsm = fs::read_to_string("/sys/kernel/security/lsm")
        .context("failed to read /sys/kernel/security/lsm; is securityfs mounted?")?;
    if !lsm.split(',').any(|entry| entry.trim() == "bpf") {
        bail!(
            "{context} requires BPF LSM; /sys/kernel/security/lsm is {}",
            lsm.trim()
        );
    }

    Ok(())
}

/// Run the privileged integration test that deploys the local core, attaches a
/// workload cgroup to a zone, and proves the kernel blocks a cross-zone read.
fn verify_integration() -> Result<()> {
    privileged_runtime_preflight("verify-integration")?;
    build_ebpf(true)?;
    run_root_command(
        "cargo",
        &[
            "test",
            "-p",
            "syva-core",
            "--test",
            "integration_file_open_enforcement",
            "--",
            "--ignored",
            "--nocapture",
        ],
    )
}

/// Run the privileged **container** integration test: deploy the local core and
/// prove a real container in zone-a is blocked from reading a zone-b file.
fn verify_container_integration() -> Result<()> {
    privileged_runtime_preflight("verify-container-integration")?;

    // Require a Docker-CLI-compatible container runtime up front so the failure
    // is clear (the target is real-container-only, never a process fallback).
    let runtime = std::env::var("SYVA_CONTAINER_RUNTIME").ok();
    let found = match &runtime {
        Some(r) => has_command(r),
        None => ["docker", "nerdctl", "podman"]
            .iter()
            .any(|r| has_command(r)),
    };
    if !found {
        bail!("verify-container-integration requires docker, nerdctl, podman, or another supported container runtime");
    }

    build_ebpf(true)?;
    run_root_command(
        "cargo",
        &[
            "test",
            "-p",
            "syva-core",
            "--test",
            "integration_container_file_open",
            "--",
            "--ignored",
            "--nocapture",
        ],
    )
}

fn has_command(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn verify_runtime() -> Result<()> {
    privileged_runtime_preflight("runtime verification")?;

    build_ebpf(true)?;

    run_root_command(
        "cargo",
        &[
            "test",
            "-p",
            "syva-core",
            "--test",
            "local_mode_starts_server",
            "--",
            "--ignored",
            "--nocapture",
        ],
    )?;
    run_root_command(
        "cargo",
        &[
            "test",
            "-p",
            "syva-core",
            "--test",
            "local_mode_register_then_list",
            "--",
            "--ignored",
            "--nocapture",
        ],
    )
}

fn run_root_command(program: &str, args: &[&str]) -> Result<()> {
    let root = project_root();
    let status = Command::new(program)
        .current_dir(root)
        .args(args)
        .status()
        .with_context(|| format!("failed to run {program} {}", args.join(" ")))?;
    if !status.success() {
        bail!("{program} {} failed", args.join(" "));
    }
    Ok(())
}
