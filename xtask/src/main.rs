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
    /// Check the active Rust workspace.
    Check,
    /// Run workspace tests.
    Test,
    /// Run the Linux/eBPF compile check.
    LinuxBpfCheck,
    /// Build eval/oracle and eval/harness so contract tests do not bitrot.
    EvalBuild,
    /// Run ignored privileged runtime verification tests.
    VerifyRuntime,
    /// Run the standard active-project CI sequence.
    Ci,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli {
        Cli::BuildEbpf { release, debug } => build_ebpf(release || !debug),
        Cli::Fmt => run_root_command("cargo", &["fmt", "--all", "--", "--check"]),
        Cli::Check => run_root_command("cargo", &["check", "--workspace"]),
        Cli::Test => run_root_command("cargo", &["test", "--workspace"]),
        Cli::LinuxBpfCheck => build_ebpf(true),
        Cli::EvalBuild => build_eval_crates(),
        Cli::VerifyRuntime => verify_runtime(),
        Cli::Ci => {
            run_root_command("cargo", &["fmt", "--all", "--", "--check"])?;
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
            )?;
            run_root_command("cargo", &["check", "--workspace"])?;
            run_root_command("cargo", &["test", "--workspace"])?;
            build_eval_crates()?;
            build_ebpf(true)
        }
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

fn verify_runtime() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("runtime verification requires Linux with BPF LSM support; Lima build checks are not runtime enforcement evidence");
    }

    let uid_output = Command::new("id")
        .arg("-u")
        .output()
        .context("failed to check current uid with id -u")?;
    let uid = String::from_utf8_lossy(&uid_output.stdout);
    if uid.trim() != "0" {
        bail!("runtime verification must be run as root so syva-core can load and attach BPF LSM programs");
    }

    let group_status = Command::new("getent")
        .args(["group", "syva"])
        .status()
        .context("failed to check for required syva group")?;
    if !group_status.success() {
        bail!("runtime verification requires a 'syva' group for the syva-core Unix socket");
    }

    let lsm = fs::read_to_string("/sys/kernel/security/lsm")
        .context("failed to read /sys/kernel/security/lsm; is securityfs mounted?")?;
    if !lsm.split(',').any(|entry| entry.trim() == "bpf") {
        bail!(
            "runtime verification requires BPF LSM; /sys/kernel/security/lsm is {}",
            lsm.trim()
        );
    }

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
