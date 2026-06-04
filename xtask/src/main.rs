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
    /// Check Rust formatting.
    Fmt,
    /// Check the active Rust workspace.
    Check,
    /// Run workspace tests.
    Test,
    /// Run the Linux/eBPF compile check.
    LinuxBpfCheck,
    /// Run the standard active-project CI sequence.
    Ci,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli {
        Cli::BuildEbpf { release } => build_ebpf(release),
        Cli::Fmt => run_root_command("cargo", &["fmt", "--all", "--", "--check"]),
        Cli::Check => run_root_command("cargo", &["check", "--workspace"]),
        Cli::Test => run_root_command("cargo", &["test", "--workspace"]),
        Cli::LinuxBpfCheck => build_ebpf(false),
        Cli::Ci => {
            run_root_command("cargo", &["fmt", "--all", "--", "--check"])?;
            run_root_command("cargo", &["check", "--workspace"])?;
            run_root_command("cargo", &["test", "--workspace"])?;
            build_ebpf(false)
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
