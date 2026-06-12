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
    /// Check API documentation covers the current local API.
    CheckApiDocs,
    /// Check the versioned syvactl command contract.
    CheckSyvactlContract,
    /// Check the REST OpenAPI document parses and covers implemented paths.
    CheckOpenapi,
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
    /// Run the privileged Kubernetes membership integration test: an annotated
    /// pod is attached by syva-k8s and blocked by file_open enforcement.
    VerifyK8sMembership,
    /// Run the privileged audit-mode integration test: a cross-zone read is
    /// recorded as a would-deny decision but NOT blocked.
    VerifyAuditMode,
    /// Run the privileged network-lock test: an Isolated zone is denied
    /// non-loopback connect/sendmsg/bind (loopback only) while a Bridged zone
    /// is allowed out.
    VerifyNetworkLock,
    /// Run the privileged egress-CIDR test: a locked zone reaches only its
    /// allowlisted CIDR; all other destinations stay denied.
    VerifyEgressCidr,
    /// Run the privileged cross-zone TCP test: exact IPv4 destination IPs map
    /// to zones and use the existing zone-pair rule.
    VerifyCrossZoneTcp,
    /// Run the privileged cgroup-escape detection test: a zoned task migrating
    /// out of its zone is detected (counter + degraded health), not prevented.
    VerifyCgroupEscape,
    /// Run the privileged (dev, ino) identity test: an inode-number collision
    /// across two filesystems must not cause cross-zone confusion.
    VerifyInodeIdentity,
    /// Verify an already-deployed syva-core (SYVA_SOCKET) blocks a real
    /// container's cross-zone file_open. Does not start its own core.
    VerifyDeployment,
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
        Cli::CheckApiDocs => check_api_docs(),
        Cli::CheckSyvactlContract => check_syvactl_contract(),
        Cli::CheckOpenapi => check_openapi(),
        Cli::CheckReleaseDocs => check_release_docs(),
        Cli::CheckEbpfArtifactPolicy => check_ebpf_artifact_policy(),
        Cli::Precommit => precommit(),
        Cli::VerifyRuntime => verify_runtime(),
        Cli::VerifyIntegration => verify_integration(),
        Cli::VerifyContainerIntegration => verify_container_integration(),
        Cli::VerifyK8sMembership => verify_k8s_membership(),
        Cli::VerifyAuditMode => verify_audit_mode(),
        Cli::VerifyNetworkLock => verify_network_lock(),
        Cli::VerifyEgressCidr => verify_egress_cidr(),
        Cli::VerifyCrossZoneTcp => verify_cross_zone_tcp(),
        Cli::VerifyCgroupEscape => verify_cgroup_escape(),
        Cli::VerifyInodeIdentity => verify_inode_identity(),
        Cli::VerifyDeployment => verify_deployment(),
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

fn check_api_docs() -> Result<()> {
    let root = project_root();
    for file in [
        "docs/api/grpc.md",
        "docs/api/api-compatibility.md",
        "docs/api/cli.md",
        "docs/api/syvactl-command-contract.md",
        "docs/api/syva-api.openapi.yaml",
    ] {
        if !root.join(file).exists() {
            bail!("missing API documentation file: {file}");
        }
    }

    let grpc = fs::read_to_string(root.join("docs/api/grpc.md"))
        .context("failed to read docs/api/grpc.md")?;
    for required in [
        "syva.core.v1",
        "RegisterZone",
        "RemoveZone",
        "ListZones",
        "AttachContainer",
        "DetachContainer",
        "AllowComm",
        "DenyComm",
        "ListComms",
        "RegisterHostPath",
        "Status",
        "WatchEvents",
        "generation `0`",
        "ok: false",
    ] {
        if !grpc.contains(required) {
            bail!("docs/api/grpc.md must mention `{required}`");
        }
    }

    let cli = fs::read_to_string(root.join("docs/api/cli.md"))
        .context("failed to read docs/api/cli.md")?;
    for required in [
        "syvactl status",
        "syvactl zones list",
        "syvactl comms list",
        "syvactl events --follow",
    ] {
        if !cli.contains(required) {
            bail!("docs/api/cli.md must mention `{required}`");
        }
    }

    check_syvactl_contract()?;

    println!("API documentation check ok");
    Ok(())
}

fn check_syvactl_contract() -> Result<()> {
    let root = project_root();
    let path = root.join("docs/api/syvactl-command-contract.md");
    let content =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;

    for required in [
        "Contract: `syvactl/v0.1`",
        "Status: Draft",
        "Source of truth: `syva.core.v1` gRPC API",
        "syvactl status",
        "syvactl zones list",
        "syvactl comms list",
        "syvactl events --follow",
        "syvactl zones register",
        "syvactl zones remove",
        "syvactl host-paths register",
        "syvactl comms allow",
        "syvactl comms deny",
        "syvactl containers attach",
        "syvactl containers detach",
        "--socket <path>",
        "--format <text|json>",
        "Exit Codes",
        "JSON output is the stable scripting interface",
    ] {
        if !content.contains(required) {
            bail!("docs/api/syvactl-command-contract.md must mention `{required}`");
        }
    }

    if content.contains("cgroup_attach_task") {
        bail!("syvactl command contract must not contain active cgroup_attach_task claims");
    }

    println!("syvactl command contract check ok");
    Ok(())
}

fn check_openapi() -> Result<()> {
    let root = project_root();
    let path = root.join("docs/api/syva-api.openapi.yaml");
    let content =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: serde_yaml::Value =
        serde_yaml::from_str(&content).context("failed to parse OpenAPI YAML")?;
    let paths = value
        .get("paths")
        .and_then(|value| value.as_mapping())
        .context("OpenAPI document must contain a paths mapping")?;
    for path in ["/healthz", "/v1/zones", "/v1/zones/{name}"] {
        if !paths.contains_key(serde_yaml::Value::String(path.to_string())) {
            bail!("OpenAPI document must describe `{path}`");
        }
    }
    println!("OpenAPI check ok");
    Ok(())
}

fn precommit() -> Result<()> {
    fmt()?;
    lint()?;
    run_root_command("cargo", &["test", "--workspace"])?;
    check_proto()?;
    check_api_docs()?;
    check_openapi()?;
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
    check_api_docs()?;
    check_openapi()?;
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
            if in_fence {
                continue;
            }
            // v0.4 grew the hook set to nine (added socket connect/sendmsg/bind).
            // Reject any stale count that is not nine.
            if lower.contains("7 hooks")
                || lower.contains("7 lsm")
                || lower.contains("seven hooks")
                || lower.contains("seven lsm")
                || lower.contains("8 hooks")
                || lower.contains("8 lsm")
                || lower.contains("eight hooks")
                || lower.contains("eight lsm")
                || lower.contains("10 hooks")
                || lower.contains("ten hooks")
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
                    // The v0.4 escape detector references the function by name.
                    // These framings all assert detection, never prevention —
                    // the honest form of the known gap.
                    "detection only",
                    "detector",
                    "detected",
                    "not prevented",
                    "cannot prevent",
                    "cannot block",
                    "best-effort",
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

/// Run the privileged audit-mode integration test: same setup as
/// verify-integration but with the core in --mode audit. The cross-zone read
/// must SUCCEED while the deny counter records the would-deny decision.
fn verify_audit_mode() -> Result<()> {
    privileged_runtime_preflight("verify-audit-mode")?;
    build_ebpf(true)?;
    run_root_command(
        "cargo",
        &[
            "test",
            "-p",
            "syva-core",
            "--test",
            "integration_audit_mode",
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

/// Run the privileged network-lock integration test: an Isolated zone is denied
/// non-loopback connect/sendmsg/bind (EPERM, per-hook deny_delta=1) while a
/// Bridged zone is allowed out.
fn verify_network_lock() -> Result<()> {
    privileged_runtime_preflight("verify-network-lock")?;
    build_ebpf(true)?;
    run_root_command(
        "cargo",
        &[
            "test",
            "-p",
            "syva-core",
            "--test",
            "integration_network_lock",
            "--",
            "--ignored",
            "--nocapture",
        ],
    )
}

/// Run the privileged cgroup-escape detection test: a zoned workload moved out
/// of its cgroup is detected (counter + degraded health). Detection only — the
/// migration is not prevented (no BPF-LSM hook can block it).
fn verify_cgroup_escape() -> Result<()> {
    privileged_runtime_preflight("verify-cgroup-escape")?;
    build_ebpf(true)?;
    run_root_command(
        "cargo",
        &[
            "test",
            "-p",
            "syva-core",
            "--test",
            "integration_cgroup_escape",
            "--",
            "--ignored",
            "--nocapture",
        ],
    )
}

/// Run the privileged egress-CIDR integration test: a network-locked zone may
/// reach only the destinations its CIDR allowlist permits.
fn verify_egress_cidr() -> Result<()> {
    privileged_runtime_preflight("verify-egress-cidr")?;
    build_ebpf(true)?;
    run_root_command(
        "cargo",
        &[
            "test",
            "-p",
            "syva-core",
            "--test",
            "integration_egress_cidr",
            "--",
            "--ignored",
            "--nocapture",
        ],
    )
}

/// Run the privileged (dev, ino) identity test: a cross-filesystem inode
/// collision is not zone-confused (allowed, deny_delta=0) while the genuinely
/// zoned file is still denied with EPERM.
fn verify_inode_identity() -> Result<()> {
    privileged_runtime_preflight("verify-inode-identity")?;
    build_ebpf(true)?;
    run_root_command(
        "cargo",
        &[
            "test",
            "-p",
            "syva-core",
            "--test",
            "integration_inode_identity",
            "--",
            "--ignored",
            "--nocapture",
        ],
    )
}

/// Run the privileged cross-zone TCP integration test: exact IPv4 pod-IP to
/// zone mappings feed the socket_connect hook, which applies ZONE_ALLOWED_COMMS.
fn verify_cross_zone_tcp() -> Result<()> {
    privileged_runtime_preflight("verify-cross-zone-tcp")?;
    build_ebpf(true)?;
    run_root_command(
        "cargo",
        &[
            "test",
            "-p",
            "syva-core",
            "--test",
            "integration_cross_zone_tcp",
            "--",
            "--ignored",
            "--nocapture",
        ],
    )
}

/// Run the privileged Kubernetes membership integration test. This starts a
/// local core and adapter, uses the current kubectl context, and requires the
/// cluster node to share the host /proc and cgroup namespace with this process.
fn verify_k8s_membership() -> Result<()> {
    privileged_runtime_preflight("verify-k8s-membership")?;

    if !has_command("kubectl") {
        bail!("verify-k8s-membership requires kubectl configured for a single-node Kubernetes cluster on this host");
    }
    if !has_command("curl") {
        bail!("verify-k8s-membership requires curl for adapter metrics checks");
    }

    build_ebpf(true)?;
    run_root_command("bash", &["scripts/verify-k8s-membership.sh"])
}

/// Verify an ALREADY-DEPLOYED syva-core. Unlike verify-container-integration,
/// this does not build the eBPF object or start a core — it targets the running
/// instance at SYVA_SOCKET and runs the container test in existing-core mode.
fn verify_deployment() -> Result<()> {
    privileged_runtime_preflight("verify-deployment")?;

    let runtime = std::env::var("SYVA_CONTAINER_RUNTIME").ok();
    let found = match &runtime {
        Some(r) => has_command(r),
        None => ["docker", "nerdctl", "podman"]
            .iter()
            .any(|r| has_command(r)),
    };
    if !found {
        bail!("verify-deployment requires docker, nerdctl, podman, or another supported container runtime");
    }

    let socket = std::env::var("SYVA_SOCKET").map_err(|_| {
        anyhow::anyhow!(
            "verify-deployment requires SYVA_SOCKET=<path> pointing at a deployed syva-core (run `make lima-deploy` first)"
        )
    })?;
    if !PathBuf::from(&socket).exists() {
        bail!("syva-core socket {socket} not found — is syva-core deployed and running? (make lima-deploy)");
    }

    // SYVA_SOCKET is inherited by the test process and selects existing-core mode.
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
