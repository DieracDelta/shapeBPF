use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
enum Cli {
    /// Build the eBPF programs (both Rust tracepoints and C qdisc)
    BuildEbpf {
        /// Set the endianness of the BPF target
        #[clap(default_value = "bpfel-unknown-none", long)]
        target: String,
        /// Build in release mode
        #[clap(long)]
        release: bool,
    },
    /// Build eBPF programs and run the daemon
    Run {
        /// Build in release mode
        #[clap(long)]
        release: bool,
        /// Arguments to pass to the binary
        #[clap(last = true)]
        run_args: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::BuildEbpf { target, release } => build_ebpf(&target, release),
        Cli::Run { release, run_args } => {
            build_ebpf("bpfel-unknown-none", release)?;
            run(release, &run_args)
        }
    }
}

fn build_ebpf(target: &str, _release: bool) -> Result<()> {
    let workspace_root = workspace_root();
    let ebpf_dir = workspace_root.join("shapebpf-ebpf");

    let arch_feature = match std::env::consts::ARCH {
        "x86_64" => "arch-x86_64",
        "aarch64" => "arch-aarch64",
        other => bail!("unsupported architecture: {other}"),
    };

    // Phase 1: Build Rust eBPF (tracepoints) via cargo
    // Must be release mode - debug builds exceed BPF's function argument limit.
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args([
            "build",
            "--target",
            target,
            "-Z",
            "build-std=core",
            "--release",
            "--features",
            arch_feature,
        ])
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            ["-Cdebuginfo=2", "-Clink-arg=--btf"].join("\x1f"),
        );

    let status = cmd.status().context("failed to build Rust eBPF programs")?;
    if !status.success() {
        bail!("Rust eBPF build failed with status: {}", status);
    }

    // Phase 2: Build C eBPF programs via clang
    ensure_vmlinux_h(&workspace_root)?;
    build_c_bpf(&workspace_root, "qdisc")?;
    build_c_bpf(&workspace_root, "ingress")?;

    Ok(())
}

/// Generate vmlinux.h if it doesn't exist.
fn ensure_vmlinux_h(workspace_root: &PathBuf) -> Result<()> {
    let vmlinux_h = workspace_root.join("shapebpf-ebpf/src/bpf/vmlinux.h");
    if !vmlinux_h.exists() {
        let status = Command::new("bpftool")
            .args(["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
            .stdout(std::fs::File::create(&vmlinux_h).context("creating vmlinux.h")?)
            .status()
            .context("running bpftool to generate vmlinux.h")?;
        if !status.success() {
            bail!("bpftool btf dump failed with status: {}", status);
        }
    }
    Ok(())
}

/// Compile a C BPF source file: src/bpf/{name}.bpf.c → target/bpf/{name}.bpf.o
fn build_c_bpf(workspace_root: &PathBuf, name: &str) -> Result<()> {
    let ebpf_dir = workspace_root.join("shapebpf-ebpf");
    let src = ebpf_dir.join(format!("src/bpf/{name}.bpf.c"));
    let out_dir = ebpf_dir.join("target/bpf");
    let out = out_dir.join(format!("{name}.bpf.o"));

    std::fs::create_dir_all(&out_dir).context("creating target/bpf directory")?;

    let target_arch = match std::env::consts::ARCH {
        "x86_64" => "__TARGET_ARCH_x86",
        "aarch64" => "__TARGET_ARCH_arm64",
        other => bail!("unsupported architecture for C eBPF: {other}"),
    };

    let mut cmd = Command::new("clang");
    // Disable nix hardening flags (e.g. -fzero-call-used-regs) that are
    // unsupported for the BPF target.
    cmd.env("NIX_HARDENING_ENABLE", "");
    cmd.args([
        "-target",
        "bpf",
        "-g",
        "-O2",
        "-Wall",
        &format!("-D{target_arch}"),
        "-I",
        ebpf_dir.join("src/bpf").to_str().unwrap(),
    ]);

    // Add libbpf include path (for bpf_helpers.h etc.)
    if let Ok(libbpf_inc) = std::env::var("LIBBPF_INCLUDE") {
        cmd.args(["-I", &libbpf_inc]);
    } else {
        // Try pkg-config
        let pkg = Command::new("pkg-config")
            .args(["--cflags", "libbpf"])
            .output();
        if let Ok(output) = pkg {
            if output.status.success() {
                let flags = String::from_utf8_lossy(&output.stdout);
                for flag in flags.split_whitespace() {
                    cmd.arg(flag);
                }
            }
        }
    }

    cmd.args([
        "-c",
        src.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]);

    let status = cmd.status().with_context(|| format!("failed to compile {name}.bpf.c"))?;
    if !status.success() {
        bail!("{name}.bpf.c compilation failed with status: {}", status);
    }

    Ok(())
}

fn run(release: bool, run_args: &[String]) -> Result<()> {
    let workspace_root = workspace_root();

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&workspace_root)
        .args(["build", "--package", "shapebpf", "--bin", "shapebpf-daemon"]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to build daemon")?;
    if !status.success() {
        bail!("daemon build failed with status: {}", status);
    }

    let profile = if release { "release" } else { "debug" };
    let bin = workspace_root
        .join("target")
        .join(profile)
        .join("shapebpf-daemon");

    let mut cmd = Command::new("sudo");
    cmd.arg(bin);
    cmd.args(run_args);

    let status = cmd.status().context("failed to run shapebpf-daemon")?;
    if !status.success() {
        bail!("shapebpf-daemon exited with status: {}", status);
    }

    Ok(())
}

fn workspace_root() -> PathBuf {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version=1", "--no-deps"])
        .output()
        .expect("failed to run cargo metadata");

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("failed to parse cargo metadata");

    PathBuf::from(
        metadata["workspace_root"]
            .as_str()
            .expect("workspace_root not found"),
    )
}
