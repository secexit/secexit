use anyhow::Context;
use clap::Parser;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
struct Opts {
    #[clap(subcommand)]
    cmd: CommandEnum,
}

#[derive(clap::Subcommand)]
enum CommandEnum {
    BuildEbpf {
        #[clap(long)]
        release: bool,
    },
    BuildDaemon {
        #[clap(long)]
        release: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    match opts.cmd {
        CommandEnum::BuildEbpf { release } => build_ebpf(release),
        CommandEnum::BuildDaemon { release } => build_daemon(release),
    }
}

fn build_ebpf(release: bool) -> anyhow::Result<()> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let workspace_dir = manifest_dir
        .parent()
        .context("failed to determine workspace root: manifest_dir has no parent")?;

    // The crate name for the kernel code
    let package = "secexit-ebpf";

    let mut args = vec![
        "build",
        "--package",
        package,
        "--target",
        "bpfel-unknown-none", // The generic BPF target (Little Endian)
        "-Z",
        "build-std=core", // Required for no_std environments
    ];

    if release {
        args.push("--release");
    }

    println!("Building eBPF program: cargo {}", args.join(" "));

    let status = Command::new("cargo")
        .current_dir(workspace_dir)
        .args(&args)
        .status()
        .context("Failed to build eBPF program")?;

    if !status.success() {
        anyhow::bail!("eBPF build failed");
    }

    println!("eBPF Program compiled successfully!");
    Ok(())
}

fn build_daemon(release: bool) -> anyhow::Result<()> {
    let mut args = vec!["build", "--package", "secexit-daemon"];
    if release {
        args.push("--release");
    }

    Command::new("cargo").args(&args).status()?;
    Ok(())
}
