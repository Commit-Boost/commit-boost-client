use std::path::PathBuf;

use cb_km_tool::{
    Overlay, ProjectionInput,
    apply::{ApplyOptions, run_apply},
    check::{Tier, run_check},
};
use clap::{Parser, Subcommand, ValueEnum};
use eyre::Result;

#[derive(Parser)]
#[command(
    name = "cb-km",
    about = "Project a Commit-Boost mux config into keymanager builder_config docs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct CommonArgs {
    /// Commit-Boost config TOML
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,
    /// Operational overlay TOML (advertised_url, vcs, per_mux)
    #[arg(long, default_value = "km-overlay.toml")]
    overlay: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// POST projected docs to the configured VCs
    Apply {
        #[command(flatten)]
        common: CommonArgs,
        /// Print the projected docs without contacting any VC
        #[arg(long)]
        dry_run: bool,
        /// Write per-key JSON docs plus a manifest to a directory instead of
        /// POSTing
        #[arg(long, value_name = "DIR")]
        emit: Option<PathBuf>,
        /// POST {} for stored-but-unprojected enumerated keys
        #[arg(long)]
        prune: bool,
    },
    /// Compare the stored VC docs against the projection (read-only)
    Check {
        #[command(flatten)]
        common: CommonArgs,
        /// Lowest finding tier that makes the exit code non-zero
        #[arg(long, value_enum, default_value_t = FailOn::Error)]
        fail_on: FailOn,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    Info,
    Warn,
    Error,
}

impl From<FailOn> for Tier {
    fn from(value: FailOn) -> Self {
        match value {
            FailOn::Info => Tier::Info,
            FailOn::Warn => Tier::Warn,
            FailOn::Error => Tier::Error,
        }
    }
}

fn load(common: &CommonArgs) -> Result<(ProjectionInput, Overlay)> {
    Ok((ProjectionInput::from_file(&common.config)?, Overlay::from_file(&common.overlay)?))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let cli = Cli::parse();

    match cli.command {
        Command::Apply { common, dry_run, emit, prune } => {
            let (input, overlay) = load(&common)?;
            let opts = ApplyOptions { dry_run, emit_dir: emit, prune };
            let report = run_apply(&input, &overlay, &opts).await?;
            for msg in &report.info {
                println!("{msg}");
            }
            for msg in &report.warnings {
                println!("WARN: {msg}");
            }
            for (key, vcs) in &report.accepted {
                println!("accepted: {key} on {vcs:?}");
            }
            for (vc, key) in &report.pruned {
                println!("pruned: {key} on {vc}");
            }
            for msg in &report.errors {
                eprintln!("ERROR: {msg}");
            }
            if !report.ok() {
                std::process::exit(1);
            }
        }
        Command::Check { common, fail_on } => {
            let (input, overlay) = load(&common)?;
            let report = run_check(&input, &overlay).await?;
            for finding in &report.findings {
                println!("{} [{}] {}", finding.tier, finding.code, finding.msg);
            }
            if report.fails(fail_on.into()) {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
