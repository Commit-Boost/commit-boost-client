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
    about = "Project a Commit-Boost mux config into keymanager builder_config docs",
    after_help = "WARNING: check-green does not mean apply-is-a-no-op: GET returns resolved docs, \
                  so third-party-pinned values for fields the projection omits (boost, cap) are \
                  invisible to check and will be ERASED by apply (POST replaces in full). Pass \
                  `apply --preserve-entries` to fold any builder entry another writer pinned back \
                  into the POST instead of erasing it."
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
    /// Operational overlay TOML (advertised_url, vcs)
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
        /// GET each key first and keep any builder entry pinned by another
        /// writer (identity = url + auth_data) that our projection does not
        /// produce, so the full-replace POST does not erase it. Off by default
        /// (today's exact-projection replace). Fails loudly if the merge would
        /// break a KM cap (e.g. >64 entries) rather than dropping an entry.
        /// (read-modify-write; not atomic vs a concurrent writer -- the
        /// entry-level PATCH endpoint is the real fix).
        #[arg(long)]
        preserve_entries: bool,
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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();

    match cli.command {
        Command::Apply { common, dry_run, emit, prune, preserve_entries } => {
            let (input, overlay) = load(&common)?;
            let opts = ApplyOptions { dry_run, emit_dir: emit, prune, preserve_entries };
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
