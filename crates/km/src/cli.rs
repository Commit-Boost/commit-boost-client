//! `commit-boost builder-config`: prints each validator key's keymanager
//! builder config, or writes it to validator clients.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::atomic::{AtomicUsize, Ordering},
};

use clap::{Args, Subcommand};
use eyre::{Context, Result, ensure};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::{
    EnvFilter, Layer,
    filter::LevelFilter,
    layer::{Context as LayerContext, SubscriberExt},
    util::SubscriberInitExt,
};

use crate::{
    apply::{ApplyOptions, LODESTAR_CAP_FLAG, run_apply},
    output,
    printed::Printed,
    project::{Projection, mux_keys, parse_config, project},
    targets::{Targets, VcConfig, check_advertised_url},
};

#[derive(Args, Debug)]
pub struct BuilderConfigArgs {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print each key's builder config as JSON, contacting no validator client
    Print {
        /// Commit-Boost config TOML
        #[arg(long, env = "CB_CONFIG")]
        config: PathBuf,
        /// Commit-Boost's URL as the beacon nodes reach it, written into
        /// every entry
        #[arg(long)]
        advertised_url: String,
    },
    /// Write the builder config of every key the validator clients hold
    Apply {
        /// Commit-Boost config TOML
        #[arg(long, env = "CB_CONFIG")]
        config: Option<PathBuf>,
        /// A document `print` wrote, or `-` for stdin, in place of the
        /// Commit-Boost config
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
        /// Commit-Boost's URL as the beacon nodes reach it, written into
        /// every entry
        #[arg(long)]
        advertised_url: String,
        /// A validator client to write to, as `<keymanager URL>=<token
        /// file>`; repeat for each
        #[arg(long = "vc", value_name = "URL=TOKEN_FILE")]
        vcs: Vec<VcConfig>,
        /// Keep each stored builder entry at a URL other than the advertised
        /// one, which a write otherwise erases
        #[arg(long)]
        preserve_entries: bool,
        /// The validator clients given are only some of those holding the
        /// muxes' keys, such as one pod's: count a mux key none of them holds
        /// instead of failing on it
        #[arg(long)]
        partial: bool,
    },
}

fn read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).wrap_err_with(|| format!("unable to read {path:?}"))
}

/// Warnings the loaders log, such as a fallback to the SSV public API, for the
/// closing tally
static LOADER_WARNINGS: AtomicUsize = AtomicUsize::new(0);

struct CountWarnings;

impl<S: Subscriber> Layer<S> for CountWarnings {
    fn on_event(&self, event: &Event<'_>, _: LayerContext<'_, S>) {
        if *event.metadata().level() <= Level::WARN {
            LOADER_WARNINGS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The loaders' own warnings go to stderr. `RUST_LOG` adds directives but
/// cannot hide these, which one set for another program would
fn init_logging() {
    // A bare level replaces `warn` rather than adding to it, so one below it,
    // such as `error` or `off`, is dropped
    let rust_log = std::env::var("RUST_LOG").unwrap_or_default();
    let quieter = |directive: &str| {
        directive.trim().parse::<LevelFilter>().is_ok_and(|level| level < LevelFilter::WARN)
    };
    let directives: Vec<&str> =
        rust_log.split(',').filter(|directive| !quieter(directive)).collect();
    let filter = format!("warn,{}", directives.join(","));
    tracing_subscriber::registry()
        .with(EnvFilter::builder().parse_lossy(filter))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(std::io::stderr().is_terminal())
                .with_target(false)
                .without_time(),
        )
        .with(CountWarnings)
        .init();
}

/// Runs `builder-config`: 0 ok, 1 an error once the config is read, 2 stopped
/// before contacting any validator client
pub async fn run(args: BuilderConfigArgs) -> ExitCode {
    init_logging();
    let result = match args.command {
        Command::Print { config, advertised_url } => print(&config, &advertised_url).await,
        Command::Apply { config, from, advertised_url, vcs, preserve_entries, partial } => {
            apply(config, from, advertised_url, vcs, ApplyOptions {
                preserve_entries,
                partial,
                print: true,
            })
            .await
        }
    };
    match result {
        Ok(code) => code,
        // Both fail only before a validator client is contacted
        Err(err) => {
            output::err(format_args!("ERROR: {err:#}"));
            ExitCode::from(2)
        }
    }
}

async fn resolve(config: &Path, advertised_url: &str) -> Result<Projection> {
    let cfg = parse_config(&read(config)?)?;
    let projection = project(&cfg, &mux_keys(&cfg).await?, advertised_url)?;
    ensure!(
        !projection.mux_docs.is_empty() || projection.relays_doc.is_some(),
        "nothing to write: the config has no mux keys and no [[relays]]"
    );
    Ok(projection)
}

/// Each mux's key count, to show a stale or wrong keys file
fn mux_counts(projection: &Projection) -> BTreeMap<&str, usize> {
    let mut counts = BTreeMap::new();
    for id in projection.mux_ids.values() {
        *counts.entry(id.as_str()).or_default() += 1;
    }
    counts
}

/// stdout carries only the document, so its counts and notes go to stderr
async fn print(config: &Path, advertised_url: &str) -> Result<ExitCode> {
    check_advertised_url(advertised_url)?;
    let projection = resolve(config, advertised_url).await?;
    for (id, count) in mux_counts(&projection) {
        output::err(format_args!("mux {id}: {count} keys"));
    }
    if projection.has_nonzero_cap() {
        output::err(format_args!(
            "NOTE: the builder config sets a max_execution_payment above 0, which a Lodestar \
             validator client refuses unless it runs with {LODESTAR_CAP_FLAG}"
        ));
    }
    let printed = Printed::new(&projection, advertised_url);
    let mut stdout = std::io::stdout().lock();
    let written = serde_json::to_writer_pretty(&mut stdout, &printed)
        .map_err(std::io::Error::from)
        .and_then(|()| writeln!(stdout))
        .and_then(|()| stdout.flush());
    if let Err(err) = written {
        output::err(format_args!("ERROR: could not write the document: {err}"));
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

/// The printed document at `from`, or on stdin for `-`
fn read_printed(from: &Path) -> Result<Printed> {
    let text = if from == Path::new("-") {
        ensure!(
            !std::io::stdin().is_terminal(),
            "--from -: stdin is a terminal; pipe in the document `print` wrote"
        );
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text).wrap_err("unable to read stdin")?;
        text
    } else {
        read(from)?
    };
    Printed::parse(&text).wrap_err_with(|| format!("{from:?} is not a printed document"))
}

async fn apply(
    config: Option<PathBuf>,
    from: Option<PathBuf>,
    advertised_url: String,
    vcs: Vec<VcConfig>,
    opts: ApplyOptions,
) -> Result<ExitCode> {
    ensure!(!vcs.is_empty(), "no validator client given: pass --vc <keymanager URL>=<token file>");
    let targets = Targets::new(advertised_url, vcs)?;
    targets.check_token_files()?;
    // `--config` may come from CB_CONFIG, so `--from` wins over it
    let projection = match (from, config) {
        (Some(from), _) => read_printed(&from)?.into_projection(&targets.advertised_url)?,
        (None, Some(config)) => resolve(&config, &targets.advertised_url).await?,
        (None, None) => eyre::bail!("pass --config, set CB_CONFIG, or pass --from"),
    };
    for (id, count) in mux_counts(&projection) {
        output::out(format_args!("mux {id}: {count} keys"));
    }

    let report = run_apply(&projection, &targets, &opts).await?;
    let written: usize = report.accepted.values().map(Vec::len).sum();
    let clients = report.accepted.values().flatten().collect::<BTreeSet<_>>().len();
    output::out(format_args!(
        "done: {written} keys written, {} not written, on {clients} of {} validator clients; {} \
         errors, {} warnings",
        report.unwritten,
        targets.vcs.len(),
        report.errors.len(),
        report.warnings.len() + LOADER_WARNINGS.load(Ordering::Relaxed)
    ));
    Ok(if report.errors.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}
