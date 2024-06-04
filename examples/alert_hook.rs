use cb_cli::runner::Runner;
use cb_common::utils::initialize_tracing_log;
use cb_pbs::{BuilderEvent, BuilderEventReceiver, BuilderState, DefaultBuilderApi};
use clap::Parser;

const HOOK_ID: &str = "DISCORD_ALERT";

fn alert_discord(msg: &str) {
    println!("{msg}")
}

async fn alert_missed_slots(mut rx: BuilderEventReceiver) -> eyre::Result<()> {
    while let Ok(data) = rx.recv().await {
        if let BuilderEvent::MissedPayload { block_hash, relays } = data {
            alert_discord(&format!(
                "Missed payload with block hash {block_hash} from relays: {relays}"
            ));
        }
    }

    alert_discord("MEV boost has stopped running and may have crashed. Check logs");

    Ok(())
}

#[tokio::main]
async fn main() {
    initialize_tracing_log();

    let (chain, config) = cb_cli::Args::parse().to_config();

    let state = BuilderState::new(chain, config);
    let mut runner = Runner::<(), DefaultBuilderApi>::new(state);

    runner.add_boost_hook(HOOK_ID, alert_missed_slots);

    if let Err(err) = runner.run().await {
        eprintln!("Error: {err}");
        std::process::exit(1)
    };
}
