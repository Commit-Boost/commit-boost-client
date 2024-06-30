use std::time::Duration;

use cb_common::{config::CommitBoostConfig, utils::initialize_tracing_log};
use cb_tests::mock_validator::MockValidator;
use clap::Parser;
use tokio::time::sleep;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    initialize_tracing_log();

    info!("Starting mock validator");

    let args = cb_cli::Args::parse();

    match args.cmd {
        cb_cli::Command::Init { .. } => {
            unreachable!()
        }
        cb_cli::Command::Start { .. } => {
            unreachable!()
        }
        cb_cli::Command::Start2 { config } => {
            let config = CommitBoostConfig::from_file(&config);

            let mock_validator = MockValidator::new(config.pbs.pbs_config.address);

            loop {
                if let Err(err) = mock_validator.do_get_status().await {
                    error!(?err, "failed to get status")
                } else {
                    info!("Get status successful")
                };

                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}
