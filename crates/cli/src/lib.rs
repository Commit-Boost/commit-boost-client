use std::process::Stdio;

use cb_common::{
    config::{CommitBoostConfig, CONFIG_PATH_ENV, MODULE_ID_ENV},
    utils::print_logo,
};
use cb_crypto::service::SigningService;
use cb_pbs::{BuilderState, DefaultBuilderApi, PbsService};
use clap::{Parser, Subcommand};
use metering::MetricsCollector;
use tokio::time::{sleep, Duration};

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Command,
    // /// Start with Holesky spec
    // #[arg(long, global = true)]
    // pub holesky: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Start {
        /// Path to config file
        config: String,
    },
}

impl Args {
    pub async fn run(self) -> eyre::Result<()> {
        print_logo();

        match self.cmd {
            Command::Start { config: config_path } => {
                // Initialize the MetricsCollector
                let collector = MetricsCollector::new();

                // Start gathering system metrics
                tokio::spawn({
                    let collector = collector.clone();
                    async move {
                        loop {
                            collector.gather_system_metrics().await;
                            sleep(Duration::from_secs(5)).await;
                        }
                    }
                });

                // Simulate external actors reporting custom metrics
                //TODO: move to custom "module"
                tokio::spawn({
                    let collector = collector.clone();
                    async move {
                        collector.report_custom_metric("service_status".to_string(), "running".to_string()).await;
                        collector.report_custom_metric("active_users".to_string(), "42".to_string()).await;
                    }
                });

                // Start the metrics server to expose metrics
                tokio::spawn({
                    async move {
                        collector.serve_metrics("0.0.0.0:8080").await;
                    }
                });

                let config = CommitBoostConfig::from_file(&config_path);

                if let Some(modules) = config.modules {
                    let signer_config = config.signer.expect("missing signer config with modules");

                    // this mocks the commit boost client starting containers, processes etc
                    let mut child_handles = Vec::with_capacity(modules.len());

                    for module in modules {
                        let child = std::process::Command::new(module.path)
                            .env(MODULE_ID_ENV, module.id)
                            .env(CONFIG_PATH_ENV, &config_path)
                            .spawn()
                            .expect("failed to start process");

                        child_handles.push(child);
                    }

                    // start signing server
                    tokio::spawn(SigningService::run(config.chain, signer_config));
                }

                // start pbs server
                if let Some(pbs_path) = config.pbs.path {
                    let cmd = std::process::Command::new(pbs_path)
                        .env(CONFIG_PATH_ENV, &config_path)
                        .stdout(Stdio::inherit())
                        .stderr(Stdio::inherit())
                        .output()
                        .expect("failed to start pbs module");

                    if !cmd.status.success() {
                        eprintln!("Process failed with status: {}", cmd.status);
                    }
                } else {
                    let state = BuilderState::<()>::new(config.chain, config.pbs);
                    PbsService::run::<(), DefaultBuilderApi>(state).await;
                }
            }
        }

        Ok(())
    }
}