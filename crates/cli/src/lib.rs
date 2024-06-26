use std::process::Stdio;
use std::env;

use cb_common::{
    config::{CommitBoostConfig, CONFIG_PATH_ENV, MODULE_ID_ENV},
    utils::print_logo,
};
use cb_crypto::service::SigningService;
use cb_pbs::{BuilderState, DefaultBuilderApi, PbsService};
use clap::{Parser, Subcommand};
use cb_metrics::docker_metrics_collector::DockerMetricsCollector;


#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Command
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

                    // start monitoring tasks for spawned modules
                    // TODO: this needs to integrate with docker module instantiation
                    let container_id = env::var("MOCK_CONTAINER_ID").expect("MOCK_CONTAINER_ID not set");
                    let metrics_config = config.metrics.expect("missing metrics config");
                    tokio::spawn(async move {
                        DockerMetricsCollector::new(vec![
                            container_id
                        ], metrics_config.address, metrics_config.jwt_path).await
                    });   

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