use std::process::Stdio;

use cb_common::{
    config::{CommitBoostConfig, CONFIG_PATH_ENV, MODULE_ID_ENV},
    utils::print_logo,
};
use cb_crypto::service::SigningService;
use cb_pbs::{BuilderState, DefaultBuilderApi, PbsService};
use clap::{Parser, Subcommand};
use metering::{MetricsCollector, DockerMetricsCollector};
use std::sync::Arc;

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

async fn metrics_collector_task(collector: Arc<dyn MetricsCollector>, addr: &'static str) {
    collector.collect_metrics().await;
    collector.serve_metrics(addr).await;
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
                    let docker_collector = Arc::new(DockerMetricsCollector::new(vec![
                        "container_id_1".to_string(),
                        "container_id_2".to_string(),
                        "container_id_3".to_string(),
                    ]).await);
                    tokio::spawn(metrics_collector_task(docker_collector.clone(), "0.0.0.0:3030"));
                    
                    //NOTE: if you start a new monitoring collector you need to specify a different port for the underlying server to server requests at
                    // let sysinfo_collector = SysinfoMetricsCollector::new(12345).await; // Replace 12345 with the actual PID you want to monitor
                    // tokio::spawn(metrics_collector_task(&sysinfo_collector, "0.0.0.0:3031""));


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