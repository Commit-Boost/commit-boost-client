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

                // Initialize Docker client
                let docker = bollard::Docker::connect_with_local_defaults().expect("Failed to connect to Docker");

                if let Some(modules) = config.modules {
                    let signer_config = config.signer.expect("missing signer config with modules");
                    // start signing server
                    tokio::spawn(SigningService::run(config.chain, signer_config));

                    for module in modules {
                        let container_config = bollard::container::Config {
                            image: Some(module.docker_image.clone()),
                            host_config: Some(bollard::secret::HostConfig {
                                binds: {
                                    let full_config_path = std::fs::canonicalize(&config_path).unwrap().to_string_lossy().to_string();
                                    Some(vec![format!("{}:{}", full_config_path, "/config.toml")])
                                },
                                network_mode: Some(String::from("host")), // Use the host network
                                ..Default::default()
                            }),
                            env: Some(vec![
                                format!("{}={}", MODULE_ID_ENV, module.id),
                                format!("{}={}", CONFIG_PATH_ENV, "/config.toml"),
                            ]),
                            ..Default::default()
                        };

                        let container = docker.create_container::<&str, String>(None, container_config).await?;
                        let container_id = container.id;
                        docker.start_container::<String>(&container_id, None).await?;

                        // start monitoring tasks for spawned modules
                        // TODO: this needs to integrate with docker module instantiation
                        // let container_id = env::var("MOCK_CONTAINER_ID").expect("MOCK_CONTAINER_ID not set");
                        let metrics_config = config.metrics.clone().expect("missing metrics config");
                        let cid = container_id.clone();
                        tokio::spawn(async move {
                            DockerMetricsCollector::new(vec![
                                cid
                            ], metrics_config.address.clone(), metrics_config.jwt_path.clone()).await
                        });

                        println!("Started container: {} from image {}", container_id, module.docker_image);
                    }
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