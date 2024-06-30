use std::{collections::HashMap, iter, iter::Iterator, process::Stdio};

use cb_common::{
    config::{CommitBoostConfig, CB_CONFIG_ENV, METRICS_SERVER_URL, MODULE_ID_ENV, MODULE_JWT_ENV},
    pbs::DEFAULT_PBS_JWT_KEY,
    utils::print_logo,
};
use cb_crypto::service::SigningService;
use cb_metrics::docker_metrics_collector::DockerMetricsCollector;
use cb_pbs::{BuilderState, DefaultBuilderApi, PbsService};
use clap::{Parser, Subcommand};
use docker_init::{CB_COMPOSE_FILE, CB_CONFIG_FILE, CB_ENV_FILE};
use tracing::info;

mod docker_init;
mod docker_start;

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Init {
        /// Path to config file
        #[arg(long("config"), default_value = CB_CONFIG_FILE)]
        config_path: String,

        /// Path to output files
        #[arg(short, long("output"), default_value = "./")]
        output_path: String,
    },

    Start {
        /// Path to docker compose file
        #[arg(
            short,
            long("docker"),
            default_value = CB_COMPOSE_FILE
        )]
        compose_path: String,

        /// Path env file
        #[arg(short, long("env"), default_value = CB_ENV_FILE)]
        env_path: String,
    },

    Start2 {
        config: String,
    },
}

impl Args {
    pub async fn run(self) -> eyre::Result<()> {
        print_logo();

        match self.cmd {
            Command::Init { config_path, output_path } => {
                docker_init::handle_docker_init(config_path, output_path)
            }

            Command::Start { compose_path, env_path } => {
                docker_start::handle_docker_start(compose_path, env_path)
            }

            Command::Start2 { config: config_path } => {
                let config = CommitBoostConfig::from_file(&config_path);
                let signer_config = config.signer.expect("missing signer config with modules");
                let metrics_config = config.metrics.clone().expect("missing metrics config");

                // TODO: Actually generate this token
                let pbs_jwt = "MY_PBS_TOKEN";
                const MODULE_JWT: &str = "JWT_FIXME";

                // Initialize Docker client
                let docker = bollard::Docker::connect_with_local_defaults()
                    .expect("Failed to connect to Docker");

                if let Some(modules) = config.modules {
                    let jwts: HashMap<String, String> =
                        iter::once((DEFAULT_PBS_JWT_KEY.into(), pbs_jwt.into()))
                            .chain(modules.iter().map(|module|
                            // TODO: Generate token instead of hard-coding it. Think about persisting it across the project.
                            (
                                module.id.clone(),
                                MODULE_JWT.into()
                                // format!("JWT_{}", module.id)
                            )))
                            .collect();

                    // start signing server
                    tokio::spawn(SigningService::run(
                        config.chain,
                        signer_config.clone(),
                        jwts.clone(),
                    ));

                    for module in modules {
                        info!("Module: {}", module.id);
                        let container_config = bollard::container::Config {
                            image: Some(module.docker_image.clone()),
                            host_config: Some(bollard::secret::HostConfig {
                                binds: {
                                    let full_config_path = std::fs::canonicalize(&config_path)
                                        .unwrap()
                                        .to_string_lossy()
                                        .to_string();
                                    Some(vec![format!("{}:{}", full_config_path, "/config.toml")])
                                },
                                network_mode: Some(String::from("host")), // Use the host network
                                ..Default::default()
                            }),
                            env: {
                                let metrics_server_url = metrics_config.address;
                                info!("Metrics");
                                Some(vec![
                                    format!("{}={}", MODULE_ID_ENV, module.id),
                                    format!("{}={}", CB_CONFIG_ENV, "/config.toml"),
                                    format!("{}={}", MODULE_JWT_ENV, jwts.get(&module.id).unwrap()),
                                    format!("{}={}", METRICS_SERVER_URL, metrics_server_url),
                                ])
                            },
                            ..Default::default()
                        };

                        let container = docker
                            .create_container::<&str, String>(None, container_config)
                            .await
                            .expect("failed to create container");
                        info!("create cid: {:?}", container.id);

                        let container_id = container.id;

                        // start monitoring tasks for spawned modules
                        let metrics_config = metrics_config.clone();
                        let cid = container_id.clone();
                        tokio::spawn(async move {
                            DockerMetricsCollector::new(
                                vec![cid],
                                metrics_config.address.clone(),
                                // FIXME: The entire DockerMetricsCollector currently works with a
                                // single JWT; need to migrate to per-module JWT.
                                MODULE_JWT.to_string(),
                            )
                            .await
                        });

                        docker.start_container::<String>(&container_id, None).await?;
                        println!(
                            "Started container: {} from image {}",
                            container_id, module.docker_image
                        );
                    }
                }

                // start pbs server
                if let Some(pbs_path) = config.pbs.path {
                    let cmd = std::process::Command::new(pbs_path)
                        .env(CB_CONFIG_ENV, &config_path)
                        .env(MODULE_JWT_ENV, pbs_jwt)
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
                };

                Ok(())
            }
        }
    }
}
