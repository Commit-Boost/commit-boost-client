use cb_common::utils::print_logo;
use clap::{Parser, Subcommand};
use docker_init::{CB_COMPOSE_FILE, CB_ENV_FILE};

mod docker_cmd;
mod docker_init;

#[derive(Parser, Debug)]
#[command(version, about, long_about = LONG_ABOUT, name = "commit-boost-cli")]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate the starting docker-compose file
    Init {
        /// Path to config file
        #[arg(long("config"))]
        config_path: String,

        /// Path to output files
        #[arg(short, long("output"), default_value = "./")]
        output_path: String,
    },

    /// Start the Commit-Boost services
    Start {
        /// Path to docker compose file
        #[arg(
            short,
            long("docker"),
            default_value = CB_COMPOSE_FILE
        )]
        compose_path: String,

        /// Path env file
        #[arg(short, long("env"))]
        env_path: Option<String>,
    },

    /// Stop the Commit-Boost services
    Stop {
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

    /// See stdout logs
    Logs {
        /// Path to docker compose file
        #[arg(
            short,
            long("docker"),
            default_value = CB_COMPOSE_FILE
        )]
        compose_path: String,
    },
}

impl Args {
    pub async fn run(self) -> eyre::Result<()> {
        print_logo();

        match self.cmd {
            Command::Init { config_path, output_path } => {
                docker_init::handle_docker_init(config_path, output_path).await
            }

            Command::Start { compose_path, env_path } => {
                docker_cmd::handle_docker_start(compose_path, env_path)
            }

            Command::Stop { compose_path, env_path } => {
                docker_cmd::handle_docker_stop(compose_path, env_path)
            }

            Command::Logs { compose_path } => docker_cmd::handle_docker_logs(compose_path),
        }
    }
}

const LONG_ABOUT: &str = "Commit-Boost allows Ethereum validators to safely run MEV-Boost and community-built commitment protocols";
