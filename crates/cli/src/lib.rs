use cb_common::utils::print_logo;
use clap::{Parser, Subcommand};
use docker_init::{CB_COMPOSE_FILE, CB_CONFIG_FILE, CB_ENV_FILE};

mod docker_cmd;
mod docker_init;

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
                docker_init::handle_docker_init(config_path, output_path)
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
