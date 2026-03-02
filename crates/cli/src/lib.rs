use std::path::PathBuf;

use cb_common::utils::print_logo;
use clap::{Parser, Subcommand};

mod docker_init;

/// Version string with a leading 'v'
const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

#[derive(Parser, Debug)]
#[command(version = VERSION, about, long_about = LONG_ABOUT, name = "commit-boost-cli")]
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
        config_path: PathBuf,

        /// Path to output files
        #[arg(short, long("output"), default_value = "./")]
        output_path: PathBuf,
    },
}

impl Args {
    pub async fn run(self) -> eyre::Result<()> {
        print_logo();

        match self.cmd {
            Command::Init { config_path, output_path } => {
                docker_init::handle_docker_init(config_path, output_path).await
            }
        }
    }
}

const LONG_ABOUT: &str = "Commit-Boost allows Ethereum validators to safely run MEV-Boost and community-built commitment protocols";

#[derive(Parser, Debug)]
#[command(version = VERSION, about, long_about = LONG_ABOUT, name = "commit-boost-pbs")]
pub struct PbsArgs;

#[derive(Parser, Debug)]
#[command(version = VERSION, about, long_about = LONG_ABOUT, name = "commit-boost-signer")]
pub struct SignerArgs;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_has_v_prefix() {
        assert!(VERSION.starts_with('v'), "VERSION should start with 'v', got: {VERSION}");
    }

    #[test]
    fn parse_init_subcommand() {
        Args::try_parse_from(["commit-boost-cli", "init", "--config", "/tmp/config.toml"])
            .expect("should parse init subcommand");
    }
}
