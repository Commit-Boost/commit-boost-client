use std::process::Stdio;

use cb_common::{
    config::{CommitBoostConfig, CONFIG_PATH_ENV, MODULE_ID_ENV},
    utils::print_logo,
};
use cb_crypto::service::SigningService;
use cb_pbs::{BuilderState, DefaultBuilderApi, PbsService};
use clap::{Parser, Subcommand};

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
    // /// Start pbs module, signing server and commit modules
    // Start {
    //     /// Address to start for boost server on
    //     #[arg(short, long, default_value = "127.0.0.1:18550", env = "BOOST_LISTEN_ADDR")]
    //     pbs_address: SocketAddr,
    //     /// Add a single relay (can be repeated or comma separated). Format is
    // scheme://pubkey@host     #[arg(short, long, visible_alias = "relays", env = "RELAYS",
    // num_args = 1.., required = true, value_delimiter = ',')]     relay: Vec<String>,
    //     #[arg(long)]
    //     pbs: Option<String>,
    //     /// Check relay status on startup and getStatus calls
    //     #[arg(long, env = "RELAY_STARTUP_CHECK")]
    //     relay_check: bool,
    //     /// Timeout in ms for calling getHeader to relays
    //     #[arg(long, default_value_t = 950, env = "RELAY_TIMEOUT_MS_GETHEADER")]
    //     timeout_get_header_ms: u64,
    //     /// Timeout in ms for calling getPayload to relays
    //     #[arg(long, default_value_t = 4000, env = "RELAY_TIMEOUT_MS_GETPAYLOAD")]
    //     timeout_get_payload_ms: u64,
    //     /// Timeout in ms for calling registerValidator to relays
    //     #[arg(long, default_value_t = 3000, env = "RELAY_TIMEOUT_MS_REGVAL")]
    //     timeout_register_validator_ms: u64,
    //     /// Skip signature verification for relay headers
    //     #[arg(long)]
    //     skip_sigverify: bool,
    //     /// Minimum bid to accept from relays in ETH
    //     #[arg(long, default_value_t = 0.0, env = "MIN_BID_ETH")]
    //     min_bid_eth: f64,
    //     /// Address where to start the service on
    //     #[arg(long, default_value = "127.0.0.1:33950", env = SIGNER_LISTEN_ADDR)]
    //     sign_address: SocketAddr,
    //     /// Path to executable
    //     #[arg(short, long, num_args = 1.., required = true, value_delimiter = ',')]
    //     module: Vec<String>,
    // },
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

                // this mocks the commit boost client starting containers, processes etc
                let mut child_handles = Vec::with_capacity(config.modules.len());

                for module in config.modules {
                    let child = std::process::Command::new(module.path)
                        .env(MODULE_ID_ENV, module.id)
                        .env(CONFIG_PATH_ENV, &config_path)
                        .spawn()
                        .expect("failed to start process");

                    child_handles.push(child);
                }

                // start signing server
                tokio::spawn(SigningService::run(config.chain, config.signer));

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

// fn deser_relay_vec(relays: Vec<String>) -> Vec<RelayEntry> {
//     relays
//         .into_iter()
//         .map(|s| {
//             serde_json::from_str::<RelayEntry>(&format!("\"{}\"", s.trim()))
//                 .expect("invalid relay format, should be scheme://pubkey@host")
//         })
//         .collect()
// }
