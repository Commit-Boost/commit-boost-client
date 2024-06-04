use std::net::SocketAddr;

use cb_common::{config::BuilderConfig, pbs::RelayEntry, types::Chain, utils::eth_to_wei};
use clap::{Parser, Subcommand};

pub mod runner;

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Command,

    /// Start with Holesky spec
    #[arg(long, global = true)]
    pub holesky: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Pbs module configs, try to keep compatibility with MEV boost cli configs
    Boost {
        /// Address to start for boost server on
        #[arg(short, long, default_value = "127.0.0.1:18550", env = "BOOST_LISTEN_ADDR")]
        listen_address: SocketAddr,
        /// Add a single relay (can be repeated or comma separated). Format is scheme://pubkey@host
        #[arg(short, long, visible_alias = "relays", env = "RELAYS", num_args = 1.., required = true, value_delimiter = ',')]
        relay: Vec<String>,
        /// Check relay status on startup and getStatus calls
        #[arg(long, env = "RELAY_STARTUP_CHECK")]
        relay_check: bool,
        /// Timeout in ms for calling getHeader to relays
        #[arg(long, default_value_t = 950, env = "RELAY_TIMEOUT_MS_GETHEADER")]
        timeout_get_header_ms: u64,
        /// Timeout in ms for calling getPayload to relays
        #[arg(long, default_value_t = 4000, env = "RELAY_TIMEOUT_MS_GETPAYLOAD")]
        timeout_get_payload_ms: u64,
        /// Timeout in ms for calling registerValidator to relays
        #[arg(long, default_value_t = 3000, env = "RELAY_TIMEOUT_MS_REGVAL")]
        timeout_register_validator_ms: u64,
        /// Skip signature verification for relay headers
        #[arg(long)]
        skip_sigverify: bool,
        /// Minimum bid to accept from relays in ETH
        #[arg(long, default_value_t = 0.0, env = "MIN_BID_ETH")]
        min_bid_eth: f64,
    },
}

impl Args {
    pub fn to_config(self) -> (Chain, BuilderConfig) {
        let chain = if self.holesky { Chain::Holesky } else { Chain::Mainnet };

        match self.cmd {
            Command::Boost {
                listen_address: address,
                relay,
                relay_check,
                timeout_get_header_ms,
                timeout_get_payload_ms,
                timeout_register_validator_ms,
                skip_sigverify,
                min_bid_eth,
            } => {
                let config = BuilderConfig {
                    address,
                    relays: deser_relay_vec(relay),
                    relay_check,
                    timeout_get_header_ms,
                    timeout_get_payload_ms,
                    timeout_register_validator_ms,
                    skip_sigverify,
                    min_bid_wei: eth_to_wei(min_bid_eth),
                };
                println!("{}", serde_json::to_string_pretty(&config).unwrap());
                (chain, config)
            }
        }
    }
}

fn deser_relay_vec(relays: Vec<String>) -> Vec<RelayEntry> {
    relays
        .into_iter()
        .map(|s| {
            serde_json::from_str::<RelayEntry>(&format!("\"{}\"", s.trim()))
                .expect("invalid relay format, should be scheme://pubkey@host")
        })
        .collect()
}
