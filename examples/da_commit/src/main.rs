use std::time::Duration;

use alloy::rpc::types::beacon::{BlsPublicKey, BlsSignature};
use commit::request::SignedProxyDelegation;
use commit_boost::prelude::*;
use eyre::{OptionExt, Result};
use lazy_static::lazy_static;
use prometheus::{IntCounter, Registry};
use serde::Deserialize;
use tokio::time::sleep;
use tracing::{error, info};

// You can define custom metrics and a custom registry for the business logic of
// your module. These will be automatically scaped by the Prometheus server
lazy_static! {
    pub static ref MY_CUSTOM_REGISTRY: prometheus::Registry =
        Registry::new_custom(Some("da_commit".to_string()), None).unwrap();
    pub static ref SIG_RECEIVED_COUNTER: IntCounter =
        IntCounter::new("signature_received", "successful signatures requests received").unwrap();
}

#[derive(TreeHash)]
struct Datagram {
    data: u64,
}

struct DaCommitService {
    config: StartCommitModuleConfig<ExtraConfig>,
}

// Extra configurations parameters can be set here and will be automatically
// parsed from the .config.toml file These parameters will be in the .extra
// field of the StartModuleConfig<ExtraConfig> struct you get after calling
// `load_module_config::<ExtraConfig>()`
#[derive(Debug, Deserialize)]
struct ExtraConfig {
    sleep_secs: u64,
}

impl DaCommitService {
    pub async fn run(self) -> Result<()> {
        // the config has the signer_client already setup, we can use it to interact
        // with the Signer API
        let pubkeys = self.config.signer_client.get_pubkeys().await?;
        info!(consensus = pubkeys.consensus.len(), proxy = pubkeys.proxy.len(), "Received pubkeys");

        let pubkey = pubkeys.consensus.first().ok_or_eyre("no key available")?;
        info!("Registered validator {pubkey}");

        let proxy_delegation = self.config.signer_client.generate_proxy_key(*pubkey).await?;
        info!("Obtained a proxy delegation {proxy_delegation:#?}");

        let mut data = 0;

        loop {
            self.send_request(data, *pubkey, proxy_delegation).await?;
            sleep(Duration::from_secs(self.config.extra.sleep_secs)).await;
            data += 1;
        }
    }

    pub async fn send_request(&self, data: u64, pubkey: BlsPublicKey, proxy_delegation: SignedProxyDelegation) -> Result<()> {
        let datagram = Datagram { data };

        let request = SignRequest::builder(pubkey)
            .with_msg(&datagram);
        let signature = self.config.signer_client.request_signature(&request);

        let proxy_request = SignRequest::builder(proxy_delegation.proxy_delegation.proxy)
            .is_proxy()
            .with_msg(&datagram);
        let proxy_signature = self.config.signer_client.request_signature(&proxy_request);

        let (signature, proxy_signature) = {
            let res = tokio::join!(signature, proxy_signature);
            (res.0?, res.1?)
        };

        info!("Proposer commitment (consensus): {}", pretty_print_sig(signature));
        info!("Proposer commitment (proxy): {}", pretty_print_sig(proxy_signature));

        SIG_RECEIVED_COUNTER.inc();

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    initialize_tracing_log();

    // Remember to register all your metrics before starting the process
    MY_CUSTOM_REGISTRY.register(Box::new(SIG_RECEIVED_COUNTER.clone()))?;
    // Spin up a server that exposes the /metrics endpoint to Prometheus
    MetricsProvider::load_and_run(MY_CUSTOM_REGISTRY.clone())?;

    match load_commit_module_config::<ExtraConfig>() {
        Ok(config) => {
            info!(
                module_id = config.id.0,
                sleep_secs = config.extra.sleep_secs,
                "Starting module with custom data"
            );

            let service = DaCommitService { config };

            if let Err(err) = service.run().await {
                error!(?err, "Service failed");
            }
        }
        Err(err) => {
            error!(?err, "Failed to load module config");
        }
    }
    Ok(())
}

fn pretty_print_sig(sig: BlsSignature) -> String {
    format!("{}..", &sig.to_string()[..16])
}
