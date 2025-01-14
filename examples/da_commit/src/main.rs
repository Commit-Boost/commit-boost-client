use std::time::Duration;

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
// `load_commit_module_config::<ExtraConfig>()`
#[derive(Debug, Deserialize)]
struct ExtraConfig {
    sleep_secs: u64,
}

impl DaCommitService {
    pub async fn run(self) -> Result<()> {
        // the config has the signer_client already setup, we can use it to interact
        // with the Signer API
        let pubkeys = self.config.signer_client.get_pubkeys().await?.keys;
        info!(pubkeys = %serde_json::to_string_pretty(&pubkeys).unwrap(), "Received pubkeys");

        let pubkey = pubkeys.first().ok_or_eyre("no key available")?.consensus;
        info!("Registered validator {pubkey}");

        let proxy_delegation_bls = self.config.signer_client.generate_proxy_key_bls(pubkey).await?;
        info!("Obtained a BLS proxy delegation:\n{proxy_delegation_bls}");
        let proxy_bls = proxy_delegation_bls.message.proxy;

        let proxy_delegation_ecdsa =
            self.config.signer_client.generate_proxy_key_ecdsa(pubkey).await?;
        info!("Obtained an ECDSA proxy delegation:\n{proxy_delegation_ecdsa}");
        let proxy_ecdsa = proxy_delegation_ecdsa.message.proxy;

        let mut data = 0;

        loop {
            self.send_request(data, pubkey, proxy_bls, proxy_ecdsa).await?;
            sleep(Duration::from_secs(self.config.extra.sleep_secs)).await;
            data += 1;
        }
    }

    pub async fn send_request(
        &self,
        data: u64,
        pubkey: BlsPublicKey,
        proxy_bls: BlsPublicKey,
        proxy_ecdsa: EcdsaPublicKey,
    ) -> Result<()> {
        let datagram = Datagram { data };

        let request = SignConsensusRequest::builder(pubkey).with_msg(&datagram);
        let signature = self.config.signer_client.request_consensus_signature(request);

        let proxy_request_bls = SignProxyRequest::builder(proxy_bls).with_msg(&datagram);
        let proxy_signature_bls =
            self.config.signer_client.request_proxy_signature_bls(proxy_request_bls);

        let proxy_request_ecdsa = SignProxyRequest::builder(proxy_ecdsa).with_msg(&datagram);
        let proxy_signature_ecdsa =
            self.config.signer_client.request_proxy_signature_ecdsa(proxy_request_ecdsa);

        let (signature, proxy_signature_bls, proxy_signature_ecdsa) = {
            let res = tokio::join!(signature, proxy_signature_bls, proxy_signature_ecdsa);
            (res.0?, res.1?, res.2?)
        };

        info!("Proposer commitment (consensus): {}", signature);
        info!("Proposer commitment (proxy BLS): {}", proxy_signature_bls);
        info!("Proposer commitment (proxy ECDSA): {}", proxy_signature_ecdsa);

        SIG_RECEIVED_COUNTER.inc();

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    // Remember to register all your metrics before starting the process
    MY_CUSTOM_REGISTRY.register(Box::new(SIG_RECEIVED_COUNTER.clone()))?;
    // Spin up a server that exposes the /metrics endpoint to Prometheus
    MetricsProvider::load_and_run(Chain::Mainnet, MY_CUSTOM_REGISTRY.clone())?;

    match load_commit_module_config::<ExtraConfig>() {
        Ok(config) => {
            let _guard = initialize_tracing_log(&config.id)?;

            info!(
                module_id = %config.id,
                sleep_secs = config.extra.sleep_secs,
                "Starting module with custom data"
            );

            let service = DaCommitService { config };

            if let Err(err) = service.run().await {
                error!(%err, "Service failed");
            }
        }
        Err(err) => {
            eprintln!("Failed to load module config: {err:?}");
        }
    }
    Ok(())
}
