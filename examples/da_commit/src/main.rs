use std::time::Duration;

use alloy::primitives::{b256, Address, B256};
use commit_boost::prelude::*;
use eyre::{OptionExt, Result};
use lazy_static::lazy_static;
use prometheus::{IntCounter, Registry};
use serde::Deserialize;
use tokio::time::sleep;
use tracing::{error, info};

// This is the signing ID used for the DA Commit module.
// Signatures produced by the signer service will incorporate this ID as part of
// the signature, preventing other modules from using the same signature for
// different purposes.
pub const DA_COMMIT_SIGNING_ID: B256 =
    b256!("0x6a33a23ef26a4836979edff86c493a69b26ccf0b4a16491a815a13787657431b");

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
    #[serde(default = "default_ecdsa")]
    use_ecdsa_keys: bool,
}

fn default_ecdsa() -> bool {
    true
}

impl DaCommitService {
    pub async fn run(&mut self) -> Result<()> {
        // the config has the signer_client already setup, we can use it to interact
        // with the Signer API
        let pubkeys = self.config.signer_client.get_pubkeys().await?.keys;
        info!(pubkeys = %serde_json::to_string_pretty(&pubkeys).unwrap(), "Received pubkeys");

        let pubkey = pubkeys.first().ok_or_eyre("no key available")?.consensus;
        info!("Registered validator {pubkey}");

        let proxy_delegation_bls = self.config.signer_client.generate_proxy_key_bls(pubkey).await?;
        info!("Obtained a BLS proxy delegation:\n{proxy_delegation_bls}");
        let proxy_bls = proxy_delegation_bls.message.proxy;

        let proxy_ecdsa = if self.config.extra.use_ecdsa_keys {
            let proxy_delegation_ecdsa =
                self.config.signer_client.generate_proxy_key_ecdsa(pubkey).await?;
            info!("Obtained an ECDSA proxy delegation:\n{proxy_delegation_ecdsa}");
            Some(proxy_delegation_ecdsa.message.proxy)
        } else {
            None
        };

        let mut data = 0;

        loop {
            self.send_request(data, pubkey, proxy_bls, proxy_ecdsa).await?;
            sleep(Duration::from_secs(self.config.extra.sleep_secs)).await;
            data += 1;
        }
    }

    pub async fn send_request(
        &mut self,
        data: u64,
        pubkey: BlsPublicKey,
        proxy_bls: BlsPublicKey,
        proxy_ecdsa: Option<Address>,
    ) -> Result<()> {
        let datagram = Datagram { data };

        // Request a signature directly from a BLS key
        let request = SignConsensusRequest::builder(pubkey).with_msg(&datagram);
        let signature = self.config.signer_client.request_consensus_signature(request).await?;
        info!("Proposer commitment (consensus): {}", signature);
        match verify_proposer_commitment_signature_bls(
            self.config.chain,
            &pubkey,
            &datagram,
            &signature,
            &DA_COMMIT_SIGNING_ID,
        ) {
            Ok(_) => info!("Signature verified successfully"),
            Err(err) => error!(%err, "Signature verification failed"),
        };

        // Request a signature from a proxy BLS key
        let proxy_request_bls = SignProxyRequest::builder(proxy_bls).with_msg(&datagram);
        let proxy_signature_bls =
            self.config.signer_client.request_proxy_signature_bls(proxy_request_bls).await?;
        info!("Proposer commitment (proxy BLS): {}", proxy_signature_bls);
        match verify_proposer_commitment_signature_bls(
            self.config.chain,
            &proxy_bls,
            &datagram,
            &proxy_signature_bls,
            &DA_COMMIT_SIGNING_ID,
        ) {
            Ok(_) => info!("Signature verified successfully"),
            Err(err) => error!(%err, "Signature verification failed"),
        };

        // If ECDSA keys are enabled, request a signature from a proxy ECDSA key
        if let Some(proxy_ecdsa) = proxy_ecdsa {
            let proxy_request_ecdsa = SignProxyRequest::builder(proxy_ecdsa).with_msg(&datagram);
            let proxy_signature_ecdsa = self
                .config
                .signer_client
                .request_proxy_signature_ecdsa(proxy_request_ecdsa)
                .await?;
            info!("Proposer commitment (proxy ECDSA): {}", proxy_signature_ecdsa);
            match verify_proposer_commitment_signature_ecdsa(
                self.config.chain,
                &proxy_ecdsa,
                &datagram,
                &proxy_signature_ecdsa,
                &DA_COMMIT_SIGNING_ID,
            ) {
                Ok(_) => info!("Signature verified successfully"),
                Err(err) => error!(%err, "Signature verification failed"),
            };
        }

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

    match load_commit_module_config::<ExtraConfig>() {
        Ok(config) => {
            let _guard = initialize_tracing_log(&config.id, LogsSettings::from_env_config()?);

            MetricsProvider::load_and_run(config.chain, MY_CUSTOM_REGISTRY.clone())?;

            info!(
                module_id = %config.id,
                sleep_secs = config.extra.sleep_secs,
                "Starting module with custom data"
            );

            let mut service = DaCommitService { config };

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
