use std::time::Duration;

use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use cb_common::{
    commit::{client::SignerClient, request::SignRequest},
    config::{load_module_config, ModuleConfig, JWT_ENV},
    utils::initialize_tracing_log,
};
use eyre::OptionExt;
use cb_metrics::sdk::{register_custom_metric, update_custom_metric};
use serde::Deserialize;
use tokio::time::sleep;
use tracing::{error, info};
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
struct Datagram {
    data: u64,
}

struct DaCommitService {
    config: ModuleConfig<ExtraConfig>,
    signer_client: SignerClient,
}

#[derive(Debug, Deserialize)]
struct ExtraConfig {
    sleep_secs: u64,
}

impl DaCommitService {
    pub async fn run(self) -> eyre::Result<()> {
        let pubkeys = self.signer_client.get_pubkeys().await?;
        info!(consensus = pubkeys.consensus.len(), proxy = pubkeys.proxy.len(), "Received pubkeys");

        let pubkey = pubkeys.consensus.first().ok_or_eyre("no key available")?;
        info!("Registered validator {pubkey}");

        let mut data = 0;

        loop {
            self.send_request(data, *pubkey).await?;

            update_custom_metric("custom_metric", 42.0, vec![("label_key".to_string(), "label_value".to_string())])
            .await
            .expect("Failed to update custom metric");

            sleep(Duration::from_secs(self.config.extra.sleep_secs)).await;
            data += 1;
        }
    }


    pub async fn send_request(&self, data: u64, pubkey: BlsPublicKey) -> eyre::Result<()> {
        let datagram = Datagram { data };
        let request = SignRequest::builder(&self.config.id, pubkey).with_msg(&datagram);

        let signature = self.signer_client.request_signature(&request).await?;

        info!("Proposer commitment: {}", pretty_print_sig(signature));

        Ok(())
    }
}

#[tokio::main]
async fn main() {
    initialize_tracing_log();

    let config = load_module_config::<ExtraConfig>();

    register_custom_metric("custom_metric", "A custom metric for demonstration").await.expect("Failed to register custom metric.");

    info!(module_id = config.config.id, "Starting module");

    // TODO: pass this via the module config
    let jwt = &std::env::var(JWT_ENV).expect(&format!("{JWT_ENV} not set"));

    let client = SignerClient::new(config.sign_address, jwt).expect("failed to create client");
    let service = DaCommitService { config: config.config, signer_client: client };

    if let Err(err) = service.run().await {
        error!(?err, "Service failed");
    }
}

fn pretty_print_sig(sig: BlsSignature) -> String {
    format!("{}..", &sig.to_string()[..16])
}
