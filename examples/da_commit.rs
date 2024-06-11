use std::time::Duration;

use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use cb_common::{
    config::{load_module_config, ModuleConfig},
    pbs::{COMMIT_BOOST_API, PUBKEYS_PATH, SIGN_REQUEST_PATH},
    utils::initialize_tracing_log,
};
use cb_crypto::types::SignRequest;
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
    url: String,
}

#[derive(Debug, Deserialize)]
struct ExtraConfig {
    sleep_secs: u64,
}

impl DaCommitService {
    pub async fn run(self) {
        let pubkeys = self.get_pubkeys().await;

        let pubkey = pubkeys[0];

        info!("Registered validator {pubkey}");

        let mut data = 0;

        loop {
            self.send_request(data, pubkey).await;
            sleep(Duration::from_secs(self.config.extra.sleep_secs)).await;
            data += 1;
        }
    }

    pub async fn get_pubkeys(&self) -> Vec<BlsPublicKey> {
        let url = format!("{}{COMMIT_BOOST_API}{PUBKEYS_PATH}", self.url);
        let response = reqwest::Client::new().get(url).send().await.expect("failed to get request");

        let status = response.status();
        let response_bytes = response.bytes().await.expect("failed to get bytes");

        if !status.is_success() {
            let err = String::from_utf8_lossy(&response_bytes).into_owned();
            error!(err, ?status, "failed to get signature");
            std::process::exit(1);
        }

        let pubkeys: Vec<BlsPublicKey> =
            serde_json::from_slice(&response_bytes).expect("failed deser");

        pubkeys
    }

    pub async fn send_request(&self, data: u64, pubkey: BlsPublicKey) {
        let datagram = Datagram { data };

        let request = SignRequest::builder(&self.config.id, pubkey).with_msg(&datagram);

        let url = format!("{}{COMMIT_BOOST_API}{SIGN_REQUEST_PATH}", self.url);

        let response = reqwest::Client::new()
            .post(url)
            .json(&request)
            .send()
            .await
            .expect("failed to get request");

        let status = response.status();
        let response_bytes = response.bytes().await.expect("failed to get bytes");

        if !status.is_success() {
            let err = String::from_utf8_lossy(&response_bytes).into_owned();
            error!(err, "failed to get signature");
            return;
        }

        let signature: BlsSignature =
            serde_json::from_slice(&response_bytes).expect("failed deser");

        info!("Proposer commitment: {}", pretty_print_sig(signature))
    }
}

#[tokio::main]
async fn main() {
    initialize_tracing_log();

    let config = load_module_config::<ExtraConfig>();

    info!(module_id = config.config.id, "Starting module");

    let service =
        DaCommitService { config: config.config, url: format!("http://{}", config.sign_address) };

    service.run().await
}

fn pretty_print_sig(sig: BlsSignature) -> String {
    format!("{}..", &sig.to_string()[..16])
}
