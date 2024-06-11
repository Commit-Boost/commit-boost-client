use std::net::SocketAddr;

use alloy_primitives::B256;
use alloy_rpc_types_beacon::{relay::ValidatorRegistration, BlsPublicKey};
use cb_common::pbs::RelayEntry;
use cb_pbs::{GetHeaderReponse, SignedBlindedBeaconBlock};
use reqwest::Error;

pub struct MockValidator {
    comm_boost: RelayEntry,
    client: reqwest::Client,
}

impl MockValidator {
    pub fn new(address: SocketAddr) -> Self {
        let client = reqwest::Client::new();

        Self {
            comm_boost: RelayEntry {
                id: "".to_owned(),
                pubkey: BlsPublicKey::ZERO,
                url: format!("http://{address}"),
            },
            client,
        }
    }

    pub async fn do_get_header(&self) -> Result<(), Error> {
        let url = self.comm_boost.get_header_url(0, B256::ZERO, BlsPublicKey::ZERO);
        let res = self.client.get(url).send().await?.bytes().await?;
        assert!(serde_json::from_slice::<GetHeaderReponse>(&res).is_ok());

        Ok(())
    }

    pub async fn do_get_status(&self) -> Result<(), Error> {
        let url = self.comm_boost.get_status_url();
        let _res = self.client.get(url).send().await?;
        // assert!(res.status().is_success());

        Ok(())
    }

    pub async fn do_register_validator(&self) -> Result<(), Error> {
        let url = self.comm_boost.register_validator_url();

        let registration: Vec<ValidatorRegistration> = vec![];

        self.client
            .post(url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&registration).unwrap())
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    pub async fn do_submit_block(&self) -> Result<(), Error> {
        let url = self.comm_boost.submit_block_url();

        let signed_blinded_block = SignedBlindedBeaconBlock::default();

        self.client
            .post(url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&signed_blinded_block).unwrap())
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}
