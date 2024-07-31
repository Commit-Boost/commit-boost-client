use alloy::{
    primitives::B256,
    rpc::types::beacon::{relay::ValidatorRegistration, BlsPublicKey},
};
use cb_common::pbs::RelayClient;
use cb_pbs::{GetHeaderReponse, SignedBlindedBeaconBlock};
use reqwest::Error;

use crate::utils::generate_mock_relay;

pub struct MockValidator {
    comm_boost: RelayClient,
}

impl MockValidator {
    pub fn new(port: u16) -> Self {
        Self { comm_boost: generate_mock_relay(port, BlsPublicKey::default()) }
    }

    pub async fn do_get_header(&self) -> Result<(), Error> {
        let url = self.comm_boost.get_header_url(0, B256::ZERO, BlsPublicKey::ZERO);
        let res = self.comm_boost.client.get(url).send().await?.bytes().await?;
        assert!(serde_json::from_slice::<GetHeaderReponse>(&res).is_ok());

        Ok(())
    }

    pub async fn do_get_status(&self) -> Result<(), Error> {
        let url = self.comm_boost.get_status_url();
        let _res = self.comm_boost.client.get(url).send().await?;
        // assert!(res.status().is_success());

        Ok(())
    }

    pub async fn do_register_validator(&self) -> Result<(), Error> {
        let url = self.comm_boost.register_validator_url();

        let registration: Vec<ValidatorRegistration> = vec![];

        self.comm_boost
            .client
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

        self.comm_boost
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&signed_blinded_block).unwrap())
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}
