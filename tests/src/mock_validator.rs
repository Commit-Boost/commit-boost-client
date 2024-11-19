use alloy::{
    primitives::B256,
    rpc::types::beacon::{relay::ValidatorRegistration, BlsPublicKey},
};
use cb_common::pbs::{GetHeaderResponse, RelayClient, SignedBlindedBeaconBlock};
use reqwest::Error;

use crate::utils::generate_mock_relay;

pub struct MockValidator {
    comm_boost: RelayClient,
}

impl MockValidator {
    pub fn new(port: u16) -> eyre::Result<Self> {
        Ok(Self { comm_boost: generate_mock_relay(port, BlsPublicKey::default())? })
    }

    pub async fn do_get_header(&self, pubkey: Option<BlsPublicKey>) -> Result<(), Error> {
        let url = self
            .comm_boost
            .get_header_url(0, B256::ZERO, pubkey.unwrap_or(BlsPublicKey::ZERO))
            .unwrap();
        let res = self.comm_boost.client.get(url).send().await?.bytes().await?;
        assert!(serde_json::from_slice::<GetHeaderResponse>(&res).is_ok());

        Ok(())
    }

    pub async fn do_get_status(&self) -> Result<(), Error> {
        let url = self.comm_boost.get_status_url().unwrap();
        let _res = self.comm_boost.client.get(url).send().await?;
        // assert!(res.status().is_success());

        Ok(())
    }

    pub async fn do_register_validator(&self) -> Result<(), Error> {
        let url = self.comm_boost.register_validator_url().unwrap();

        let registration: Vec<ValidatorRegistration> = vec![];

        self.comm_boost.client.post(url).json(&registration).send().await?.error_for_status()?;

        Ok(())
    }

    pub async fn do_submit_block(&self) -> Result<(), Error> {
        let url = self.comm_boost.submit_block_url().unwrap();

        let signed_blinded_block = SignedBlindedBeaconBlock::default();

        self.comm_boost
            .client
            .post(url)
            .json(&signed_blinded_block)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}
