use alloy::{
    primitives::B256,
    rpc::types::beacon::{relay::ValidatorRegistration, BlsPublicKey},
};
use cb_common::pbs::{RelayClient, SignedBlindedBeaconBlock};
use reqwest::Response;

use crate::utils::generate_mock_relay;

pub struct MockValidator {
    pub comm_boost: RelayClient,
}

impl MockValidator {
    pub fn new(port: u16) -> eyre::Result<Self> {
        Ok(Self { comm_boost: generate_mock_relay(port, BlsPublicKey::default())? })
    }

    pub async fn do_get_header(&self, pubkey: Option<BlsPublicKey>) -> eyre::Result<Response> {
        let url = self.comm_boost.get_header_url(0, B256::ZERO, pubkey.unwrap_or_default())?;
        Ok(self.comm_boost.client.get(url).send().await?)
    }

    pub async fn do_get_status(&self) -> eyre::Result<Response> {
        let url = self.comm_boost.get_status_url()?;
        Ok(self.comm_boost.client.get(url).send().await?)
    }

    pub async fn do_register_validator(
        &self,
        validators: Option<Vec<ValidatorRegistration>>,
    ) -> eyre::Result<Response> {
        let url = self.comm_boost.register_validator_url().unwrap();

        let registrations = validators.unwrap_or_default();

        Ok(self.comm_boost.client.post(url).json(&registrations).send().await?)
    }

    pub async fn do_submit_block(
        &self,
        signed_blinded_block: Option<SignedBlindedBeaconBlock>,
    ) -> eyre::Result<Response> {
        let url = self.comm_boost.submit_block_url().unwrap();

        Ok(self
            .comm_boost
            .client
            .post(url)
            .json(&signed_blinded_block.unwrap_or_default())
            .send()
            .await?)
    }
}
