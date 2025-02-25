use alloy::{
    primitives::B256,
    rpc::types::beacon::{relay::ValidatorRegistration, BlsPublicKey},
};
use cb_common::{
    pbs::{RelayClient, SignedBlindedBeaconBlock},
    utils::{Accept, ContentType, ForkName, CONSENSUS_VERSION_HEADER},
};
use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    Response,
};
use ssz::Encode;

use crate::utils::generate_mock_relay;

pub struct MockValidator {
    pub comm_boost: RelayClient,
}

impl MockValidator {
    pub fn new(port: u16) -> eyre::Result<Self> {
        Ok(Self { comm_boost: generate_mock_relay(port, BlsPublicKey::default())? })
    }

    pub async fn do_get_header(
        &self,
        pubkey: Option<BlsPublicKey>,
        accept: Option<Accept>,
        fork_name: ForkName,
    ) -> eyre::Result<Response> {
        let url = self
            .comm_boost
            .get_header_url(0, B256::ZERO, pubkey.unwrap_or(BlsPublicKey::ZERO))
            .unwrap();
        let res = self
            .comm_boost
            .client
            .get(url)
            .header(ACCEPT, &accept.unwrap_or(Accept::Any).to_string())
            .header(CONSENSUS_VERSION_HEADER, &fork_name.to_string())
            .send()
            .await?;
        Ok(res)
    }

    pub async fn do_get_status(&self) -> eyre::Result<Response> {
        let url = self.comm_boost.get_status_url()?;
        Ok(self.comm_boost.client.get(url).send().await?)
    }

    pub async fn do_register_validator(&self) -> eyre::Result<Response> {
        self.do_register_custom_validators(vec![]).await
    }

    pub async fn do_register_custom_validators(
        &self,
        registrations: Vec<ValidatorRegistration>,
    ) -> eyre::Result<Response> {
        let url = self.comm_boost.register_validator_url().unwrap();

        Ok(self.comm_boost.client.post(url).json(&registrations).send().await?)
    }

    pub async fn do_submit_block(
        &self,
        signed_blinded_block_opt: Option<SignedBlindedBeaconBlock>,
        accept: Accept,
        content_type: ContentType,
        fork_name: ForkName,
    ) -> eyre::Result<Response> {
        let url = self.comm_boost.submit_block_url().unwrap();

        let signed_blinded_block = signed_blinded_block_opt.unwrap_or_default();

        let body = match content_type {
            ContentType::Json => serde_json::to_vec(&signed_blinded_block).unwrap(),
            ContentType::Ssz => signed_blinded_block.as_ssz_bytes(),
        };

        Ok(self
            .comm_boost
            .client
            .post(url)
            .body(body)
            .header(CONSENSUS_VERSION_HEADER, &fork_name.to_string())
            .header(CONTENT_TYPE, &content_type.to_string())
            .header(ACCEPT, &accept.to_string())
            .send()
            .await?)
    }
}
