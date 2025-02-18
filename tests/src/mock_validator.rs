use alloy::{
    primitives::B256,
    rpc::types::beacon::{relay::ValidatorRegistration, BlsPublicKey},
};
use cb_common::{
    pbs::{
        GetHeaderResponse, RelayClient, SignedBlindedBeaconBlock, SignedExecutionPayloadHeader,
        Version,
    },
    utils::{get_content_type_header, Accept, ContentType, CONSENSUS_VERSION_HEADER},
};
use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    Error,
};
use ssz::{Decode, Encode};

use crate::utils::generate_mock_relay;

pub struct MockValidator {
    comm_boost: RelayClient,
}

impl MockValidator {
    pub fn new(port: u16) -> eyre::Result<Self> {
        Ok(Self { comm_boost: generate_mock_relay(port, BlsPublicKey::default())? })
    }

    pub async fn do_get_header(
        &self,
        pubkey: Option<BlsPublicKey>,
        accept: Accept,
    ) -> Result<(), Error> {
        let url = self
            .comm_boost
            .get_header_url(0, B256::ZERO, pubkey.unwrap_or(BlsPublicKey::ZERO))
            .unwrap();
        let res =
            self.comm_boost.client.get(url).header(ACCEPT, &accept.to_string()).send().await?;
        let content_type = get_content_type_header(res.headers());
        let res_bytes = res.bytes().await?;

        match content_type {
            ContentType::Json => {
                assert!(serde_json::from_slice::<GetHeaderResponse>(&res_bytes).is_ok())
            }
            ContentType::Ssz => {
                assert!(SignedExecutionPayloadHeader::from_ssz_bytes(&res_bytes).is_ok())
            }
        }

        Ok(())
    }

    pub async fn do_get_status(&self) -> Result<(), Error> {
        let url = self.comm_boost.get_status_url().unwrap();
        let _res = self.comm_boost.client.get(url).send().await?;
        // assert!(res.status().is_success());

        Ok(())
    }

    pub async fn do_register_validator(&self) -> Result<(), Error> {
        self.do_register_custom_validators(vec![]).await
    }

    pub async fn do_register_custom_validators(
        &self,
        registrations: Vec<ValidatorRegistration>,
    ) -> Result<(), Error> {
        let url = self.comm_boost.register_validator_url().unwrap();

        self.comm_boost.client.post(url).json(&registrations).send().await?.error_for_status()?;

        Ok(())
    }

    pub async fn do_submit_block(
        &self,
        accept: Accept,
        content_type: ContentType,
    ) -> Result<(), Error> {
        let url = self.comm_boost.submit_block_url().unwrap();

        let signed_blinded_block = SignedBlindedBeaconBlock::default();

        let body = match content_type {
            ContentType::Json => serde_json::to_vec(&signed_blinded_block).unwrap(),
            ContentType::Ssz => signed_blinded_block.as_ssz_bytes(),
        };

        self.comm_boost
            .client
            .post(url)
            .body(body)
            .header(CONSENSUS_VERSION_HEADER, Version::Deneb.to_string())
            .header(CONTENT_TYPE, &content_type.to_string())
            .header(ACCEPT, &accept.to_string())
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}
