use alloy::{primitives::B256, rpc::types::beacon::relay::ValidatorRegistration};
use cb_common::{
    pbs::{BuilderApiVersion, RelayClient, SignedBlindedBeaconBlock},
    types::BlsPublicKey,
    utils::{CONSENSUS_VERSION_HEADER, EncodingType, ForkName, bls_pubkey_from_hex},
};
use reqwest::{
    Response,
    header::{ACCEPT, CONTENT_TYPE},
};
use ssz::Encode;

use crate::utils::generate_mock_relay;

pub struct MockValidator {
    pub comm_boost: RelayClient,
}

impl MockValidator {
    pub fn new(port: u16) -> eyre::Result<Self> {
        let pubkey = bls_pubkey_from_hex(
            "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae",
        )?;
        Ok(Self { comm_boost: generate_mock_relay(port, pubkey)? })
    }

    pub async fn do_get_header(
        &self,
        pubkey: Option<BlsPublicKey>,
        accept: Option<EncodingType>,
        fork_name: ForkName,
    ) -> eyre::Result<Response> {
        let default_pubkey = bls_pubkey_from_hex(
            "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae",
        )?;
        let url =
            self.comm_boost.get_header_url(0, &B256::ZERO, &pubkey.unwrap_or(default_pubkey))?;
        let res = self
            .comm_boost
            .client
            .get(url)
            .header(ACCEPT, &accept.unwrap_or(EncodingType::Json).to_string())
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

    pub async fn do_submit_block_v1(
        &self,
        signed_blinded_block_opt: Option<SignedBlindedBeaconBlock>,
        accept: EncodingType,
        content_type: EncodingType,
        fork_name: ForkName,
    ) -> eyre::Result<Response> {
        self.do_submit_block_impl(
            signed_blinded_block_opt,
            accept,
            content_type,
            fork_name,
            BuilderApiVersion::V1,
        )
        .await
    }

    pub async fn do_submit_block_v2(
        &self,
        signed_blinded_block_opt: Option<SignedBlindedBeaconBlock>,
        accept: EncodingType,
        content_type: EncodingType,
        fork_name: ForkName,
    ) -> eyre::Result<Response> {
        self.do_submit_block_impl(
            signed_blinded_block_opt,
            accept,
            content_type,
            fork_name,
            BuilderApiVersion::V2,
        )
        .await
    }

    async fn do_submit_block_impl(
        &self,
        signed_blinded_block_opt: Option<SignedBlindedBeaconBlock>,
        accept: EncodingType,
        content_type: EncodingType,
        fork_name: ForkName,
        api_version: BuilderApiVersion,
    ) -> eyre::Result<Response> {
        let url = self.comm_boost.submit_block_url(api_version).unwrap();

        let signed_blinded_block =
            signed_blinded_block_opt.unwrap_or_else(load_test_signed_blinded_block);
        let body = match content_type {
            EncodingType::Json => serde_json::to_vec(&signed_blinded_block).unwrap(),
            EncodingType::Ssz => signed_blinded_block.as_ssz_bytes(),
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

pub fn load_test_signed_blinded_block() -> SignedBlindedBeaconBlock {
    let data_json = include_str!(
        "../../crates/common/src/pbs/types/testdata/signed-blinded-beacon-block-electra-2.json"
    );
    serde_json::from_str(data_json).unwrap()
}
