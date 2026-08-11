use alloy::{primitives::B256, rpc::types::beacon::relay::ValidatorRegistration};
use cb_common::{
    pbs::{
        BuilderApiVersion, BuilderPreferencesRequest, HEADER_START_TIME_UNIX_MS, HEADER_TIMEOUT_MS,
        RelayClient, SignedBeaconBlock, SignedBlindedBeaconBlock, SignedRequestAuth,
    },
    types::{BlsPublicKey, KnownChain},
    utils::{bls_pubkey_from_hex, utcnow_ms},
    wire::{CONSENSUS_VERSION_HEADER, EncodingType},
};
use lh_types::ForkName;
use reqwest::{
    Response,
    header::{ACCEPT, CONTENT_TYPE},
};
use ssz::Encode;

use crate::utils::generate_mock_relay;

/// Timeout a test beacon node advertises on bid requests; long enough that the
/// deadline never bites in tests.
const DEFAULT_TEST_TIMEOUT_MS: u64 = 60_000;

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
        accept: Vec<EncodingType>,
        fork_name: ForkName,
    ) -> eyre::Result<Response> {
        let default_pubkey = bls_pubkey_from_hex(
            "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae",
        )?;
        let slot = match fork_name {
            ForkName::Fulu => KnownChain::Hoodi.fulu_fork_slot() + 1,
            _ => 0,
        };

        let url =
            self.comm_boost.get_header_url(slot, &B256::ZERO, &pubkey.unwrap_or(default_pubkey))?;
        let accept = match accept.len() {
            0 => None,
            1 => Some(accept.into_iter().next().unwrap().to_string()),
            _ => {
                let accept_strings: Vec<String> =
                    accept.into_iter().map(|e| e.to_string()).collect();
                Some(accept_strings.join(", "))
            }
        };
        let mut res = self
            .comm_boost
            .client
            .get(url)
            .header(CONSENSUS_VERSION_HEADER, &fork_name.to_string());
        if let Some(accept_header) = accept {
            res = res.header(ACCEPT, accept_header);
        }
        let res = res.send().await?;
        Ok(res)
    }

    /// Submits builder preferences for `pubkey`, encoding the body as
    /// `content_type` so a test can exercise both wire formats. The spec makes
    /// `Eth-Consensus-Version` required, so a compliant BN always sets it to
    /// Gloas; header-less negative tests build their request by hand.
    pub async fn do_submit_builder_preferences(
        &self,
        pubkey: Option<BlsPublicKey>,
        request: &BuilderPreferencesRequest,
        content_type: EncodingType,
    ) -> eyre::Result<Response> {
        let default_pubkey = bls_pubkey_from_hex(
            "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae",
        )?;
        let url =
            self.comm_boost.submit_builder_preferences_url(&pubkey.unwrap_or(default_pubkey))?;

        let body = match content_type {
            EncodingType::Json => serde_json::to_vec(request)?,
            EncodingType::Ssz => request.as_ssz_bytes(),
        };
        let res = self
            .comm_boost
            .client
            .post(url)
            .header(CONTENT_TYPE, content_type.content_type_header().clone())
            .header(CONSENSUS_VERSION_HEADER, ForkName::Gloas.to_string())
            .body(body)
            .send()
            .await?;
        Ok(res)
    }

    /// Submits a `SignedBeaconBlock`, encoding the body as `content_type`. The
    /// spec requires `Eth-Consensus-Version` on every submission, so it is
    /// always set to Gloas (the only fork this endpoint serves).
    pub async fn do_submit_signed_beacon_block(
        &self,
        block: &SignedBeaconBlock,
        content_type: EncodingType,
    ) -> eyre::Result<Response> {
        let url = self.comm_boost.submit_signed_beacon_block_url()?;
        let body = match content_type {
            EncodingType::Json => serde_json::to_vec(block)?,
            EncodingType::Ssz => block.as_ssz_bytes(),
        };
        let res = self
            .comm_boost
            .client
            .post(url)
            .header(CONTENT_TYPE, content_type.content_type_header().clone())
            .header(CONSENSUS_VERSION_HEADER, ForkName::Gloas.to_string())
            .body(body)
            .send()
            .await?;
        Ok(res)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn do_get_execution_payload_bid(
        &self,
        slot: u64,
        parent_hash: B256,
        parent_root: B256,
        pubkey: Option<BlsPublicKey>,
        auth: Option<&SignedRequestAuth>,
        accept: Vec<EncodingType>,
    ) -> eyre::Result<Response> {
        self.do_get_execution_payload_bid_with_timeout(
            slot,
            parent_hash,
            parent_root,
            pubkey,
            auth,
            accept,
            DEFAULT_TEST_TIMEOUT_MS,
        )
        .await
    }

    /// Same, but with the proposer's `X-Timeout-Ms` under the test's control:
    /// that header is what bounds the whole bid poll ladder.
    #[allow(clippy::too_many_arguments)]
    pub async fn do_get_execution_payload_bid_with_timeout(
        &self,
        slot: u64,
        parent_hash: B256,
        parent_root: B256,
        pubkey: Option<BlsPublicKey>,
        auth: Option<&SignedRequestAuth>,
        accept: Vec<EncodingType>,
        timeout_ms: u64,
    ) -> eyre::Result<Response> {
        let default_pubkey = bls_pubkey_from_hex(
            "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae",
        )?;
        let url = self.comm_boost.get_execution_payload_bid_url(
            slot,
            &parent_hash,
            &parent_root,
            &pubkey.unwrap_or(default_pubkey),
        )?;
        // The spec requires both timing headers and `Eth-Consensus-Version` on
        // every bid request; header-less negative tests build theirs by hand
        let mut req = self
            .comm_boost
            .client
            .post(url)
            .header(HEADER_START_TIME_UNIX_MS, utcnow_ms())
            .header(HEADER_TIMEOUT_MS, timeout_ms)
            .header(CONSENSUS_VERSION_HEADER, ForkName::Gloas.to_string());
        if !accept.is_empty() {
            let accept_header = accept.iter().map(|e| e.to_string()).collect::<Vec<_>>().join(", ");
            req = req.header(ACCEPT, accept_header);
        }
        let req = match auth {
            Some(auth) => req.json(auth),
            None => req,
        };
        Ok(req.send().await?)
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
        accept: Vec<EncodingType>,
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
        accept: Vec<EncodingType>,
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
        accept: Vec<EncodingType>,
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

        let accept = match accept.len() {
            0 => None,
            1 => Some(accept.into_iter().next().unwrap().to_string()),
            _ => {
                // Ordered: first-listed is highest preference. Server honors
                // RFC 9110 §12.5.1 (first-listed wins at equal q).
                let accept_strings: Vec<String> =
                    accept.into_iter().map(|e| e.to_string()).collect();
                Some(accept_strings.join(", "))
            }
        };
        let mut res = self
            .comm_boost
            .client
            .post(url)
            .body(body)
            .header(CONSENSUS_VERSION_HEADER, &fork_name.to_string())
            .header(CONTENT_TYPE, &content_type.to_string());
        if let Some(accept_header) = accept {
            res = res.header(ACCEPT, accept_header);
        }
        let res = res.send().await?;
        Ok(res)
    }
}

pub fn load_test_signed_blinded_block() -> SignedBlindedBeaconBlock {
    let data_json = include_str!(
        "../../crates/common/src/pbs/types/testdata/signed-blinded-beacon-block-electra-2.json"
    );
    serde_json::from_str(data_json).unwrap()
}
