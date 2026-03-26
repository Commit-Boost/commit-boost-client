use std::sync::Arc;

use alloy::{
    primitives::{B256, U256, aliases::B32},
    providers::Provider,
    rpc::types::Block,
};
use cb_common::{
    constants::APPLICATION_BUILDER_DOMAIN,
    pbs::{
        EMPTY_TX_ROOT_HASH, ForkName, ForkVersionDecode, GetHeaderInfo, GetHeaderResponse,
        SignedBuilderBid,
        error::{PbsError, ValidationError},
    },
    signature::verify_signed_message,
    types::{BlsPublicKey, BlsPublicKeyBytes, BlsSignature, Chain},
    utils::timestamp_of_slot_start_sec,
};
use parking_lot::RwLock;
use serde::Deserialize;
use tracing::{debug, error};
use tree_hash::TreeHash;
use url::Url;

use crate::utils::check_gas_limit;

/// Fetch the parent block from the RPC URL for extra validation of the header.
/// Extra validation will be skipped if:
/// - relay returns header before parent block is fetched
/// - parent block is not found, eg because of a RPC delay
pub async fn fetch_parent_block(
    rpc_url: Url,
    parent_hash: B256,
    parent_block: Arc<RwLock<Option<Block>>>,
) {
    let provider = alloy::providers::ProviderBuilder::new().connect_http(rpc_url).to_owned();

    debug!(%parent_hash, "fetching parent block");

    match provider.get_block_by_hash(parent_hash).await {
        Ok(maybe_block) => {
            debug!(block_found = maybe_block.is_some(), "fetched parent block");
            let mut guard = parent_block.write();
            *guard = maybe_block;
        }
        Err(err) => {
            error!(%err, "fetch failed");
        }
    }
}

pub struct HeaderData {
    pub block_hash: B256,
    pub parent_hash: B256,
    pub tx_root: B256,
    pub value: U256,
    pub timestamp: u64,
}

pub fn validate_header_data(
    header_data: &HeaderData,
    chain: Chain,
    expected_parent_hash: B256,
    minimum_bid_wei: U256,
    slot: u64,
) -> Result<(), ValidationError> {
    if header_data.block_hash == B256::ZERO {
        return Err(ValidationError::EmptyBlockhash);
    }

    if expected_parent_hash != header_data.parent_hash {
        return Err(ValidationError::ParentHashMismatch {
            expected: expected_parent_hash,
            got: header_data.parent_hash,
        });
    }

    if header_data.tx_root == EMPTY_TX_ROOT_HASH {
        return Err(ValidationError::EmptyTxRoot);
    }

    if header_data.value < minimum_bid_wei {
        return Err(ValidationError::BidTooLow { min: minimum_bid_wei, got: header_data.value });
    }

    let expected_timestamp = timestamp_of_slot_start_sec(slot, chain);
    if expected_timestamp != header_data.timestamp {
        return Err(ValidationError::TimestampMismatch {
            expected: expected_timestamp,
            got: header_data.timestamp,
        });
    }

    Ok(())
}

pub fn validate_signature<T: TreeHash>(
    chain: Chain,
    expected_relay_pubkey: &BlsPublicKey,
    received_relay_pubkey: &BlsPublicKeyBytes,
    message: &T,
    signature: &BlsSignature,
) -> Result<(), ValidationError> {
    if expected_relay_pubkey.serialize() != received_relay_pubkey.as_serialized() {
        return Err(ValidationError::PubkeyMismatch {
            expected: BlsPublicKeyBytes::from(expected_relay_pubkey),
            got: *received_relay_pubkey,
        });
    }

    if !verify_signed_message(
        chain,
        expected_relay_pubkey,
        &message,
        signature,
        None,
        &B32::from(APPLICATION_BUILDER_DOMAIN),
    ) {
        return Err(ValidationError::Sigverify);
    }

    Ok(())
}

pub fn extra_validation(
    parent_block: &Block,
    signed_header: &GetHeaderResponse,
) -> Result<(), ValidationError> {
    if signed_header.block_number() != parent_block.header.number + 1 {
        return Err(ValidationError::BlockNumberMismatch {
            parent: parent_block.header.number,
            header: signed_header.block_number(),
        });
    }

    if !check_gas_limit(signed_header.gas_limit(), parent_block.header.gas_limit) {
        return Err(ValidationError::GasLimit {
            parent: parent_block.header.gas_limit,
            header: signed_header.gas_limit(),
        });
    };

    Ok(())
}

pub fn decode_json_payload(response_bytes: &[u8]) -> Result<GetHeaderResponse, PbsError> {
    match serde_json::from_slice::<GetHeaderResponse>(response_bytes) {
        Ok(parsed) => Ok(parsed),
        Err(err) => Err(PbsError::JsonDecode {
            err,
            raw: String::from_utf8_lossy(response_bytes).into_owned(),
        }),
    }
}

pub fn get_light_info_from_json(response_bytes: &[u8]) -> Result<(ForkName, U256), PbsError> {
    #[derive(Deserialize)]
    struct LightBuilderBid {
        #[serde(with = "serde_utils::quoted_u256")]
        pub value: U256,
    }

    #[derive(Deserialize)]
    struct LightSignedBuilderBid {
        pub message: LightBuilderBid,
    }

    #[derive(Deserialize)]
    struct LightHeaderResponse {
        version: ForkName,
        data: LightSignedBuilderBid,
    }

    match serde_json::from_slice::<LightHeaderResponse>(response_bytes) {
        Ok(parsed) => Ok((parsed.version, parsed.data.message.value)),
        Err(err) => Err(PbsError::JsonDecode {
            err,
            raw: String::from_utf8_lossy(response_bytes).into_owned(),
        }),
    }
}

pub fn decode_ssz_payload(
    response_bytes: &[u8],
    fork: ForkName,
) -> Result<GetHeaderResponse, PbsError> {
    let data = SignedBuilderBid::from_ssz_bytes_by_fork(response_bytes, fork).map_err(|e| {
        PbsError::RelayResponse {
            error_msg: (format!("error decoding relay payload: {e:?}")).to_string(),
            code: 200,
        }
    })?;
    Ok(GetHeaderResponse { version: fork, data, metadata: Default::default() })
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use alloy::primitives::{B256, U256};
    use cb_common::{
        pbs::*,
        signature::sign_builder_message,
        types::{BlsPublicKeyBytes, BlsSecretKey, BlsSignature, Chain},
        utils::{
            TestRandomSeed, get_bid_value_from_signed_builder_bid_ssz, timestamp_of_slot_start_sec,
        },
    };
    use ssz::Encode;

    use super::{validate_header_data, *};

    #[test]
    fn test_validate_header() {
        let slot = 5;
        let parent_hash = B256::from_slice(&[1; 32]);
        let chain = Chain::Holesky;
        let min_bid = U256::from(10);

        let mut mock_header_data = HeaderData {
            block_hash: B256::default(),
            parent_hash: B256::default(),
            tx_root: EMPTY_TX_ROOT_HASH,
            value: U256::default(),
            timestamp: 0,
        };

        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::EmptyBlockhash)
        );

        mock_header_data.block_hash.0[1] = 1;

        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::ParentHashMismatch {
                expected: parent_hash,
                got: B256::default()
            })
        );

        mock_header_data.parent_hash = parent_hash;

        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::EmptyTxRoot)
        );

        mock_header_data.tx_root = Default::default();

        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::BidTooLow { min: min_bid, got: U256::ZERO })
        );

        mock_header_data.value = U256::from(11);

        let expected = timestamp_of_slot_start_sec(slot, chain);
        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::TimestampMismatch { expected, got: 0 })
        );

        mock_header_data.timestamp = expected;

        assert!(validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot).is_ok());
    }

    #[test]
    fn test_validate_signature() {
        let secret_key = BlsSecretKey::test_random();
        let pubkey = secret_key.public_key();
        let wrong_pubkey = BlsPublicKeyBytes::test_random();
        let wrong_signature = BlsSignature::test_random();

        let message = B256::random();

        let signature = sign_builder_message(Chain::Holesky, &secret_key, &message);

        assert_eq!(
            validate_signature(Chain::Holesky, &pubkey, &wrong_pubkey, &message, &wrong_signature),
            Err(ValidationError::PubkeyMismatch {
                expected: BlsPublicKeyBytes::from(&pubkey),
                got: wrong_pubkey
            })
        );

        assert!(matches!(
            validate_signature(
                Chain::Holesky,
                &pubkey,
                &BlsPublicKeyBytes::from(&pubkey),
                &message,
                &wrong_signature
            ),
            Err(ValidationError::Sigverify)
        ));

        assert!(
            validate_signature(
                Chain::Holesky,
                &pubkey,
                &BlsPublicKeyBytes::from(&pubkey),
                &message,
                &signature
            )
            .is_ok()
        );
    }

    #[test]
    fn test_ssz_value_extraction() {
        for fork_name in ForkName::list_all() {
            match fork_name {
                // Handle forks that didn't have builder bids yet
                ForkName::Altair | ForkName::Base => continue,

                // Handle supported forks
                ForkName::Bellatrix |
                ForkName::Capella |
                ForkName::Deneb |
                ForkName::Electra |
                ForkName::Fulu => {}

                // Skip unsupported forks
                ForkName::Gloas => continue,
            }

            // Load get_header JSON from test data
            let fork_name_str = fork_name.to_string().to_lowercase();
            let path_str = format!("../../tests/data/get_header/{fork_name_str}.json");
            let path = Path::new(path_str.as_str());
            let json_bytes = fs::read(path).expect("file not found");
            let decoded = decode_json_payload(&json_bytes).expect("failed to decode JSON");

            // Extract the bid value from the SSZ
            let encoded = decoded.data.as_ssz_bytes();
            let bid_value = get_bid_value_from_signed_builder_bid_ssz(&encoded, fork_name)
                .expect("failed to extract bid value from SSZ");

            // Compare to the original value
            println!("Testing fork: {}", fork_name);
            println!("Original value: {}", decoded.value());
            println!("Extracted value: {}", bid_value);
            assert_eq!(*decoded.value(), bid_value);
        }
    }
}
