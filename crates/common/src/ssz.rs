use alloy::primitives::U256;
use lh_bls::Signature;
use lh_types::ForkName;
use ssz::BYTES_PER_LENGTH_OFFSET;

use crate::pbs::{
    BuilderBidFulu, ExecutionPayloadHeaderFulu, ExecutionRequests, KzgCommitments,
    error::SszValueError,
};

// Get the offset of the message in a SignedBuilderBid SSZ structure
fn get_ssz_value_offset_for_fork(fork: ForkName) -> Result<usize, SszValueError> {
    match fork {
        ForkName::Fulu => {
            // Message goes header -> blob_kzg_commitments -> execution_requests -> value ->
            // pubkey
            Ok(get_message_offset::<BuilderBidFulu>() +
                <ExecutionPayloadHeaderFulu as ssz::Decode>::ssz_fixed_len() +
                <KzgCommitments as ssz::Decode>::ssz_fixed_len() +
                <ExecutionRequests as ssz::Decode>::ssz_fixed_len())
        }

        _ => Err(SszValueError::UnsupportedFork { name: fork }),
    }
}

/// Extracts the bid value from SSZ-encoded SignedBuilderBid response bytes.
pub fn get_bid_value_from_signed_builder_bid_ssz(
    response_bytes: &[u8],
    fork: ForkName,
) -> Result<U256, SszValueError> {
    let value_offset = get_ssz_value_offset_for_fork(fork)?;

    // Sanity check the response length so we don't panic trying to slice it
    let end_offset = value_offset + 32; // U256 is 32 bytes
    if response_bytes.len() < end_offset {
        return Err(SszValueError::InvalidPayloadLength {
            required: end_offset,
            actual: response_bytes.len(),
        });
    }

    // Extract the value bytes and convert to U256
    let value_bytes = &response_bytes[value_offset..end_offset];
    let value = U256::from_le_slice(value_bytes);
    Ok(value)
}

// Get the offset where the `message` field starts in some SignedBuilderBid SSZ
// data. Requires that SignedBuilderBid always has the following structure:
// message -> signature
// where `message` is a BuilderBid type determined by the fork choice, and
// `signature` is a fixed-length Signature type.
fn get_message_offset<BuilderBidType>() -> usize
where
    BuilderBidType: ssz::Encode,
{
    // Since `message` is the first field, its offset is always 0
    let mut offset = 0;

    // If it's variable length, then it will be represented by a pointer to
    // the actual data, so we need to get the location of where that data starts
    if !BuilderBidType::is_ssz_fixed_len() {
        offset += BYTES_PER_LENGTH_OFFSET + <Signature as ssz::Decode>::ssz_fixed_len();
    }

    offset
}

#[cfg(test)]
mod test {
    use alloy::primitives::U256;
    use lh_types::ForkName;
    use ssz::Encode;

    use super::get_bid_value_from_signed_builder_bid_ssz;
    use crate::{
        pbs::{
            BuilderBid, BuilderBidFulu, ExecutionPayloadHeaderFulu, ExecutionRequests,
            SignedBuilderBid, error::SszValueError,
        },
        types::{BlsPublicKeyBytes, BlsSignature},
        utils::TestRandomSeed,
    };

    #[test]
    fn test_ssz_value_extraction_unsupported_fork() {
        let dummy_bytes = vec![0u8; 1000];
        let err =
            get_bid_value_from_signed_builder_bid_ssz(&dummy_bytes, ForkName::Altair).unwrap_err();
        assert!(matches!(err, SszValueError::UnsupportedFork { .. }));
    }

    #[test]
    fn test_ssz_value_extraction_truncated_payload() {
        // A payload that is far too short for any supported fork's value offset
        let tiny_bytes = vec![0u8; 4];
        let err =
            get_bid_value_from_signed_builder_bid_ssz(&tiny_bytes, ForkName::Fulu).unwrap_err();
        assert!(matches!(err, SszValueError::InvalidPayloadLength { .. }));
    }

    /// Per-fork positive tests: construct a `SignedBuilderBid` with a known
    /// value for each supported fork, SSZ-encode it, and verify
    /// `get_bid_value_from_signed_builder_bid_ssz` round-trips correctly.
    #[test]
    fn test_ssz_value_extraction_with_known_bid() {
        // Distinctive value — large enough that endianness bugs produce a
        // different number and zero-matches are impossible.
        let known_value = U256::from(0x0102_0304_0506_0708_u64);
        let pubkey = BlsPublicKeyBytes::test_random();
        let sig = BlsSignature::test_random();

        // ── Fulu ─────────────────────────────────────────────────────────────
        {
            let message = BuilderBid::Fulu(BuilderBidFulu {
                header: ExecutionPayloadHeaderFulu::test_random(),
                blob_kzg_commitments: Default::default(),
                execution_requests: ExecutionRequests::default(),
                value: known_value,
                pubkey,
            });
            let bid = SignedBuilderBid { message, signature: sig };
            let got =
                get_bid_value_from_signed_builder_bid_ssz(&bid.as_ssz_bytes(), ForkName::Fulu)
                    .expect("Fulu extraction failed");
            assert_eq!(got, known_value, "Fulu: value mismatch");
        }
    }
}
