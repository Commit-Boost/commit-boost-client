use alloy::primitives::{Address, B256, aliases::B32};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    constants::{
        COMMIT_BOOST_DOMAIN, DOMAIN_BEACON_BUILDER, DOMAIN_REQUEST_AUTH, GENESIS_VALIDATORS_ROOT,
    },
    signer::{EcdsaSignature, verify_bls_signature, verify_ecdsa_signature},
    types::{self, BlsPublicKey, BlsSecretKey, BlsSignature, Chain, SignatureRequestInfo},
};

pub fn sign_message(secret_key: &BlsSecretKey, msg: B256) -> BlsSignature {
    secret_key.sign(msg)
}

pub fn compute_prop_commit_signing_root(
    chain: Chain,
    object_root: &B256,
    signature_request_info: Option<&SignatureRequestInfo>,
    domain_mask: &B32,
) -> B256 {
    let domain = compute_domain(chain, domain_mask);
    match signature_request_info {
        Some(SignatureRequestInfo { module_signing_id, nonce }) => {
            let object_root = types::PropCommitSigningInfo {
                data: *object_root,
                module_signing_id: *module_signing_id,
                nonce: *nonce,
                chain_id: chain.id(),
            }
            .tree_hash_root();
            types::SigningData { object_root, signing_domain: domain }.tree_hash_root()
        }
        None => types::SigningData { object_root: *object_root, signing_domain: domain }
            .tree_hash_root(),
    }
}

// Signing domain from a chain + 4-byte domain mask (genesis fork version, zero
// root). ref: https://github.com/ralexstokes/ethereum-consensus/blob/cf3c404043230559660810bc0c9d6d5a8498d819/ethereum-consensus/src/builder/mod.rs#L26-L29
pub fn compute_domain(chain: Chain, domain_mask: &B32) -> B256 {
    compute_domain_with_fork_version(
        chain.genesis_fork_version(),
        GENESIS_VALIDATORS_ROOT.into(),
        domain_mask,
    )
}

pub fn compute_domain_with_fork_version(
    fork_version: [u8; 4],
    genesis_validators_root: B256,
    domain_mask: &B32,
) -> B256 {
    #[derive(Debug, TreeHash)]
    struct ForkData {
        fork_version: [u8; 4],
        genesis_validators_root: B256,
    }

    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_mask.0);

    let fd = ForkData { fork_version, genesis_validators_root };
    let fork_data_root = fd.tree_hash_root();

    domain[4..].copy_from_slice(&fork_data_root[..28]);

    B256::from(domain)
}

/// ePBS bid signing domain, mirroring consensus-specs
/// `get_domain(state, DOMAIN_BEACON_BUILDER)`.
pub fn execution_payload_bid_domain(fork_version: [u8; 4], genesis_validators_root: B256) -> B256 {
    compute_domain_with_fork_version(
        fork_version,
        genesis_validators_root,
        &B32::from(DOMAIN_BEACON_BUILDER),
    )
}

/// Builder API request-auth signing domain. The request WIRE type is
/// fork-versioned per builder-specs, but the signing domain is not: the spec's
/// `compute_domain(DOMAIN_REQUEST_AUTH)` takes the genesis fork version and a
/// zero root, exactly like the validator registrations it replaces.
pub fn request_auth_domain(chain: Chain) -> B256 {
    compute_domain(chain, &B32::from(DOMAIN_REQUEST_AUTH))
}

/// Signs a `RequestAuthV1` message root under the request-auth domain.
pub fn sign_request_auth_root(
    secret_key: &BlsSecretKey,
    object_root: &B256,
    chain: Chain,
) -> BlsSignature {
    let signing_data = types::SigningData {
        object_root: *object_root,
        signing_domain: request_auth_domain(chain),
    };
    sign_message(secret_key, signing_data.tree_hash_root())
}

/// Verifies a `SignedRequestAuthV1` signature under the request-auth domain.
pub fn verify_request_auth_signature<T: TreeHash>(
    pubkey: &BlsPublicKey,
    msg: &T,
    signature: &BlsSignature,
    chain: Chain,
) -> bool {
    let signing_data = types::SigningData {
        object_root: msg.tree_hash_root(),
        signing_domain: request_auth_domain(chain),
    };
    verify_bls_signature(pubkey, signing_data.tree_hash_root(), signature)
}

pub fn verify_signed_message<T: TreeHash>(
    chain: Chain,
    pubkey: &BlsPublicKey,
    msg: &T,
    signature: &BlsSignature,
    signature_request_info: Option<&SignatureRequestInfo>,
    domain_mask: &B32,
) -> bool {
    let signing_root = compute_prop_commit_signing_root(
        chain,
        &msg.tree_hash_root(),
        signature_request_info,
        domain_mask,
    );
    verify_bls_signature(pubkey, signing_root, signature)
}

/// Signs a message with the Beacon builder domain.
pub fn sign_builder_message(
    chain: Chain,
    secret_key: &BlsSecretKey,
    msg: &impl TreeHash,
) -> BlsSignature {
    sign_builder_root(chain, secret_key, &msg.tree_hash_root())
}

pub fn sign_builder_root(
    chain: Chain,
    secret_key: &BlsSecretKey,
    object_root: &B256,
) -> BlsSignature {
    let signing_domain = chain.builder_domain();
    let signing_data =
        types::SigningData { object_root: object_root.tree_hash_root(), signing_domain };
    let signing_root = signing_data.tree_hash_root();
    sign_message(secret_key, signing_root)
}

/// Signs a message root under the ePBS execution payload bid domain.
pub fn sign_execution_payload_bid_root(
    secret_key: &BlsSecretKey,
    object_root: &B256,
    fork_version: [u8; 4],
    genesis_validators_root: B256,
) -> BlsSignature {
    let signing_data = types::SigningData {
        object_root: *object_root,
        signing_domain: execution_payload_bid_domain(fork_version, genesis_validators_root),
    };
    sign_message(secret_key, signing_data.tree_hash_root())
}

/// Verifies an ePBS execution payload bid signature under the bid domain.
pub fn verify_execution_payload_bid_signature<T: TreeHash>(
    pubkey: &BlsPublicKey,
    msg: &T,
    signature: &BlsSignature,
    fork_version: [u8; 4],
    genesis_validators_root: B256,
) -> bool {
    let signing_data = types::SigningData {
        object_root: msg.tree_hash_root(),
        signing_domain: execution_payload_bid_domain(fork_version, genesis_validators_root),
    };
    verify_bls_signature(pubkey, signing_data.tree_hash_root(), signature)
}

pub fn sign_commit_boost_root(
    chain: Chain,
    secret_key: &BlsSecretKey,
    object_root: &B256,
    signature_request_info: Option<&SignatureRequestInfo>,
) -> BlsSignature {
    let signing_root = compute_prop_commit_signing_root(
        chain,
        object_root,
        signature_request_info,
        &B32::from(COMMIT_BOOST_DOMAIN),
    );
    sign_message(secret_key, signing_root)
}

// ==============================
// === Signature Verification ===
// ==============================

/// Verifies that a proposer commitment signature was generated by the given BLS
/// key for the provided message, chain ID, and module signing ID.
pub fn verify_proposer_commitment_signature_bls(
    chain: Chain,
    pubkey: &BlsPublicKey,
    msg: &impl TreeHash,
    signature: &BlsSignature,
    module_signing_id: &B256,
    nonce: u64,
) -> bool {
    let signing_domain = compute_domain(chain, &B32::from(COMMIT_BOOST_DOMAIN));
    let object_root = types::PropCommitSigningInfo {
        data: msg.tree_hash_root(),
        module_signing_id: *module_signing_id,
        nonce,
        chain_id: chain.id(),
    }
    .tree_hash_root();
    let signing_root = types::SigningData { object_root, signing_domain }.tree_hash_root();
    verify_bls_signature(pubkey, signing_root, signature)
}

/// Verifies that a proposer commitment signature was generated by the given
/// ECDSA key for the provided message, chain ID, and module signing ID.
pub fn verify_proposer_commitment_signature_ecdsa(
    chain: Chain,
    address: &Address,
    msg: &impl TreeHash,
    signature: &EcdsaSignature,
    module_signing_id: &B256,
    nonce: u64,
) -> Result<(), eyre::Report> {
    let signing_domain = compute_domain(chain, &B32::from(COMMIT_BOOST_DOMAIN));
    let object_root = types::PropCommitSigningInfo {
        data: msg.tree_hash_root(),
        module_signing_id: *module_signing_id,
        nonce,
        chain_id: chain.id(),
    }
    .tree_hash_root();
    let signing_root = types::SigningData { object_root, signing_domain }.tree_hash_root();
    verify_ecdsa_signature(address, &signing_root, signature)
}

// ===============
// === Testing ===
// ===============

#[cfg(test)]
mod tests {

    use alloy::primitives::{U256, aliases::B32};

    use super::{compute_domain, sign_builder_message, verify_signed_message};
    use crate::{
        constants::APPLICATION_BUILDER_DOMAIN,
        pbs::{
            BlindedBeaconBlockElectra, BuilderBid, BuilderBidElectra,
            ExecutionPayloadHeaderElectra, ExecutionRequests,
        },
        types::{BlsSecretKey, Chain},
        utils::TestRandomSeed,
    };

    #[test]
    fn test_builder_domains() {
        let domain = &B32::from(APPLICATION_BUILDER_DOMAIN);
        assert_eq!(compute_domain(Chain::Mainnet, domain), Chain::Mainnet.builder_domain());
        assert_eq!(compute_domain(Chain::Holesky, domain), Chain::Holesky.builder_domain());
        assert_eq!(compute_domain(Chain::Sepolia, domain), Chain::Sepolia.builder_domain());
        assert_eq!(compute_domain(Chain::Hoodi, domain), Chain::Hoodi.builder_domain());
    }

    #[test]
    fn test_builder_bid_sign_and_verify() {
        let secret_key = BlsSecretKey::test_random();
        let pubkey = secret_key.public_key();

        let message = BuilderBid::Electra(BuilderBidElectra {
            header: ExecutionPayloadHeaderElectra::test_random(),
            blob_kzg_commitments: Default::default(),
            execution_requests: ExecutionRequests::default(),
            value: U256::from(10),
            pubkey: pubkey.clone().into(),
        });

        let sig = sign_builder_message(Chain::Mainnet, &secret_key, &message);

        assert!(verify_signed_message(
            Chain::Mainnet,
            &pubkey,
            &message,
            &sig,
            None,
            &B32::from(APPLICATION_BUILDER_DOMAIN),
        ));
    }

    #[test]
    fn test_blinded_block_sign_and_verify() {
        let secret_key = BlsSecretKey::test_random();
        let pubkey = secret_key.public_key();

        let block = BlindedBeaconBlockElectra::test_random();

        let sig = sign_builder_message(Chain::Mainnet, &secret_key, &block);

        assert!(verify_signed_message(
            Chain::Mainnet,
            &pubkey,
            &block,
            &sig,
            None,
            &B32::from(APPLICATION_BUILDER_DOMAIN),
        ));
    }
}
