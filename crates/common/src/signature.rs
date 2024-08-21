use alloy::rpc::types::beacon::{constants::BLS_DST_SIG, BlsPublicKey, BlsSignature};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    constants::{APPLICATION_BUILDER_DOMAIN, GENESIS_VALIDATORS_ROOT},
    error::BlstErrorWrapper,
    signer::{schemes::bls::verify_bls_signature, BlsSecretKey},
    types::Chain,
};

pub fn sign_message(secret_key: &BlsSecretKey, msg: &[u8]) -> BlsSignature {
    let signature = secret_key.sign(msg, BLS_DST_SIG, &[]).to_bytes();
    BlsSignature::from_slice(&signature)
}

pub fn compute_signing_root(object_root: [u8; 32], signing_domain: [u8; 32]) -> [u8; 32] {
    #[derive(Default, Debug, Encode, Decode, TreeHash)]
    struct SigningData {
        object_root: [u8; 32],
        signing_domain: [u8; 32],
    }

    let signing_data = SigningData { object_root, signing_domain };
    signing_data.tree_hash_root().0
}

#[allow(dead_code)]
fn compute_builder_domain(chain: Chain) -> [u8; 32] {
    #[derive(Debug, Encode, Decode, TreeHash)]
    struct ForkData {
        fork_version: [u8; 4],
        genesis_validators_root: [u8; 32],
    }

    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&APPLICATION_BUILDER_DOMAIN);

    let fork_version = chain.fork_version();
    let fd = ForkData { fork_version, genesis_validators_root: GENESIS_VALIDATORS_ROOT };
    let fork_data_root = fd.tree_hash_root();

    domain[4..].copy_from_slice(&fork_data_root[..28]);

    domain
}

pub fn verify_signed_builder_message<T: TreeHash>(
    chain: Chain,
    pubkey: &BlsPublicKey,
    msg: &T,
    signature: &BlsSignature,
) -> Result<(), BlstErrorWrapper> {
    let domain = chain.builder_domain();
    let signing_root = compute_signing_root(msg.tree_hash_root().0, domain);

    verify_bls_signature(pubkey, &signing_root, signature)
}

pub fn sign_builder_message(
    chain: Chain,
    secret_key: &BlsSecretKey,
    msg: &impl TreeHash,
) -> BlsSignature {
    sign_builder_root(chain, secret_key, msg.tree_hash_root().0)
}

pub fn sign_builder_root(
    chain: Chain,
    secret_key: &BlsSecretKey,
    object_root: [u8; 32],
) -> BlsSignature {
    let domain = chain.builder_domain();
    let signing_root = compute_signing_root(object_root, domain);
    sign_message(secret_key, &signing_root)
}

#[cfg(test)]
mod tests {

    use super::compute_builder_domain;
    use crate::types::Chain;

    #[test]
    fn test_builder_domains() {
        assert_eq!(compute_builder_domain(Chain::Mainnet), Chain::Mainnet.builder_domain());
        assert_eq!(compute_builder_domain(Chain::Holesky), Chain::Holesky.builder_domain());
        assert_eq!(compute_builder_domain(Chain::Rhea), Chain::Rhea.builder_domain());
        assert_eq!(compute_builder_domain(Chain::Helder), Chain::Helder.builder_domain());
    }
}
