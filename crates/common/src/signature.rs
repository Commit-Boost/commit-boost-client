use alloy::rpc::types::beacon::{constants::BLS_DST_SIG, BlsPublicKey, BlsSignature};
use blst::{
    min_pk::{PublicKey, SecretKey as BlsSecretKey, Signature},
    BLST_ERROR,
};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    constants::{APPLICATION_BUILDER_DOMAIN, GENESIS_VALIDATORS_ROOT},
    error::BlstErrorWrapper,
    signer::SecretKey,
    types::Chain,
    utils::{alloy_pubkey_to_blst, alloy_sig_to_blst},
};

// TODO(David): Think about removing
pub fn verify_signature(
    pubkey: &BlsPublicKey,
    msg: &[u8],
    signature: &BlsSignature,
) -> Result<(), BlstErrorWrapper> {
    let pubkey: PublicKey = alloy_pubkey_to_blst(pubkey)?;
    let signature: Signature = alloy_sig_to_blst(signature)?;

    let res = signature.verify(true, msg, BLS_DST_SIG, &[], &pubkey, true);
    if res == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(res.into())
    }
}

pub fn sign_message(secret_key: &BlsSecretKey, msg: &[u8]) -> BlsSignature {
    let signature = secret_key.sign(msg, BLS_DST_SIG, &[]).to_bytes();
    BlsSignature::from_slice(&signature)
}

#[derive(Default, Debug, Encode, Decode, TreeHash)]
struct SigningData {
    object_root: [u8; 32],
    signing_domain: [u8; 32],
}

pub fn compute_signing_root(object_root: [u8; 32], signing_domain: [u8; 32]) -> [u8; 32] {
    let signing_data = SigningData { object_root, signing_domain };
    signing_data.tree_hash_root().0
}

#[derive(Debug, Encode, Decode, TreeHash)]
struct ForkData {
    fork_version: [u8; 4],
    genesis_validators_root: [u8; 32],
}

#[allow(dead_code)]
fn compute_builder_domain(chain: Chain) -> [u8; 32] {
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

    verify_signature(pubkey, &signing_root, signature)
}

pub fn sign_builder_message<T: SecretKey>(
    chain: Chain,
    secret_key: &T,
    msg: &impl TreeHash,
) -> T::Signature {
    sign_builder_root(chain, secret_key, msg.tree_hash_root().0)
}

// TODO(David): This utility function seems unnecessary
pub fn sign_builder_root<T: SecretKey>(
    chain: Chain,
    secret_key: &T,
    object_root: [u8; 32],
) -> T::Signature {
    let domain = chain.builder_domain();
    let signing_root = compute_signing_root(object_root, domain);
    secret_key.sign(&signing_root)
    // sign_message(secret_key, &signing_root)
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
