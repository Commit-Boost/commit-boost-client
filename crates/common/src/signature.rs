use alloy::primitives::B256;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    constants::{COMMIT_BOOST_DOMAIN, GENESIS_VALIDATORS_ROOT},
    pbs::{BlsPublicKey, BlsSecretKey, BlsSignature},
    signer::verify_bls_signature,
    types::Chain,
};

pub fn sign_message(secret_key: &BlsSecretKey, msg: B256) -> BlsSignature {
    secret_key.sign(msg)
}

pub fn compute_signing_root(object_root: B256, signing_domain: B256) -> B256 {
    #[derive(Default, Debug, TreeHash)]
    struct SigningData {
        object_root: B256,
        signing_domain: B256,
    }

    let signing_data = SigningData { object_root, signing_domain };
    signing_data.tree_hash_root()
}

// NOTE: this currently works only for builder domain signatures and
// verifications
// ref: https://github.com/ralexstokes/ethereum-consensus/blob/cf3c404043230559660810bc0c9d6d5a8498d819/ethereum-consensus/src/builder/mod.rs#L26-L29
pub fn compute_domain(chain: Chain, domain_mask: [u8; 4]) -> B256 {
    #[derive(Debug, TreeHash)]
    struct ForkData {
        fork_version: [u8; 4],
        genesis_validators_root: B256,
    }

    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_mask);

    let fork_version = chain.genesis_fork_version();
    let fd = ForkData { fork_version, genesis_validators_root: GENESIS_VALIDATORS_ROOT.into() };
    let fork_data_root = fd.tree_hash_root();

    domain[4..].copy_from_slice(&fork_data_root[..28]);

    domain.into()
}

pub fn verify_signed_message<T: TreeHash>(
    chain: Chain,
    pubkey: &BlsPublicKey,
    msg: &T,
    signature: &BlsSignature,
    domain_mask: [u8; 4],
) -> bool {
    let domain = compute_domain(chain, domain_mask);
    let signing_root = compute_signing_root(msg.tree_hash_root(), domain);

    verify_bls_signature(pubkey, signing_root, signature)
}

pub fn sign_builder_message(
    chain: Chain,
    secret_key: &BlsSecretKey,
    msg: &impl TreeHash,
) -> BlsSignature {
    sign_builder_root(chain, secret_key, msg.tree_hash_root())
}

pub fn sign_builder_root(
    chain: Chain,
    secret_key: &BlsSecretKey,
    object_root: B256,
) -> BlsSignature {
    let domain = chain.builder_domain();
    let signing_root = compute_signing_root(object_root, domain);
    sign_message(secret_key, signing_root)
}

pub fn sign_commit_boost_root(
    chain: Chain,
    secret_key: &BlsSecretKey,
    object_root: B256,
) -> BlsSignature {
    let domain = compute_domain(chain, COMMIT_BOOST_DOMAIN);
    let signing_root = compute_signing_root(object_root, domain);
    sign_message(secret_key, signing_root)
}

#[cfg(test)]
mod tests {

    use super::compute_domain;
    use crate::{constants::APPLICATION_BUILDER_DOMAIN, types::Chain};

    #[test]
    fn test_builder_domains() {
        assert_eq!(
            compute_domain(Chain::Mainnet, APPLICATION_BUILDER_DOMAIN),
            Chain::Mainnet.builder_domain()
        );
        assert_eq!(
            compute_domain(Chain::Holesky, APPLICATION_BUILDER_DOMAIN),
            Chain::Holesky.builder_domain()
        );
        assert_eq!(
            compute_domain(Chain::Sepolia, APPLICATION_BUILDER_DOMAIN),
            Chain::Sepolia.builder_domain()
        );
        assert_eq!(
            compute_domain(Chain::Helder, APPLICATION_BUILDER_DOMAIN),
            Chain::Helder.builder_domain()
        );
        assert_eq!(
            compute_domain(Chain::Hoodi, APPLICATION_BUILDER_DOMAIN),
            Chain::Hoodi.builder_domain()
        );
    }
}
