use std::{ops::Deref, str::FromStr};

use alloy::{
    primitives::{Address, B256, PrimitiveSignature},
    signers::{SignerSync, local::PrivateKeySigner},
};
use eyre::ensure;
use tree_hash::TreeHash;

use crate::{
    constants::COMMIT_BOOST_DOMAIN,
    signature::{compute_domain, compute_signing_root},
    types::Chain,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EcdsaSignature(PrimitiveSignature);

impl std::fmt::Display for EcdsaSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl serde::Serialize for EcdsaSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for EcdsaSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self(PrimitiveSignature::from_str(&s).map_err(serde::de::Error::custom)?))
    }
}

impl From<PrimitiveSignature> for EcdsaSignature {
    fn from(signature: PrimitiveSignature) -> Self {
        Self(signature)
    }
}

impl Deref for EcdsaSignature {
    type Target = PrimitiveSignature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// SIGNER
#[derive(Clone)]
pub enum EcdsaSigner {
    Local(PrivateKeySigner),
}

impl EcdsaSigner {
    pub fn new_random() -> Self {
        Self::Local(PrivateKeySigner::random())
    }

    pub fn new_from_bytes(bytes: &[u8]) -> eyre::Result<Self> {
        let secret = PrivateKeySigner::from_slice(bytes)?;
        Ok(Self::Local(secret))
    }

    pub fn address(&self) -> Address {
        match self {
            EcdsaSigner::Local(secret) => secret.address(),
        }
    }

    pub fn secret(&self) -> Vec<u8> {
        match self {
            EcdsaSigner::Local(secret) => secret.to_bytes().to_vec(),
        }
    }

    pub async fn sign(
        &self,
        chain: Chain,
        object_root: B256,
    ) -> Result<EcdsaSignature, alloy::signers::Error> {
        match self {
            EcdsaSigner::Local(sk) => {
                let domain = compute_domain(chain, COMMIT_BOOST_DOMAIN);
                let signing_root = compute_signing_root(object_root, domain);
                sk.sign_hash_sync(&signing_root).map(EcdsaSignature::from)
            }
        }
    }

    pub async fn sign_msg(
        &self,
        chain: Chain,
        msg: &impl TreeHash,
    ) -> Result<EcdsaSignature, alloy::signers::Error> {
        self.sign(chain, msg.tree_hash_root()).await
    }
}

pub fn verify_ecdsa_signature(
    address: &Address,
    msg: &[u8; 32],
    signature: &EcdsaSignature,
) -> eyre::Result<()> {
    let recovered = signature.recover_address_from_prehash(msg.into())?;
    ensure!(recovered == *address, "invalid signature");
    Ok(())
}

#[cfg(test)]
mod test {

    use alloy::{hex, primitives::bytes};

    use super::*;

    #[tokio::test]
    async fn test_ecdsa_signer() {
        let pk = bytes!("88bcd6672d95bcba0d52a3146494ed4d37675af4ed2206905eb161aa99a6c0d1");
        let signer = EcdsaSigner::new_from_bytes(&pk).unwrap();

        let object_root = B256::from([1; 32]);
        let signature = signer.sign(Chain::Holesky, object_root).await.unwrap();

        let domain = compute_domain(Chain::Holesky, COMMIT_BOOST_DOMAIN);
        let msg = compute_signing_root(object_root, domain);

        assert_eq!(msg, hex!("219ca7a673b2cbbf67bec6c9f60f78bd051336d57b68d1540190f30667e86725"));

        let address = signer.address();
        let verified = verify_ecdsa_signature(&address, &msg, &signature);
        assert!(verified.is_ok());
    }
}
