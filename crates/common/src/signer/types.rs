use std::collections::HashMap;

use alloy::primitives::{Address, Bytes};
use base64::{prelude::BASE64_STANDARD, Engine};
use derive_more::derive::Deref;
use serde::{
    de::{Error as DeError, Unexpected},
    Deserialize, Deserializer,
};

use super::{BlsPublicKey, EcdsaSigner};
use crate::{
    commit::request::{SignedProxyDelegationBls, SignedProxyDelegationEcdsa},
    signer::BlsSigner,
};

// For extra safety and to avoid risking signing malicious messages, use a proxy
// setup: proposer creates a new ephemeral keypair which will be used to sign
// commit messages, it also signs a ProxyDelegation associating the new keypair
// with its consensus pubkey When a new commit module starts, pass the
// ProxyDelegation msg and then sign all future commit messages with the proxy
// key for slashing the faulty message + proxy delegation can be used
#[derive(Clone, Deref)]
pub struct BlsProxySigner {
    #[deref]
    pub signer: BlsSigner,
    pub delegation: SignedProxyDelegationBls,
}

#[derive(Clone, Deref)]
pub struct EcdsaProxySigner {
    #[deref]
    pub signer: EcdsaSigner,
    pub delegation: SignedProxyDelegationEcdsa,
}

#[derive(Default, Clone)]
pub struct ProxySigners {
    pub bls_signers: HashMap<BlsPublicKey, BlsProxySigner>,
    pub ecdsa_signers: HashMap<Address, EcdsaProxySigner>,
}

// Prysm keystore actually has a more complex structure, but we only need
// this subset of fields
pub struct PrysmKeystore {
    pub message: Bytes,
    pub salt: Bytes,
    pub c: u32,
    pub iv: Bytes,
}

#[derive(Deserialize, Debug)]
pub struct PrysmDecryptedKeystore {
    #[serde(deserialize_with = "base64_list_decode")]
    pub private_keys: Vec<Bytes>,
    #[serde(deserialize_with = "base64_list_decode")]
    pub public_keys: Vec<Bytes>,
}

fn base64_list_decode<'de, D>(deserializer: D) -> Result<Vec<Bytes>, D::Error>
where
    D: Deserializer<'de>,
{
    let list: Vec<&str> = Deserialize::deserialize(deserializer)?;
    let mut decoded_list = Vec::with_capacity(list.len());

    for encoded_key in list.iter() {
        decoded_list.push(
            BASE64_STANDARD
                .decode(encoded_key)
                .map_err(|_| DeError::invalid_type(Unexpected::Other("unknown"), &"base64 string"))?
                .into(),
        );
    }

    Ok(decoded_list)
}

// impl serde deserialize for PrysmKeystore:
impl<'de> Deserialize<'de> for PrysmKeystore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: serde_json::Value = Deserialize::deserialize(deserializer)?;
        let crypto = value.get("crypto").ok_or(DeError::missing_field("crypto"))?;
        let cipher = crypto.get("cipher").ok_or(DeError::missing_field("crypto.cipher"))?;
        let kdf_params = crypto
            .get("kdf")
            .ok_or(DeError::missing_field("kdf"))?
            .get("params")
            .ok_or(DeError::missing_field("kdf.params"))?;

        Ok(PrysmKeystore {
            message: serde_json::from_value(
                cipher
                    .get("message")
                    .ok_or(DeError::missing_field("crypto.cipher.message"))?
                    .clone(),
            )
            .map_err(|_| DeError::invalid_type(Unexpected::Other("unknown"), &"bytes"))?,
            salt: serde_json::from_value(
                kdf_params
                    .get("salt")
                    .ok_or(DeError::missing_field("crypto.kdf.params.salt"))?
                    .clone(),
            )
            .map_err(|_| DeError::invalid_type(Unexpected::Other("unknown"), &"bytes"))?,
            c: serde_json::from_value(
                kdf_params.get("c").ok_or(DeError::missing_field("crypto.kdf.params.c"))?.clone(),
            )
            .map_err(|_| DeError::invalid_type(Unexpected::Other("unknown"), &"u32"))?,
            iv: serde_json::from_value(
                cipher
                    .get("params")
                    .ok_or(DeError::missing_field("crypto.cipher.params"))?
                    .get("iv")
                    .ok_or(DeError::missing_field("crypto.cipher.params.iv"))?
                    .clone(),
            )
            .map_err(|_| DeError::invalid_type(Unexpected::Other("unknown"), &"bytes"))?,
        })
    }
}
