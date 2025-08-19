use std::{
    collections::HashMap,
    fmt::{self, Debug, Display},
    str::FromStr,
};

use alloy::{
    hex,
    primitives::{aliases::B32, Address, B256},
    rpc::types::beacon::BlsSignature,
};
use derive_more::derive::From;
use serde::{Deserialize, Deserializer, Serialize};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    config::decode_string_to_map,
    constants::COMMIT_BOOST_DOMAIN,
    error::BlstErrorWrapper,
    signature::verify_signed_message,
    signer::BlsPublicKey,
    types::{Chain, ModuleId},
};

pub trait ProxyId: AsRef<[u8]> + Debug + Clone + Copy + TreeHash + Display {}

impl ProxyId for Address {}

impl ProxyId for BlsPublicKey {}

// GENERIC PROXY DELEGATION
#[derive(Debug, Clone, Copy, Serialize, Deserialize, TreeHash)]
pub struct ProxyDelegation<T: ProxyId> {
    pub delegator: BlsPublicKey,
    pub proxy: T,
}

pub type ProxyDelegationBls = ProxyDelegation<BlsPublicKey>;
pub type ProxyDelegationEcdsa = ProxyDelegation<Address>;

impl<T: ProxyId> fmt::Display for ProxyDelegation<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Delegator: {}\nProxy: {}", self.delegator, self.proxy)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SignedProxyDelegation<T: ProxyId> {
    pub message: ProxyDelegation<T>,
    /// Signature of message with the delegator keypair
    pub signature: BlsSignature,
}

pub type SignedProxyDelegationBls = SignedProxyDelegation<BlsPublicKey>;
pub type SignedProxyDelegationEcdsa = SignedProxyDelegation<Address>;

impl<T: ProxyId> SignedProxyDelegation<T> {
    pub fn validate(&self, chain: Chain) -> Result<(), BlstErrorWrapper> {
        verify_signed_message(
            chain,
            &self.message.delegator,
            &self.message,
            &self.signature,
            None,
            &B32::from(COMMIT_BOOST_DOMAIN),
        )
    }
}

impl<T: ProxyId> fmt::Display for SignedProxyDelegation<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\nSignature: {}", self.message, self.signature)
    }
}

// TODO(David): This struct shouldn't be visible to module authors
#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignRequest {
    Consensus(SignConsensusRequest),
    ProxyBls(SignProxyRequest<BlsPublicKey>),
    ProxyEcdsa(SignProxyRequest<Address>),
}

impl Display for SignRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignRequest::Consensus(req) => write!(
                f,
                "Consensus(pubkey: {}, object_root: {})",
                req.pubkey,
                hex::encode_prefixed(req.object_root)
            ),
            SignRequest::ProxyBls(req) => write!(
                f,
                "BLS(proxy: {}, object_root: {})",
                req.proxy,
                hex::encode_prefixed(req.object_root)
            ),
            SignRequest::ProxyEcdsa(req) => write!(
                f,
                "ECDSA(proxy: {}, object_root: {})",
                req.proxy,
                hex::encode_prefixed(req.object_root)
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignConsensusRequest {
    pub pubkey: BlsPublicKey,
    pub object_root: B256,
}

impl SignConsensusRequest {
    pub fn new(pubkey: BlsPublicKey, object_root: B256) -> Self {
        Self { pubkey, object_root }
    }

    pub fn builder(pubkey: BlsPublicKey) -> Self {
        Self::new(pubkey, B256::ZERO)
    }

    pub fn with_root<R: Into<B256>>(self, object_root: R) -> Self {
        Self { object_root: object_root.into(), ..self }
    }

    pub fn with_msg(self, msg: &impl TreeHash) -> Self {
        self.with_root(msg.tree_hash_root().0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignProxyRequest<T: ProxyId> {
    pub proxy: T,
    pub object_root: B256,
}

impl<T: ProxyId> SignProxyRequest<T> {
    pub fn new(proxy: T, object_root: B256) -> Self {
        Self { proxy, object_root }
    }

    pub fn builder(proxy: T) -> Self {
        Self::new(proxy, B256::ZERO)
    }

    pub fn with_root<R: Into<B256>>(self, object_root: R) -> Self {
        Self { object_root: object_root.into(), ..self }
    }

    pub fn with_msg(self, msg: &impl TreeHash) -> Self {
        self.with_root(msg.tree_hash_root().0)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EncryptionScheme {
    #[serde(rename = "bls")]
    Bls,
    #[serde(rename = "ecdsa")]
    Ecdsa,
}

impl Display for EncryptionScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionScheme::Bls => write!(f, "bls"),
            EncryptionScheme::Ecdsa => write!(f, "ecdsa"),
        }
    }
}

impl FromStr for EncryptionScheme {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bls" => Ok(EncryptionScheme::Bls),
            "ecdsa" => Ok(EncryptionScheme::Ecdsa),
            _ => Err(format!("Unknown scheme: {s}")),
        }
    }
}

// TODO(David): This struct shouldn't be visible to module authors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateProxyRequest {
    #[serde(rename = "pubkey")]
    pub consensus_pubkey: BlsPublicKey,
    pub scheme: EncryptionScheme,
}

impl GenerateProxyRequest {
    pub fn new(consensus_pubkey: BlsPublicKey, scheme: EncryptionScheme) -> Self {
        GenerateProxyRequest { consensus_pubkey, scheme }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetPubkeysResponse {
    pub keys: Vec<ConsensusProxyMap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadRequest {
    #[serde(default, deserialize_with = "deserialize_jwt_secrets")]
    pub jwt_secrets: Option<HashMap<ModuleId, String>>,
    pub admin_secret: Option<String>,
}

pub fn deserialize_jwt_secrets<'de, D>(
    deserializer: D,
) -> Result<Option<HashMap<ModuleId, String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: String = Deserialize::deserialize(deserializer)?;

    decode_string_to_map(&raw)
        .map(Some)
        .map_err(|_| serde::de::Error::custom("Invalid format".to_string()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeModuleRequest {
    pub module_id: ModuleId,
}

/// Map of consensus pubkeys to proxies
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConsensusProxyMap {
    pub consensus: BlsPublicKey,
    pub proxy_bls: Vec<BlsPublicKey>,
    pub proxy_ecdsa: Vec<Address>,
}

impl ConsensusProxyMap {
    pub fn new(consensus: BlsPublicKey) -> Self {
        Self { consensus, proxy_bls: vec![], proxy_ecdsa: vec![] }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::signer::EcdsaSignature;

    #[test]
    fn test_decode_request_signature() {
        let data = r#"{
            "type": "consensus",
            "pubkey": "0xa3366b54f28e4bf1461926a3c70cdb0ec432b5c92554ecaae3742d33fb33873990cbed1761c68020e6d3c14d30a22050",
            "object_root": "0x5c89913beafa0472168e0ec05e349b4ceb9985d25ab9fa8de53a60208c85b3a5"
        }"#;

        let request: SignRequest = serde_json::from_str(data).unwrap();
        assert!(matches!(request, SignRequest::Consensus(..)));

        let data = r#"{
            "type": "proxy_bls",
            "proxy": "0xa3366b54f28e4bf1461926a3c70cdb0ec432b5c92554ecaae3742d33fb33873990cbed1761c68020e6d3c14d30a22050",
            "object_root": "0x5c89913beafa0472168e0ec05e349b4ceb9985d25ab9fa8de53a60208c85b3a5"
        }"#;

        let request: SignRequest = serde_json::from_str(data).unwrap();
        assert!(matches!(request, SignRequest::ProxyBls(..)));

        let data = r#"{
            "type": "proxy_ecdsa",
            "proxy": "0x4ca9939a8311a7cab3dde201b70157285fa81a9d",
            "object_root": "0x5c89913beafa0472168e0ec05e349b4ceb9985d25ab9fa8de53a60208c85b3a5"
        }"#;

        let request: SignRequest = serde_json::from_str(data).unwrap();
        assert!(matches!(request, SignRequest::ProxyEcdsa(..)));
    }

    #[test]
    fn test_decode_response_signature() {
        let data = r#""0xa3ffa9241f78279f1af04644cb8c79c2d8f02bcf0e28e2f186f6dcccac0a869c2be441fda50f0dea895cfce2e53f0989a3ffa9241f78279f1af04644cb8c79c2d8f02bcf0e28e2f186f6dcccac0a869c2be441fda50f0dea895cfce2e53f0989""#;
        let _: BlsSignature = serde_json::from_str(data).unwrap();

        let data = r#""0x985b495f49d1b96db3bba3f6c5dd1810950317c10d4c2042bd316f338cdbe74359072e209b85e56ac492092d7860063dd096ca31b4e164ef27e3f8d508e656801c""#;
        let _: EcdsaSignature = serde_json::from_str(data).unwrap();
    }

    #[test]
    fn test_decode_request_proxy() {
        let data = r#"{
            "pubkey": "0xa3366b54f28e4bf1461926a3c70cdb0ec432b5c92554ecaae3742d33fb33873990cbed1761c68020e6d3c14d30a22050",
            "scheme": "bls"
        }"#;

        let request: GenerateProxyRequest = serde_json::from_str(data).unwrap();
        assert!(matches!(request, GenerateProxyRequest { scheme: EncryptionScheme::Bls, .. }));

        let data = r#"{
            "pubkey": "0xa3366b54f28e4bf1461926a3c70cdb0ec432b5c92554ecaae3742d33fb33873990cbed1761c68020e6d3c14d30a22050",
            "scheme": "ecdsa"
        }"#;

        let request: GenerateProxyRequest = serde_json::from_str(data).unwrap();
        assert!(matches!(request, GenerateProxyRequest { scheme: EncryptionScheme::Ecdsa, .. }));
    }

    #[test]
    fn test_decode_response_proxy() {
        let data = r#"{
            "message": {
                "delegator": "0xa3366b54f28e4bf1461926a3c70cdb0ec432b5c92554ecaae3742d33fb33873990cbed1761c68020e6d3c14d30a22050",
                "proxy": "0xa3366b54f28e4bf1461926a3c70cdb0ec432b5c92554ecaae3742d33fb33873990cbed1761c68020e6d3c14d30a22050"
            },
            "signature": "0xa3ffa9241f78279f1af04644cb8c79c2d8f02bcf0e28e2f186f6dcccac0a869c2be441fda50f0dea895cfce2e53f0989a3ffa9241f78279f1af04644cb8c79c2d8f02bcf0e28e2f186f6dcccac0a869c2be441fda50f0dea895cfce2e53f0989"
        }"#;

        let _: SignedProxyDelegationBls = serde_json::from_str(data).unwrap();

        let data = r#"{
            "message": {
                "delegator": "0xa3366b54f28e4bf1461926a3c70cdb0ec432b5c92554ecaae3742d33fb33873990cbed1761c68020e6d3c14d30a22050",
                "proxy": "0x4ca9939a8311a7cab3dde201b70157285fa81a9d"
            },
            "signature": "0xa3ffa9241f78279f1af04644cb8c79c2d8f02bcf0e28e2f186f6dcccac0a869c2be441fda50f0dea895cfce2e53f0989a3ffa9241f78279f1af04644cb8c79c2d8f02bcf0e28e2f186f6dcccac0a869c2be441fda50f0dea895cfce2e53f0989"
        }"#;

        let _: SignedProxyDelegationEcdsa = serde_json::from_str(data).unwrap();
    }

    #[test]
    fn test_decode_response_proxy_map() {
        let data = r#"{
            "keys": [
                {
                    "consensus": "0xa3366b54f28e4bf1461926a3c70cdb0ec432b5c92554ecaae3742d33fb33873990cbed1761c68020e6d3c14d30a22050",
                    "proxy_bls": ["0xa3366b54f28e4bf1461926a3c70cdb0ec432b5c92554ecaae3742d33fb33873990cbed1761c68020e6d3c14d30a22050"],
                    "proxy_ecdsa": ["0x4ca9939a8311a7cab3dde201b70157285fa81a9d"]
                }
            ]
        }"#;

        let _: GetPubkeysResponse = serde_json::from_str(data).unwrap();
    }
}
