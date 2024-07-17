use alloy::{
    primitives::{hex::FromHex, B256},
    rpc::types::beacon::BlsPublicKey,
};
use serde::{Deserialize, Serialize};
use url::Url;

use super::constants::{
    BULDER_API_PATH, GET_STATUS_PATH, REGISTER_VALIDATOR_PATH, SUBMIT_BLOCK_PATH,
};

#[derive(Debug, Default, Clone)]
pub struct RelayEntry {
    pub id: String,
    pub pubkey: BlsPublicKey,
    pub url: String,
}

impl RelayEntry {
    fn get_url(&self, path: &str) -> String {
        format!("{}{path}", &self.url)
    }

    pub fn get_header_url(
        &self,
        slot: u64,
        parent_hash: B256,
        validator_pubkey: BlsPublicKey,
    ) -> String {
        self.get_url(&format!("{BULDER_API_PATH}/header/{slot}/{parent_hash}/{validator_pubkey}"))
    }

    pub fn get_status_url(&self) -> String {
        self.get_url(&format!("{BULDER_API_PATH}{GET_STATUS_PATH}"))
    }

    pub fn register_validator_url(&self) -> String {
        self.get_url(&format!("{BULDER_API_PATH}{REGISTER_VALIDATOR_PATH}"))
    }

    pub fn submit_block_url(&self) -> String {
        self.get_url(&format!("{BULDER_API_PATH}{SUBMIT_BLOCK_PATH}"))
    }
}

impl Serialize for RelayEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.url)
    }
}

impl<'de> Deserialize<'de> for RelayEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        let url = Url::parse(&str).map_err(serde::de::Error::custom)?;
        let pubkey = BlsPublicKey::from_hex(url.username()).map_err(serde::de::Error::custom)?;
        let id = url.host().ok_or(serde::de::Error::custom("missing host"))?.to_string();

        Ok(RelayEntry { pubkey, url: str, id })
    }
}

#[cfg(test)]
mod tests {
    use alloy::{primitives::hex::FromHex, rpc::types::beacon::BlsPublicKey};

    use super::RelayEntry;

    #[test]
    fn test_relay_entry() {
        let s = "http://0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae@abc.xyz";

        let parsed = serde_json::from_str::<RelayEntry>(&format!("\"{s}\"")).unwrap();

        assert_eq!(parsed.pubkey, BlsPublicKey::from_hex("0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae").unwrap());
        assert_eq!(parsed.url, s);
        assert_eq!(parsed.id, "abc.xyz");
    }
}
