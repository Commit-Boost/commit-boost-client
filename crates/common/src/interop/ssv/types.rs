use serde::{Deserialize, Deserializer, Serialize};

use crate::types::BlsPublicKey;

/// Response from the SSV API for validators
#[derive(Deserialize, Serialize)]
pub struct SSVResponse {
    /// List of validators returned by the SSV API
    pub validators: Vec<SSVValidator>,

    /// Pagination information
    pub pagination: SSVPagination,
}

/// Representation of a validator in the SSV API
#[derive(Clone)]
pub struct SSVValidator {
    /// The public key of the validator
    pub pubkey: BlsPublicKey,
}

impl<'de> Deserialize<'de> for SSVValidator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SSVValidator {
            public_key: String,
        }

        let s = SSVValidator::deserialize(deserializer)?;
        let bytes = alloy::hex::decode(&s.public_key).map_err(serde::de::Error::custom)?;
        let pubkey = BlsPublicKey::deserialize(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("invalid BLS public key: {e:?}")))?;

        Ok(Self { pubkey })
    }
}

impl Serialize for SSVValidator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct SSVValidator {
            public_key: String,
        }

        let s = SSVValidator { public_key: self.pubkey.as_hex_string() };
        s.serialize(serializer)
    }
}

/// Pagination information from the SSV API
#[derive(Deserialize, Serialize)]
pub struct SSVPagination {
    /// Total number of validators available
    pub total: usize,
}
