//! The keymanager builder config document (keymanager-APIs
//! `types/builder_entry.yaml`): Uint64s are JSON strings and `auth_data` is
//! 0x-prefixed hex.

use serde::{Deserialize, Serialize};

/// The most entries a key's builder config can hold
pub const MAX_BUILDER_ENTRIES: usize = 64;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuilderConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_bid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_boost_factor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builders: Option<Vec<BuilderEntry>>,
}

impl BuilderConfig {
    /// Whether any entry has a cap above 0, which Lodestar refuses without a
    /// flag
    pub fn has_nonzero_cap(&self) -> bool {
        self.builders
            .iter()
            .flatten()
            .any(|entry| entry.max_execution_payment.as_deref() != Some("0"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuilderEntry {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_pubkeys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_execution_payment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_bid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_boost_factor: Option<String>,
}
