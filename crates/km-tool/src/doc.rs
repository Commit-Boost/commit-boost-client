//! Wire types for the keymanager builder_config document
//! (keymanager-APIs `types/builder_entry.yaml`): Uint64s are JSON strings,
//! `auth_data` is 0x-prefixed hex, omitted fields are omitted on the wire.

use eyre::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

/// `BuilderConfig` as POSTed to / returned by the keymanager API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BuilderConfigDoc {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_bid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_boost_factor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builders: Option<Vec<BuilderEntryDoc>>,
}

/// `BuilderEntry` as it appears in `BuilderConfigDoc.builders`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuilderEntryDoc {
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

/// Encodes bytes as the KM `auth_data` wire form: 0x-prefixed lowercase hex.
pub fn encode_auth_data(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decodes a 0x-prefixed hex `auth_data`, accepting either hex case.
pub fn decode_auth_data(hex: &str) -> Result<Vec<u8>> {
    let Some(body) = hex.strip_prefix("0x") else {
        bail!("auth_data must be 0x-prefixed: {hex}");
    };
    ensure!(!body.is_empty(), "auth_data must not be empty");
    ensure!(body.len() % 2 == 0, "auth_data has odd hex length: {hex}");
    (0..body.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&body[i..i + 2], 16)
                .map_err(|err| eyre::eyre!("invalid hex in auth_data {hex}: {err}"))
        })
        .collect()
}

/// A `BuilderConfigDoc` reduced to comparable values: hex decoded, Uint64
/// strings parsed, entries sorted by `(url, auth_data bytes)`, pubkeys treated
/// as a case-insensitive set. The spec promises none of entry order, hex case,
/// or pubkey order, so stored docs are compared canonically, never byte-wise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalDoc {
    pub min_bid: Option<u64>,
    pub builder_boost_factor: Option<u64>,
    pub builders: Option<Vec<CanonicalEntry>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanonicalEntry {
    pub url: String,
    pub auth_data: Option<Vec<u8>>,
    pub builder_pubkeys: Vec<String>,
    pub max_execution_payment: Option<u64>,
    pub min_bid: Option<u64>,
    pub builder_boost_factor: Option<u64>,
}

fn parse_uint64(field: &str, value: &Option<String>) -> Result<Option<u64>> {
    match value {
        None => Ok(None),
        Some(s) => {
            let n = s.parse::<u64>().map_err(|err| {
                eyre::eyre!("{field} must be a Uint64 JSON string, got {s:?}: {err}")
            })?;
            Ok(Some(n))
        }
    }
}

impl CanonicalDoc {
    pub fn from_doc(doc: &BuilderConfigDoc) -> Result<Self> {
        let builders = match &doc.builders {
            None => None,
            Some(entries) => {
                let mut out = Vec::with_capacity(entries.len());
                for entry in entries {
                    let auth_data = match &entry.auth_data {
                        None => None,
                        Some(hex) => Some(decode_auth_data(hex)?),
                    };
                    let mut builder_pubkeys: Vec<String> = entry
                        .builder_pubkeys
                        .clone()
                        .unwrap_or_default()
                        .iter()
                        .map(|pk| pk.to_lowercase())
                        .collect();
                    builder_pubkeys.sort();
                    out.push(CanonicalEntry {
                        url: entry.url.clone(),
                        auth_data,
                        builder_pubkeys,
                        max_execution_payment: parse_uint64(
                            "max_execution_payment",
                            &entry.max_execution_payment,
                        )?,
                        min_bid: parse_uint64("min_bid", &entry.min_bid)?,
                        builder_boost_factor: parse_uint64(
                            "builder_boost_factor",
                            &entry.builder_boost_factor,
                        )?,
                    });
                }
                out.sort();
                Some(out)
            }
        };
        Ok(Self {
            min_bid: parse_uint64("min_bid", &doc.min_bid)?,
            builder_boost_factor: parse_uint64("builder_boost_factor", &doc.builder_boost_factor)?,
            builders,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_data_round_trips_lowercase() {
        let bytes = b"https://builder.example.com";
        let hex = encode_auth_data(bytes);
        assert_eq!(hex, "0x68747470733a2f2f6275696c6465722e6578616d706c652e636f6d");
        assert_eq!(decode_auth_data(&hex).unwrap(), bytes);
    }

    #[test]
    fn decode_accepts_uppercase_hex() {
        assert_eq!(decode_auth_data("0xDEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn decode_rejects_bad_forms() {
        assert!(decode_auth_data("deadbeef").is_err());
        assert!(decode_auth_data("0x").is_err());
        assert!(decode_auth_data("0xabc").is_err());
        assert!(decode_auth_data("0xzz").is_err());
    }

    #[test]
    fn empty_doc_serializes_to_empty_object() {
        let doc = BuilderConfigDoc::default();
        assert_eq!(serde_json::to_string(&doc).unwrap(), "{}");
    }

    #[test]
    fn omitted_fields_stay_off_the_wire() {
        let doc = BuilderConfigDoc {
            min_bid: Some("10000000".into()),
            builder_boost_factor: None,
            builders: Some(vec![BuilderEntryDoc {
                url: "https://cb.example.com".into(),
                auth_data: Some("0xaa".into()),
                builder_pubkeys: Some(vec![]),
                max_execution_payment: None,
                min_bid: None,
                builder_boost_factor: None,
            }]),
        };
        let json = serde_json::to_string(&doc).unwrap();
        assert_eq!(
            json,
            r#"{"min_bid":"10000000","builders":[{"url":"https://cb.example.com","auth_data":"0xaa","builder_pubkeys":[]}]}"#
        );
    }

    #[test]
    fn canonical_compare_ignores_order_and_hex_case() {
        let entry = |auth: &str, pks: Vec<&str>| BuilderEntryDoc {
            url: "https://cb.example.com".into(),
            auth_data: Some(auth.into()),
            builder_pubkeys: Some(pks.into_iter().map(String::from).collect()),
            max_execution_payment: None,
            min_bid: Some("5".into()),
            builder_boost_factor: None,
        };
        let a = BuilderConfigDoc {
            min_bid: Some("5".into()),
            builder_boost_factor: None,
            builders: Some(vec![entry("0xaabb", vec!["0xAA", "0xBB"]), entry("0x0102", vec![])]),
        };
        let b = BuilderConfigDoc {
            min_bid: Some("5".into()),
            builder_boost_factor: None,
            builders: Some(vec![entry("0x0102", vec![]), entry("0xAABB", vec!["0xbb", "0xaa"])]),
        };
        assert_eq!(CanonicalDoc::from_doc(&a).unwrap(), CanonicalDoc::from_doc(&b).unwrap());
    }

    #[test]
    fn canonical_compare_distinguishes_values() {
        let a = BuilderConfigDoc { min_bid: Some("5".into()), ..Default::default() };
        let b = BuilderConfigDoc { min_bid: Some("6".into()), ..Default::default() };
        assert_ne!(CanonicalDoc::from_doc(&a).unwrap(), CanonicalDoc::from_doc(&b).unwrap());
    }

    #[test]
    fn canonical_rejects_non_numeric_uint64() {
        let doc = BuilderConfigDoc { min_bid: Some("1e9".into()), ..Default::default() };
        assert!(CanonicalDoc::from_doc(&doc).is_err());
    }

    #[test]
    fn canonical_empty_builders_differs_from_omitted() {
        let empty = BuilderConfigDoc { builders: Some(vec![]), ..Default::default() };
        let omitted = BuilderConfigDoc::default();
        assert_ne!(
            CanonicalDoc::from_doc(&empty).unwrap(),
            CanonicalDoc::from_doc(&omitted).unwrap()
        );
    }
}
