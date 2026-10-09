//! The document `builder-config print` writes and `apply --from` reads: each
//! mux's builder config once, with its keys, and the `[[relays]]` config for
//! every other key. Every config is a keymanager POST body as is.

use std::collections::{BTreeMap, BTreeSet};

use alloy::primitives::hex;
use cb_common::utils::bls_pubkey_from_hex;
use eyre::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::{doc::BuilderConfig, project::Projection};

pub const VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Printed {
    pub version: u32,
    pub advertised_url: String,
    /// The config of every key in no mux; `null` with no `[[relays]]`, so other
    /// keys are left alone
    pub default: Option<BuilderConfig>,
    pub muxes: BTreeMap<String, PrintedMux>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrintedMux {
    pub config: BuilderConfig,
    /// Keys the Commit-Boost config names
    pub keys: Vec<String>,
    /// Keys only a URL or registry loader lists, which can change after the
    /// print
    pub fetched_keys: Vec<String>,
}

impl Printed {
    pub fn new(projection: &Projection, advertised_url: &str) -> Self {
        let mut muxes: BTreeMap<String, PrintedMux> = BTreeMap::new();
        for (key, id) in &projection.mux_ids {
            let mux = muxes.entry(id.clone()).or_insert_with(|| PrintedMux {
                config: projection.mux_docs[key].clone(),
                keys: vec![],
                fetched_keys: vec![],
            });
            if projection.fetched_keys.contains(key) {
                mux.fetched_keys.push(key.clone());
            } else {
                mux.keys.push(key.clone());
            }
        }
        Self {
            version: VERSION,
            advertised_url: advertised_url.to_string(),
            default: projection.relays_doc.clone(),
            muxes,
        }
    }

    /// Reads a document as `print` writes it. A field `print` does not write,
    /// such as a misspelled cap, would be dropped from each POST and the
    /// client's default applied
    pub fn parse(text: &str) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(text)?;
        let printed: Self = serde_json::from_value(value.clone())?;
        ensure!(
            serde_json::to_value(&printed)? == value,
            "it holds a field `print` does not write"
        );
        Ok(printed)
    }

    /// The projection `apply` writes, once the document is checked against the
    /// advertised URL apply was given
    pub fn into_projection(self, advertised_url: &str) -> Result<Projection> {
        ensure!(
            self.version == VERSION,
            "the printed document is version {}, and this commit-boost reads version {VERSION}",
            self.version
        );
        // Each entry's url is written as is, so it must be the one checked
        ensure!(
            self.advertised_url == advertised_url,
            "the printed document is for {}, not --advertised-url {advertised_url}",
            self.advertised_url
        );
        for (name, config) in self
            .muxes
            .iter()
            .map(|(id, mux)| (id.as_str(), &mux.config))
            .chain(self.default.as_ref().map(|config| ("default", config)))
        {
            for entry in config.builders.iter().flatten() {
                ensure!(
                    entry.url == advertised_url,
                    "{name}'s config has an entry at {}, not {advertised_url}",
                    entry.url
                );
                if let Some(auth_data) = &entry.auth_data {
                    ensure!(
                        auth_data.starts_with("0x") && hex::decode(auth_data).is_ok(),
                        "{name}'s config has auth_data {auth_data}, not 0x-prefixed hex"
                    );
                }
            }
        }

        let mut projection = Projection {
            mux_docs: BTreeMap::new(),
            fetched_keys: BTreeSet::new(),
            relays_doc: self.default,
            mux_ids: BTreeMap::new(),
        };
        for (id, mux) in self.muxes {
            let keys = mux.keys.iter().map(|key| (key, false));
            for (key, fetched) in keys.chain(mux.fetched_keys.iter().map(|key| (key, true))) {
                let key = bls_pubkey_from_hex(key)
                    .map_err(|err| eyre::eyre!("mux {id}: {key} is not a validator key: {err}"))?
                    .as_hex_string();
                if let Some(other) = projection.mux_ids.insert(key.clone(), id.clone()) {
                    bail!("{key} is in both mux {other} and mux {id}");
                }
                if fetched {
                    projection.fetched_keys.insert(key.clone());
                }
                projection.mux_docs.insert(key, mux.config.clone());
            }
        }
        Ok(projection)
    }
}
