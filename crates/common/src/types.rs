use std::path::PathBuf;

use alloy::primitives::{hex, Bytes};
use derive_more::{Deref, Display, From, Into};
use eyre::{bail, Context};
use serde::{Deserialize, Serialize};

use crate::{
    constants::{
        APPLICATION_BUILDER_DOMAIN, DEFAULT_SECONDS_PER_SLOT, HELDER_BUILDER_DOMAIN,
        HELDER_GENESIS_FORK_VERSION, HELDER_GENESIS_TIME_SECONDS, HOLESKY_BUILDER_DOMAIN,
        HOLESKY_GENESIS_FORK_VERSION, HOLESKY_GENESIS_TIME_SECONDS, MAINNET_BUILDER_DOMAIN,
        MAINNET_GENESIS_FORK_VERSION, MAINNET_GENESIS_TIME_SECONDS,
    },
    signature::compute_domain,
};

#[derive(Clone, Debug, Display, PartialEq, Eq, Hash, Deref, From, Into, Serialize, Deserialize)]
#[into(owned, ref, ref_mut)]
#[serde(transparent)]
pub struct ModuleId(pub String);

#[derive(Clone, Debug, Display, PartialEq, Eq, Hash, Deref, From, Into, Serialize, Deserialize)]
#[into(owned, ref, ref_mut)]
#[serde(transparent)]
pub struct Jwt(pub String);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Mainnet,
    Holesky,
    Helder,
    Custom { genesis_time_secs: u64, slot_time_secs: u64, genesis_fork_version: [u8; 4] },
}

impl std::fmt::Debug for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "Mainnet"),
            Self::Holesky => write!(f, "Holesky"),
            Self::Helder => write!(f, "Helder"),
            Self::Custom { genesis_time_secs, slot_time_secs, genesis_fork_version } => f
                .debug_struct("Custom")
                .field("genesis_time_secs", genesis_time_secs)
                .field("slot_time_secs", slot_time_secs)
                .field("genesis_fork_version", &hex::encode_prefixed(genesis_fork_version))
                .finish(),
        }
    }
}

impl Chain {
    pub fn builder_domain(&self) -> [u8; 32] {
        match self {
            Chain::Mainnet => MAINNET_BUILDER_DOMAIN,
            Chain::Holesky => HOLESKY_BUILDER_DOMAIN,
            Chain::Helder => HELDER_BUILDER_DOMAIN,
            Chain::Custom { .. } => compute_domain(*self, APPLICATION_BUILDER_DOMAIN),
        }
    }

    pub fn genesis_fork_version(&self) -> [u8; 4] {
        match self {
            Chain::Mainnet => MAINNET_GENESIS_FORK_VERSION,
            Chain::Holesky => HOLESKY_GENESIS_FORK_VERSION,
            Chain::Helder => HELDER_GENESIS_FORK_VERSION,
            Chain::Custom { genesis_fork_version, .. } => *genesis_fork_version,
        }
    }

    pub fn genesis_time_sec(&self) -> u64 {
        match self {
            Chain::Mainnet => MAINNET_GENESIS_TIME_SECONDS,
            Chain::Holesky => HOLESKY_GENESIS_TIME_SECONDS,
            Chain::Helder => HELDER_GENESIS_TIME_SECONDS,
            Chain::Custom { genesis_time_secs, .. } => *genesis_time_secs,
        }
    }

    pub fn slot_time_sec(&self) -> u64 {
        match self {
            Chain::Mainnet | Chain::Holesky | Chain::Helder => DEFAULT_SECONDS_PER_SLOT,
            Chain::Custom { slot_time_secs, .. } => *slot_time_secs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum ChainLoader {
    Known(KnownChain),
    Path(PathBuf),
    Custom { genesis_time_secs: u64, slot_time_secs: u64, genesis_fork_version: Bytes },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum KnownChain {
    #[serde(alias = "mainnet")]
    Mainnet,
    #[serde(alias = "holesky")]
    Holesky,
    #[serde(alias = "helder")]
    Helder,
}

impl From<KnownChain> for Chain {
    fn from(value: KnownChain) -> Self {
        match value {
            KnownChain::Mainnet => Chain::Mainnet,
            KnownChain::Holesky => Chain::Holesky,
            KnownChain::Helder => Chain::Helder,
        }
    }
}

impl Serialize for Chain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let loader = match self {
            Chain::Mainnet => ChainLoader::Known(KnownChain::Mainnet),
            Chain::Holesky => ChainLoader::Known(KnownChain::Holesky),
            Chain::Helder => ChainLoader::Known(KnownChain::Helder),
            Chain::Custom { genesis_time_secs, slot_time_secs, genesis_fork_version } => {
                ChainLoader::Custom {
                    genesis_time_secs: *genesis_time_secs,
                    slot_time_secs: *slot_time_secs,
                    genesis_fork_version: Bytes::from(*genesis_fork_version),
                }
            }
        };

        loader.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Chain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let loader = ChainLoader::deserialize(deserializer)?;

        match loader {
            ChainLoader::Known(known) => Ok(Chain::from(known)),
            ChainLoader::Path(path) => load_chain_from_file(path).map_err(serde::de::Error::custom),
            ChainLoader::Custom { genesis_time_secs, slot_time_secs, genesis_fork_version } => {
                let genesis_fork_version: [u8; 4] =
                    genesis_fork_version.as_ref().try_into().map_err(serde::de::Error::custom)?;
                Ok(Chain::Custom { genesis_time_secs, slot_time_secs, genesis_fork_version })
            }
        }
    }
}

/// Load a chain config from a spec file, such as returned by
/// /eth/v1/config/spec ref: https://ethereum.github.io/beacon-APIs/#/Config/getSpec
pub fn load_chain_from_file(path: PathBuf) -> eyre::Result<Chain> {
    #[derive(Deserialize)]
    #[serde(rename_all = "UPPERCASE")]
    struct QuotedSpecFile {
        #[serde(with = "serde_utils::quoted_u64")]
        min_genesis_time: u64,
        #[serde(with = "serde_utils::quoted_u64")]
        genesis_delay: u64,
        #[serde(with = "serde_utils::quoted_u64")]
        seconds_per_slot: u64,
        genesis_fork_version: Bytes,
    }

    impl QuotedSpecFile {
        fn to_chain(&self) -> eyre::Result<Chain> {
            let genesis_fork_version: [u8; 4] = self.genesis_fork_version.as_ref().try_into()?;

            Ok(Chain::Custom {
                genesis_time_secs: self.min_genesis_time + self.genesis_delay,
                slot_time_secs: self.seconds_per_slot,
                genesis_fork_version,
            })
        }
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "UPPERCASE")]
    struct SpecFile {
        min_genesis_time: u64,
        genesis_delay: u64,
        seconds_per_slot: u64,
        genesis_fork_version: u32,
    }

    impl SpecFile {
        fn to_chain(&self) -> Chain {
            let genesis_fork_version: [u8; 4] = self.genesis_fork_version.to_be_bytes();

            Chain::Custom {
                genesis_time_secs: self.min_genesis_time + self.genesis_delay,
                slot_time_secs: self.seconds_per_slot,
                genesis_fork_version,
            }
        }
    }

    #[derive(Deserialize)]
    struct SpecFileJson {
        data: QuotedSpecFile,
    }

    let file =
        std::fs::read(&path).wrap_err(format!("Unable to find chain spec file: {path:?}"))?;

    if let Ok(decoded) = serde_json::from_slice::<SpecFileJson>(&file) {
        decoded.data.to_chain()
    } else if let Ok(decoded) = serde_json::from_slice::<QuotedSpecFile>(&file) {
        decoded.to_chain()
    } else if let Ok(decoded) = serde_yaml::from_slice::<SpecFile>(&file) {
        Ok(decoded.to_chain())
    } else {
        bail!("unable to decode file: {path:?}, accepted formats are: json or yml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    struct MockConfig {
        chain: Chain,
    }

    #[test]
    fn test_load_known() {
        let s = r#"chain = "Mainnet""#;
        let decoded: MockConfig = toml::from_str(s).unwrap();
        assert_eq!(decoded.chain, Chain::Mainnet);
    }

    #[test]
    fn test_load_custom() {
        let s = r#"chain = { genesis_time_secs = 1, slot_time_secs = 2, genesis_fork_version = "0x01000000" }"#;
        let decoded: MockConfig = toml::from_str(s).unwrap();
        assert_eq!(decoded.chain, Chain::Custom {
            genesis_time_secs: 1,
            slot_time_secs: 2,
            genesis_fork_version: [1, 0, 0, 0]
        })
    }

    #[test]
    fn test_load_file_data_json() {
        let a = env!("CARGO_MANIFEST_DIR");
        let mut path = PathBuf::from(a);

        path.pop();
        path.pop();
        path.push("tests/data/holesky_spec_data.json");

        let s = format!(r#"chain = {path:?}"#);

        let decoded: MockConfig = toml::from_str(&s).unwrap();
        assert_eq!(decoded.chain, Chain::Custom {
            genesis_time_secs: HOLESKY_GENESIS_TIME_SECONDS,
            slot_time_secs: DEFAULT_SECONDS_PER_SLOT,
            genesis_fork_version: HOLESKY_GENESIS_FORK_VERSION
        })
    }

    #[test]
    fn test_load_file_json() {
        let a = env!("CARGO_MANIFEST_DIR");
        let mut path = PathBuf::from(a);

        path.pop();
        path.pop();
        path.push("tests/data/holesky_spec.json");

        let s = format!("chain = {path:?}");

        let decoded: MockConfig = toml::from_str(&s).unwrap();
        assert_eq!(decoded.chain, Chain::Custom {
            genesis_time_secs: HOLESKY_GENESIS_TIME_SECONDS,
            slot_time_secs: DEFAULT_SECONDS_PER_SLOT,
            genesis_fork_version: HOLESKY_GENESIS_FORK_VERSION
        })
    }

    #[test]
    fn test_load_file_yml() {
        let a = env!("CARGO_MANIFEST_DIR");
        let mut path = PathBuf::from(a);

        path.pop();
        path.pop();
        path.push("tests/data/helder_spec.yml");

        let s = format!("chain = {path:?}");

        let decoded: MockConfig = toml::from_str(&s).unwrap();
        assert_eq!(decoded.chain, Chain::Custom {
            genesis_time_secs: HELDER_GENESIS_TIME_SECONDS,
            slot_time_secs: DEFAULT_SECONDS_PER_SLOT,
            genesis_fork_version: HELDER_GENESIS_FORK_VERSION
        })
    }
}
