use std::path::PathBuf;

use alloy::primitives::{hex, Bytes};
use derive_more::{Deref, Display, From, Into};
use eyre::{bail, Context};
use serde::{Deserialize, Serialize};

use crate::{constants::APPLICATION_BUILDER_DOMAIN, signature::compute_domain};

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
    Sepolia,
    Helder,
    Custom { genesis_time_secs: u64, slot_time_secs: u64, genesis_fork_version: ForkVersion },
}

pub type ForkVersion = [u8; 4];

impl std::fmt::Debug for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "Mainnet"),
            Self::Holesky => write!(f, "Holesky"),
            Self::Sepolia => write!(f, "Sepolia"),
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
            Chain::Mainnet => KnownChain::Mainnet.builder_domain(),
            Chain::Holesky => KnownChain::Holesky.builder_domain(),
            Chain::Sepolia => KnownChain::Sepolia.builder_domain(),
            Chain::Helder => KnownChain::Helder.builder_domain(),
            Chain::Custom { .. } => compute_domain(*self, APPLICATION_BUILDER_DOMAIN),
        }
    }

    pub fn genesis_fork_version(&self) -> ForkVersion {
        match self {
            Chain::Mainnet => KnownChain::Mainnet.genesis_fork_version(),
            Chain::Holesky => KnownChain::Holesky.genesis_fork_version(),
            Chain::Sepolia => KnownChain::Sepolia.genesis_fork_version(),
            Chain::Helder => KnownChain::Helder.genesis_fork_version(),
            Chain::Custom { genesis_fork_version, .. } => *genesis_fork_version,
        }
    }

    pub fn genesis_time_sec(&self) -> u64 {
        match self {
            Chain::Mainnet => KnownChain::Mainnet.genesis_time_sec(),
            Chain::Holesky => KnownChain::Holesky.genesis_time_sec(),
            Chain::Sepolia => KnownChain::Sepolia.genesis_time_sec(),
            Chain::Helder => KnownChain::Helder.genesis_time_sec(),
            Chain::Custom { genesis_time_secs, .. } => *genesis_time_secs,
        }
    }

    pub fn slot_time_sec(&self) -> u64 {
        match self {
            Chain::Mainnet => KnownChain::Mainnet.slot_time_sec(),
            Chain::Holesky => KnownChain::Holesky.slot_time_sec(),
            Chain::Sepolia => KnownChain::Sepolia.slot_time_sec(),
            Chain::Helder => KnownChain::Helder.slot_time_sec(),
            Chain::Custom { slot_time_secs, .. } => *slot_time_secs,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum KnownChain {
    #[serde(alias = "mainnet")]
    Mainnet,
    #[serde(alias = "holesky")]
    Holesky,
    #[serde(alias = "sepolia")]
    Sepolia,
    #[serde(alias = "helder")]
    Helder,
}

// Constants
impl KnownChain {
    pub fn builder_domain(&self) -> [u8; 32] {
        match self {
            KnownChain::Mainnet => [
                0, 0, 0, 1, 245, 165, 253, 66, 209, 106, 32, 48, 39, 152, 239, 110, 211, 9, 151,
                155, 67, 0, 61, 35, 32, 217, 240, 232, 234, 152, 49, 169,
            ],
            KnownChain::Holesky => [
                0, 0, 0, 1, 91, 131, 162, 55, 89, 197, 96, 178, 208, 198, 69, 118, 225, 220, 252,
                52, 234, 148, 196, 152, 143, 62, 13, 159, 119, 240, 83, 135,
            ],
            KnownChain::Sepolia => [
                0, 0, 0, 1, 211, 1, 7, 120, 205, 8, 238, 81, 75, 8, 254, 103, 182, 197, 3, 181, 16,
                152, 122, 76, 228, 63, 66, 48, 109, 151, 198, 124,
            ],
            KnownChain::Helder => [
                0, 0, 0, 1, 148, 196, 26, 244, 132, 255, 247, 150, 73, 105, 224, 189, 217, 34, 248,
                45, 255, 15, 75, 232, 122, 96, 208, 102, 76, 201, 209, 255,
            ],
        }
    }

    pub fn genesis_fork_version(&self) -> ForkVersion {
        match self {
            KnownChain::Mainnet => hex!("00000000"),
            KnownChain::Holesky => hex!("01017000"),
            KnownChain::Sepolia => hex!("90000069"),
            KnownChain::Helder => hex!("10000000"),
        }
    }

    fn genesis_time_sec(&self) -> u64 {
        match self {
            KnownChain::Mainnet => 1606824023,
            KnownChain::Holesky => 1695902400,
            KnownChain::Sepolia => 1655733600,
            KnownChain::Helder => 1718967660,
        }
    }

    pub fn slot_time_sec(&self) -> u64 {
        match self {
            KnownChain::Mainnet |
            KnownChain::Holesky |
            KnownChain::Sepolia |
            KnownChain::Helder => 12,
        }
    }
}

impl From<KnownChain> for Chain {
    fn from(value: KnownChain) -> Self {
        match value {
            KnownChain::Mainnet => Chain::Mainnet,
            KnownChain::Holesky => Chain::Holesky,
            KnownChain::Sepolia => Chain::Sepolia,
            KnownChain::Helder => Chain::Helder,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ChainLoader {
    Known(KnownChain),
    Path {
        /// Genesis time as returned in /eth/v1/beacon/genesis
        genesis_time_secs: u64,
        /// Path to the genesis spec, as returned by /eth/v1/config/spec
        /// either in JSON or YAML format
        path: PathBuf,
    },
    Custom {
        /// Genesis time as returned in /eth/v1/beacon/genesis
        genesis_time_secs: u64,
        slot_time_secs: u64,
        genesis_fork_version: Bytes,
    },
}

impl Serialize for Chain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let loader = match self {
            Chain::Mainnet => ChainLoader::Known(KnownChain::Mainnet),
            Chain::Holesky => ChainLoader::Known(KnownChain::Holesky),
            Chain::Sepolia => ChainLoader::Known(KnownChain::Sepolia),
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
            ChainLoader::Path { genesis_time_secs, path } => {
                let (slot_time_secs, genesis_fork_version) =
                    load_chain_from_file(path).map_err(serde::de::Error::custom)?;
                Ok(Chain::Custom { genesis_time_secs, slot_time_secs, genesis_fork_version })
            }
            ChainLoader::Custom { genesis_time_secs, slot_time_secs, genesis_fork_version } => {
                let genesis_fork_version: ForkVersion =
                    genesis_fork_version.as_ref().try_into().map_err(serde::de::Error::custom)?;
                Ok(Chain::Custom { genesis_time_secs, slot_time_secs, genesis_fork_version })
            }
        }
    }
}

/// Returns seconds_per_slot and genesis_fork_version from a spec, such as
/// returned by /eth/v1/config/spec ref: https://ethereum.github.io/beacon-APIs/#/Config/getSpec
/// Try to load two formats:
/// - JSON as return the getSpec endpoint, either with or without the `data`
///   field
/// - YAML as used e.g. in Kurtosis/Ethereum Package
pub fn load_chain_from_file(path: PathBuf) -> eyre::Result<(u64, ForkVersion)> {
    #[derive(Deserialize)]
    #[serde(rename_all = "UPPERCASE")]
    struct QuotedSpecFile {
        #[serde(with = "serde_utils::quoted_u64")]
        seconds_per_slot: u64,
        genesis_fork_version: Bytes,
    }

    impl QuotedSpecFile {
        fn to_chain(&self) -> eyre::Result<(u64, ForkVersion)> {
            let genesis_fork_version: ForkVersion =
                self.genesis_fork_version.as_ref().try_into()?;
            Ok((self.seconds_per_slot, genesis_fork_version))
        }
    }

    #[derive(Deserialize)]
    struct SpecFileJson {
        data: QuotedSpecFile,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "UPPERCASE")]
    struct SpecFile {
        seconds_per_slot: u64,
        genesis_fork_version: u32,
    }

    impl SpecFile {
        fn to_chain(&self) -> (u64, ForkVersion) {
            let genesis_fork_version: ForkVersion = self.genesis_fork_version.to_be_bytes();
            (self.seconds_per_slot, genesis_fork_version)
        }
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
    fn test_spec_mainnet_data_json() {
        let a = env!("CARGO_MANIFEST_DIR");
        let mut path = PathBuf::from(a);

        path.pop();
        path.pop();
        path.push("tests/data/mainnet_spec_data.json");

        let s = format!("chain = {{ genesis_time_secs = 1, path = {path:?}}}");

        let decoded: MockConfig = toml::from_str(&s).unwrap();

        assert_eq!(decoded.chain.genesis_time_sec(), 1);
        assert_eq!(decoded.chain.slot_time_sec(), KnownChain::Mainnet.slot_time_sec());
        assert_eq!(
            decoded.chain.genesis_fork_version(),
            KnownChain::Mainnet.genesis_fork_version()
        );
    }

    #[test]
    fn test_spec_holesky_json() {
        let a = env!("CARGO_MANIFEST_DIR");
        let mut path = PathBuf::from(a);

        path.pop();
        path.pop();
        path.push("tests/data/holesky_spec.json");

        let s = format!("chain = {{ genesis_time_secs = 1, path = {path:?}}}");

        let decoded: MockConfig = toml::from_str(&s).unwrap();
        assert_eq!(decoded.chain, Chain::Custom {
            genesis_time_secs: 1,
            slot_time_secs: KnownChain::Holesky.slot_time_sec(),
            genesis_fork_version: KnownChain::Holesky.genesis_fork_version()
        })
    }

    #[test]
    fn test_spec_sepolia_data_json() {
        let a = env!("CARGO_MANIFEST_DIR");
        let mut path = PathBuf::from(a);

        path.pop();
        path.pop();
        path.push("tests/data/sepolia_spec_data.json");

        let s = format!("chain = {{ genesis_time_secs = 1, path = {path:?}}}");

        let decoded: MockConfig = toml::from_str(&s).unwrap();
        assert_eq!(decoded.chain, Chain::Custom {
            genesis_time_secs: 1,
            slot_time_secs: KnownChain::Sepolia.slot_time_sec(),
            genesis_fork_version: KnownChain::Sepolia.genesis_fork_version()
        })
    }

    #[test]
    fn test_spec_helder_yml() {
        let a = env!("CARGO_MANIFEST_DIR");
        let mut path = PathBuf::from(a);

        path.pop();
        path.pop();
        path.push("tests/data/helder_spec.yml");

        let s = format!("chain = {{ genesis_time_secs = 1, path = {path:?}}}");

        let decoded: MockConfig = toml::from_str(&s).unwrap();
        assert_eq!(decoded.chain, Chain::Custom {
            genesis_time_secs: 1,
            slot_time_secs: KnownChain::Helder.slot_time_sec(),
            genesis_fork_version: KnownChain::Helder.genesis_fork_version()
        })
    }
}
