use std::path::PathBuf;

use alloy::primitives::{B256, Bytes, b256, hex};
use derive_more::{Deref, Display, From, Into};
use eyre::{Context, bail};
use lh_types::ForkName;
use serde::{Deserialize, Serialize};

use crate::{constants::APPLICATION_BUILDER_DOMAIN, signature::compute_domain};

pub type BlsPublicKeyBytes = lh_types::PublicKeyBytes;
pub type BlsPublicKey = lh_types::PublicKey;
pub type BlsSignature = lh_types::Signature;
pub type BlsSecretKey = lh_types::SecretKey;

#[derive(Clone, Debug, Display, PartialEq, Eq, Hash, Deref, From, Into, Serialize, Deserialize)]
#[into(owned, ref, ref_mut)]
#[serde(transparent)]
pub struct ModuleId(pub String);

#[derive(Clone, Debug, Display, PartialEq, Eq, Hash, Deref, From, Into, Serialize, Deserialize)]
#[into(owned, ref, ref_mut)]
#[serde(transparent)]
pub struct Jwt(pub String);

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub exp: u64,
    pub module: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chain {
    Mainnet,
    Holesky,
    Sepolia,
    Hoodi,
    Custom {
        genesis_time_secs: u64,
        slot_time_secs: u64,
        genesis_fork_version: ForkVersion,
        fulu_fork_slot: u64,
        chain_id: u64,
    },
}

pub enum MainnetLidoModule {
    Curated = 1,
    SimpleDVT = 2,
    CommunityStaking = 3,
}

pub enum HoleskyLidoModule {
    Curated = 1,
    SimpleDVT = 2,
    Sandbox = 3,
    CommunityStaking = 4,
}

pub enum HoodiLidoModule {
    Curated = 1,
    SimpleDVT = 2,
    Sandbox = 3,
    CommunityStaking = 4,
}

pub type ForkVersion = [u8; 4];

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mainnet | Self::Holesky | Self::Sepolia | Self::Hoodi => {
                write!(f, "{self:?}")
            }
            Self::Custom { .. } => write!(f, "Custom"),
        }
    }
}

impl std::fmt::Debug for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "Mainnet"),
            Self::Holesky => write!(f, "Holesky"),
            Self::Sepolia => write!(f, "Sepolia"),
            Self::Hoodi => write!(f, "Hoodi"),
            Self::Custom {
                genesis_time_secs,
                slot_time_secs,
                genesis_fork_version,
                fulu_fork_slot,
                chain_id,
            } => f
                .debug_struct("Custom")
                .field("genesis_time_secs", genesis_time_secs)
                .field("slot_time_secs", slot_time_secs)
                .field("genesis_fork_version", &hex::encode_prefixed(genesis_fork_version))
                .field("fulu_fork_slot", fulu_fork_slot)
                .field("chain_id", chain_id)
                .finish(),
        }
    }
}

impl Chain {
    pub fn id(&self) -> u64 {
        match self {
            Chain::Mainnet => KnownChain::Mainnet.id(),
            Chain::Holesky => KnownChain::Holesky.id(),
            Chain::Sepolia => KnownChain::Sepolia.id(),
            Chain::Hoodi => KnownChain::Hoodi.id(),
            Chain::Custom { chain_id, .. } => *chain_id,
        }
    }

    pub fn builder_domain(&self) -> B256 {
        match self {
            Chain::Mainnet => KnownChain::Mainnet.builder_domain(),
            Chain::Holesky => KnownChain::Holesky.builder_domain(),
            Chain::Sepolia => KnownChain::Sepolia.builder_domain(),
            Chain::Hoodi => KnownChain::Hoodi.builder_domain(),
            Chain::Custom { .. } => compute_domain(*self, APPLICATION_BUILDER_DOMAIN),
        }
    }

    pub fn genesis_fork_version(&self) -> ForkVersion {
        match self {
            Chain::Mainnet => KnownChain::Mainnet.genesis_fork_version(),
            Chain::Holesky => KnownChain::Holesky.genesis_fork_version(),
            Chain::Sepolia => KnownChain::Sepolia.genesis_fork_version(),
            Chain::Hoodi => KnownChain::Hoodi.genesis_fork_version(),
            Chain::Custom { genesis_fork_version, .. } => *genesis_fork_version,
        }
    }

    pub fn genesis_time_sec(&self) -> u64 {
        match self {
            Chain::Mainnet => KnownChain::Mainnet.genesis_time_sec(),
            Chain::Holesky => KnownChain::Holesky.genesis_time_sec(),
            Chain::Sepolia => KnownChain::Sepolia.genesis_time_sec(),
            Chain::Hoodi => KnownChain::Hoodi.genesis_time_sec(),
            Chain::Custom { genesis_time_secs, .. } => *genesis_time_secs,
        }
    }

    pub fn slot_time_sec(&self) -> u64 {
        match self {
            Chain::Mainnet => KnownChain::Mainnet.slot_time_sec(),
            Chain::Holesky => KnownChain::Holesky.slot_time_sec(),
            Chain::Sepolia => KnownChain::Sepolia.slot_time_sec(),
            Chain::Hoodi => KnownChain::Hoodi.slot_time_sec(),
            Chain::Custom { slot_time_secs, .. } => *slot_time_secs,
        }
    }

    pub fn fulu_fork_slot(&self) -> u64 {
        match self {
            Chain::Mainnet => KnownChain::Mainnet.fulu_fork_slot(),
            Chain::Holesky => KnownChain::Holesky.fulu_fork_slot(),
            Chain::Sepolia => KnownChain::Sepolia.fulu_fork_slot(),
            Chain::Hoodi => KnownChain::Hoodi.fulu_fork_slot(),
            Chain::Custom { slot_time_secs, .. } => *slot_time_secs,
        }
    }

    pub fn fork_by_slot(&self, slot: u64) -> ForkName {
        if slot >= self.fulu_fork_slot() { ForkName::Fulu } else { ForkName::Electra }
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
    #[serde(alias = "hoodi")]
    Hoodi,
}

// Constants
impl KnownChain {
    pub fn id(&self) -> u64 {
        match self {
            KnownChain::Mainnet => 1,
            KnownChain::Holesky => 17000,
            KnownChain::Sepolia => 11155111,
            KnownChain::Hoodi => 560048,
        }
    }

    pub fn builder_domain(&self) -> B256 {
        match self {
            KnownChain::Mainnet => {
                b256!("0x00000001f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9")
            }
            KnownChain::Holesky => {
                b256!("0x000000015b83a23759c560b2d0c64576e1dcfc34ea94c4988f3e0d9f77f05387")
            }
            KnownChain::Sepolia => {
                b256!("0x00000001d3010778cd08ee514b08fe67b6c503b510987a4ce43f42306d97c67c")
            }
            KnownChain::Hoodi => {
                b256!("0x00000001719103511efa4f1362ff2a50996cccf329cc84cb410c5e5c7d351d03")
            }
        }
    }

    pub fn genesis_fork_version(&self) -> ForkVersion {
        match self {
            KnownChain::Mainnet => hex!("00000000"),
            KnownChain::Holesky => hex!("01017000"),
            KnownChain::Sepolia => hex!("90000069"),
            KnownChain::Hoodi => hex!("10000910"),
        }
    }

    fn genesis_time_sec(&self) -> u64 {
        match self {
            KnownChain::Mainnet => 1606824023,
            KnownChain::Holesky => 1695902400,
            KnownChain::Sepolia => 1655733600,
            KnownChain::Hoodi => 1742213400,
        }
    }

    pub fn slot_time_sec(&self) -> u64 {
        match self {
            KnownChain::Mainnet |
            KnownChain::Holesky |
            KnownChain::Sepolia |
            KnownChain::Hoodi => 12,
        }
    }

    pub fn fulu_fork_slot(&self) -> u64 {
        match self {
            KnownChain::Mainnet => 13164544,
            KnownChain::Holesky => 5283840,
            KnownChain::Sepolia => 8724480,
            KnownChain::Hoodi => 1622016,
        }
    }
}

impl From<KnownChain> for Chain {
    fn from(value: KnownChain) -> Self {
        match value {
            KnownChain::Mainnet => Chain::Mainnet,
            KnownChain::Holesky => Chain::Holesky,
            KnownChain::Sepolia => Chain::Sepolia,
            KnownChain::Hoodi => Chain::Hoodi,
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
        fulu_fork_slot: u64,
        chain_id: u64,
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
            Chain::Hoodi => ChainLoader::Known(KnownChain::Hoodi),
            Chain::Custom {
                genesis_time_secs,
                slot_time_secs,
                genesis_fork_version,
                fulu_fork_slot,
                chain_id,
            } => ChainLoader::Custom {
                genesis_time_secs: *genesis_time_secs,
                slot_time_secs: *slot_time_secs,
                genesis_fork_version: Bytes::from(*genesis_fork_version),
                fulu_fork_slot: *fulu_fork_slot,
                chain_id: *chain_id,
            },
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
                let (slot_time_secs, genesis_fork_version, fulu_fork_slot, chain_id) =
                    load_chain_from_file(path).map_err(serde::de::Error::custom)?;
                Ok(Chain::Custom {
                    genesis_time_secs,
                    slot_time_secs,
                    genesis_fork_version,
                    fulu_fork_slot,
                    chain_id,
                })
            }
            ChainLoader::Custom {
                genesis_time_secs,
                slot_time_secs,
                genesis_fork_version,
                fulu_fork_slot,
                chain_id,
            } => {
                let genesis_fork_version: ForkVersion =
                    genesis_fork_version.as_ref().try_into().map_err(serde::de::Error::custom)?;
                Ok(Chain::Custom {
                    genesis_time_secs,
                    slot_time_secs,
                    genesis_fork_version,
                    fulu_fork_slot,
                    chain_id,
                })
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
pub fn load_chain_from_file(path: PathBuf) -> eyre::Result<(u64, ForkVersion, u64, u64)> {
    #[derive(Deserialize)]
    #[serde(rename_all = "UPPERCASE")]
    struct QuotedSpecFile {
        #[serde(with = "serde_utils::quoted_u64")]
        seconds_per_slot: u64,
        genesis_fork_version: Bytes,
        #[serde(with = "serde_utils::quoted_u64")]
        slots_per_epoch: u64,
        #[serde(with = "serde_utils::quoted_u64")]
        fulu_fork_epoch: u64,
        #[serde(with = "serde_utils::quoted_u64")]
        deposit_chain_id: u64,
    }

    impl QuotedSpecFile {
        fn to_chain(&self) -> eyre::Result<(u64, ForkVersion, u64, u64)> {
            let genesis_fork_version: ForkVersion =
                self.genesis_fork_version.as_ref().try_into()?;
            let fulu_fork_slot = self.fulu_fork_epoch.saturating_mul(self.slots_per_epoch);
            Ok((self.seconds_per_slot, genesis_fork_version, fulu_fork_slot, self.deposit_chain_id))
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
        slots_per_epoch: Option<u64>,
        fulu_fork_epoch: u64,
        deposit_chain_id: u64,
    }

    impl SpecFile {
        fn to_chain(&self) -> (u64, ForkVersion, u64, u64) {
            let genesis_fork_version: ForkVersion = self.genesis_fork_version.to_be_bytes();
            let fulu_fork_slot =
                self.fulu_fork_epoch.saturating_mul(self.slots_per_epoch.unwrap_or(32));
            (self.seconds_per_slot, genesis_fork_version, fulu_fork_slot, self.deposit_chain_id)
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
        let s = r#"chain = { genesis_time_secs = 1, slot_time_secs = 2, genesis_fork_version = "0x01000000", fulu_fork_slot = 1, chain_id = 123 }"#;
        let decoded: MockConfig = toml::from_str(s).unwrap();
        assert_eq!(decoded.chain, Chain::Custom {
            genesis_time_secs: 1,
            slot_time_secs: 2,
            genesis_fork_version: [1, 0, 0, 0],
            fulu_fork_slot: 1,
            chain_id: 123,
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
        assert_eq!(decoded.chain.slot_time_sec(), KnownChain::Holesky.slot_time_sec());
        assert_eq!(decoded.chain, Chain::Custom {
            genesis_time_secs: 1,
            slot_time_secs: KnownChain::Holesky.slot_time_sec(),
            genesis_fork_version: KnownChain::Holesky.genesis_fork_version(),
            fulu_fork_slot: KnownChain::Holesky.fulu_fork_slot(),
            chain_id: KnownChain::Holesky.id(),
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
        assert_eq!(decoded.chain.slot_time_sec(), KnownChain::Sepolia.slot_time_sec());
        assert_eq!(decoded.chain, Chain::Custom {
            genesis_time_secs: 1,
            slot_time_secs: KnownChain::Sepolia.slot_time_sec(),
            genesis_fork_version: KnownChain::Sepolia.genesis_fork_version(),
            fulu_fork_slot: KnownChain::Sepolia.fulu_fork_slot(),
            chain_id: KnownChain::Sepolia.id(),
        })
    }

    #[test]
    fn test_spec_hoodi_data_json() {
        let a = env!("CARGO_MANIFEST_DIR");
        let mut path = PathBuf::from(a);

        path.pop();
        path.pop();
        path.push("tests/data/hoodi_spec.json");

        let s = format!("chain = {{ genesis_time_secs = 1, path = {path:?}}}");

        let decoded: MockConfig = toml::from_str(&s).unwrap();
        assert_eq!(decoded.chain.slot_time_sec(), KnownChain::Hoodi.slot_time_sec());
        assert_eq!(decoded.chain, Chain::Custom {
            genesis_time_secs: 1,
            slot_time_secs: KnownChain::Hoodi.slot_time_sec(),
            genesis_fork_version: KnownChain::Hoodi.genesis_fork_version(),
            fulu_fork_slot: KnownChain::Hoodi.fulu_fork_slot(),
            chain_id: KnownChain::Hoodi.id(),
        })
    }
}
