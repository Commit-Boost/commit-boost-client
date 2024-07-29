use serde::{Deserialize, Serialize};

use crate::constants::{
    HELDER_BUILDER_DOMAIN, HELDER_FORK_VERSION, HELDER_GENESIS_TIME_SECONDS,
    HOLESKY_BUILDER_DOMAIN, HOLESKY_FORK_VERSION, HOLESKY_GENESIS_TIME_SECONDS,
    MAINNET_BUILDER_DOMAIN, MAINNET_FORK_VERSION, MAINNET_GENESIS_TIME_SECONDS,
    RHEA_BUILDER_DOMAIN, RHEA_FORK_VERSION, RHEA_GENESIS_TIME_SECONDS,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Chain {
    Mainnet,
    Holesky,
    Rhea,
    Helder,
}

impl Chain {
    pub fn builder_domain(&self) -> [u8; 32] {
        match self {
            Chain::Mainnet => MAINNET_BUILDER_DOMAIN,
            Chain::Holesky => HOLESKY_BUILDER_DOMAIN,
            Chain::Rhea => RHEA_BUILDER_DOMAIN,
            Chain::Helder => HELDER_BUILDER_DOMAIN,
        }
    }

    pub fn fork_version(&self) -> [u8; 4] {
        match self {
            Chain::Mainnet => MAINNET_FORK_VERSION,
            Chain::Holesky => HOLESKY_FORK_VERSION,
            Chain::Rhea => RHEA_FORK_VERSION,
            Chain::Helder => HELDER_FORK_VERSION,
        }
    }

    pub fn genesis_time_sec(&self) -> u64 {
        match self {
            Chain::Mainnet => MAINNET_GENESIS_TIME_SECONDS,
            Chain::Holesky => HOLESKY_GENESIS_TIME_SECONDS,
            Chain::Rhea => RHEA_GENESIS_TIME_SECONDS,
            Chain::Helder => HELDER_GENESIS_TIME_SECONDS,
        }
    }
}
