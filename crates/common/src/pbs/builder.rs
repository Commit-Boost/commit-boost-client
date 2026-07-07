use std::fmt::{Display, Formatter, Result};

use serde::{Deserialize, Serialize};

use crate::pbs::{BUILDER_V1_API_PATH, BUILDER_V2_API_PATH, BUILDER_V3_API_PATH};

// Version of the builder API for various routes
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BuilderApiVersion {
    V1 = 1,
    V2,
    V3,
}
impl BuilderApiVersion {
    pub const fn path(&self) -> &'static str {
        match self {
            BuilderApiVersion::V1 => BUILDER_V1_API_PATH,
            BuilderApiVersion::V2 => BUILDER_V2_API_PATH,
            BuilderApiVersion::V3 => BUILDER_V3_API_PATH,
        }
    }
}
impl Display for BuilderApiVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let s = match self {
            BuilderApiVersion::V1 => "v1",
            BuilderApiVersion::V2 => "v2",
            BuilderApiVersion::V3 => "v3",
        };
        write!(f, "{s}")
    }
}
