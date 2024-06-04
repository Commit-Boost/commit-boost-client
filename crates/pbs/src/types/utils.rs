use serde::{Deserialize, Serialize};

pub mod quoted_variable_list_u64 {
    use serde::{ser::SerializeSeq, Deserializer, Serializer};
    use serde_utils::quoted_u64_vec::{QuotedIntVecVisitor, QuotedIntWrapper};
    use ssz_types::VariableList;
    use typenum::Unsigned;

    pub fn serialize<S, T>(value: &VariableList<u64, T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Unsigned,
    {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for &int in value.iter() {
            seq.serialize_element(&QuotedIntWrapper { int })?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<VariableList<u64, T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Unsigned,
    {
        deserializer.deserialize_any(QuotedIntVecVisitor).and_then(|vec| {
            VariableList::new(vec)
                .map_err(|e| serde::de::Error::custom(format!("invalid length: {:?}", e)))
        })
    }
}

pub mod as_dec_str {
    use ethereum_types::U256;
    use serde::Deserialize;

    pub fn serialize<S>(data: &U256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = data.to_string();
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        U256::from_dec_str(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VersionedResponse<T> {
    pub version: Version,
    pub data: T,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub enum Version {
    #[serde(rename = "deneb")]
    #[default]
    Deneb,
}
