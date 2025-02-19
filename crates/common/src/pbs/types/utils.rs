use serde::{Deserialize, Serialize};

pub mod quoted_variable_list_u64 {
    use serde::{ser::SerializeSeq, Deserializer, Serializer};
    use serde_utils::quoted_u64_vec::{QuotedIntVecVisitor, QuotedIntWrapper};
    use ssz_types::{typenum::Unsigned, VariableList};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "version", content = "data")]
pub enum VersionedResponse<D, E> {
    #[serde(rename = "deneb")]
    Deneb(D),
    #[serde(rename = "electra")]
    Electra(E),
}

impl<D: Default, E> Default for VersionedResponse<D, E> {
    fn default() -> Self {
        Self::Deneb(D::default())
    }
}

impl<D, E> VersionedResponse<D, E> {
    pub fn version(&self) -> &str {
        match self {
            VersionedResponse::Deneb(_) => "deneb",
            VersionedResponse::Electra(_) => "electra",
        }
    }
}
