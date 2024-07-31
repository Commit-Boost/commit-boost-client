use std::fs;

use alloy::{primitives::hex::FromHex, rpc::types::beacon::BlsPublicKey};
use eth2_keystore::Keystore;
use eyre::eyre;
use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{
    config::{
        load_env_var_infallible, SIGNER_DIR_KEYS_ENV, SIGNER_DIR_SECRETS_ENV, SIGNER_KEYS_ENV,
    },
    signer::Signer,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum SignerLoader {
    /// Plain text, do not use in prod
    File {
        key_path: String,
    },
    ValidatorsDir {
        keys_path: String,
        secrets_path: String,
    },
}

impl SignerLoader {
    pub fn load_keys(self) -> Vec<Signer> {
        // TODO: add flag to support also native loader
        self.load_from_env()
    }

    pub fn load_from_env(self) -> Vec<Signer> {
        match self {
            SignerLoader::File { .. } => {
                let path = load_env_var_infallible(SIGNER_KEYS_ENV);
                let file = std::fs::read_to_string(path)
                    .unwrap_or_else(|_| panic!("Unable to find keys file"));

                let keys: Vec<FileKey> = serde_json::from_str(&file).unwrap();

                keys.into_iter().map(|k| Signer::new_from_bytes(&k.secret_key)).collect()
            }
            SignerLoader::ValidatorsDir { .. } => {
                // TODO: hacky way to load for now, we should support reading the
                // definitions.yml file
                let keys_path = load_env_var_infallible(SIGNER_DIR_KEYS_ENV);
                let secrets_path = load_env_var_infallible(SIGNER_DIR_SECRETS_ENV);
                load_secrets_and_keys(keys_path, secrets_path).expect("failed to load signers")
            }
        }
    }
}

pub struct FileKey {
    pub secret_key: [u8; 32],
}

impl<'de> Deserialize<'de> for FileKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = alloy::primitives::hex::decode(s.trim_start_matches("0x"))
            .map_err(de::Error::custom)?;
        let bytes: [u8; 32] = s.try_into().map_err(|_| de::Error::custom("wrong lenght"))?;

        Ok(FileKey { secret_key: bytes })
    }
}

fn load_secrets_and_keys(keys_path: String, secrets_path: String) -> eyre::Result<Vec<Signer>> {
    let entries = fs::read_dir(keys_path.clone())?;

    let mut signers = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        // Check if file name is a pubkey
        if path.is_dir() {
            if let Some(maybe_pubkey) = path.file_name().and_then(|d| d.to_str()) {
                if let Ok(pubkey) = BlsPublicKey::from_hex(maybe_pubkey) {
                    let ks_path = format!("{}/{}/voting-keystore.json", keys_path, maybe_pubkey);
                    let pw_path = format!("{}/{}", secrets_path, pubkey);

                    if let Ok(signer) = load_one(ks_path, pw_path) {
                        signers.push(signer);
                    }
                }
            };
        }
    }

    Ok(signers)
}

fn load_one(ks_path: String, pw_path: String) -> eyre::Result<Signer> {
    let keystore = Keystore::from_json_file(ks_path).map_err(|_| eyre!("failed reading json"))?;
    let password = fs::read(pw_path)?;
    let key =
        keystore.decrypt_keypair(&password).map_err(|_| eyre!("failed decrypting keypair"))?;
    Ok(Signer::new_from_bytes(key.sk.serialize().as_bytes()))
}

#[cfg(test)]
mod tests {

    use super::FileKey;

    #[test]
    fn test_decode() {
        let s = [
            0, 136, 227, 100, 165, 57, 106, 129, 181, 15, 235, 189, 200, 120, 70, 99, 251, 144,
            137, 181, 230, 124, 189, 193, 115, 153, 26, 0, 197, 135, 103, 63,
        ];

        let d = r#"[
    "0088e364a5396a81b50febbdc8784663fb9089b5e67cbdc173991a00c587673f",
    "0088e364a5396a81b50febbdc8784663fb9089b5e67cbdc173991a00c587673f"
]"#;
        let decoded: Vec<FileKey> = serde_json::from_str(d).unwrap();

        assert_eq!(decoded[0].secret_key, s)
    }
}
