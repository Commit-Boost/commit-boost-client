use std::{ffi::OsStr, fs, path::PathBuf};

use alloy::{primitives::hex::FromHex, rpc::types::beacon::BlsPublicKey};
use eth2_keystore::Keystore;
use eyre::{eyre, Context, OptionExt};
use serde::{de, Deserialize, Deserializer, Serialize};
use tracing::warn;

use crate::{
    config::{load_env_var, SIGNER_DIR_KEYS_ENV, SIGNER_DIR_SECRETS_ENV, SIGNER_KEYS_ENV},
    signer::ConsensusSigner,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum SignerLoader {
    /// Plain text, do not use in prod
    File {
        key_path: PathBuf,
    },
    ValidatorsDir {
        keys_path: PathBuf,
        secrets_path: PathBuf,
        format: ValidatorKeysFormat,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ValidatorKeysFormat {
    Lighthouse,
    Teku,
}

impl SignerLoader {
    pub fn load_keys(self) -> eyre::Result<Vec<ConsensusSigner>> {
        self.load_from_env()
    }

    pub fn load_from_env(self) -> eyre::Result<Vec<ConsensusSigner>> {
        Ok(match self {
            SignerLoader::File { .. } => {
                let path = load_env_var(SIGNER_KEYS_ENV)?;
                let file = std::fs::read_to_string(path)
                    .unwrap_or_else(|_| panic!("Unable to find keys file"));

                let keys: Vec<FileKey> = serde_json::from_str(&file)?;

                keys.into_iter()
                    .map(|k| ConsensusSigner::new_from_bytes(&k.secret_key))
                    .collect::<Result<_, _>>()
                    .context("failed to load signers")?
            }
            SignerLoader::ValidatorsDir { keys_path, secrets_path, format } => {
                // TODO: hacky way to load for now, we should support reading the
                // definitions.yml file
                let keys_path = load_env_var(SIGNER_DIR_KEYS_ENV).unwrap_or(
                    keys_path.to_str().ok_or_eyre("Missing signer keys path")?.to_string(),
                );
                let secrets_path = load_env_var(SIGNER_DIR_SECRETS_ENV).unwrap_or(
                    secrets_path.to_str().ok_or_eyre("Missing signer secrets path")?.to_string(),
                );

                match format {
                    ValidatorKeysFormat::Lighthouse => {
                        load_from_lighthouse_format(keys_path, secrets_path)
                            .context("failed to load signers")?
                    }
                    ValidatorKeysFormat::Teku => load_from_teku_format(keys_path, secrets_path)
                        .context("failed to load signers")?,
                }
            }
        })
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
        let bytes: [u8; 32] = s.try_into().map_err(|_| de::Error::custom("wrong length"))?;

        Ok(FileKey { secret_key: bytes })
    }
}

fn load_from_lighthouse_format(
    keys_path: String,
    secrets_path: String,
) -> eyre::Result<Vec<ConsensusSigner>> {
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

                    match load_one(ks_path, pw_path) {
                        Ok(signer) => signers.push(signer),
                        Err(e) => warn!("Failed to load signer for pubkey: {}, err: {}", pubkey, e),
                    }
                } else {
                    warn!("Invalid pubkey: {}", maybe_pubkey);
                }
            }
        }
    }

    Ok(signers)
}

fn load_from_teku_format(
    keys_path: String,
    secrets_path: String,
) -> eyre::Result<Vec<ConsensusSigner>> {
    let entries = fs::read_dir(keys_path.clone())?;
    let mut signers = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            warn!("Path {path:?} is a dir");
            continue;
        }

        let file_name = path
            .file_name()
            .map(OsStr::to_str)
            .flatten()
            .ok_or_eyre("File name not valid")?
            .rsplit_once(".")
            .ok_or_eyre("File doesn't have extension")?
            .0;

        match load_one(
            format!("{keys_path}/{file_name}.json"),
            format!("{secrets_path}/{file_name}.txt"),
        ) {
            Ok(signer) => signers.push(signer),
            Err(e) => warn!("Sign load error: {e}"),
        }
    }

    Ok(signers)
}

fn load_one(ks_path: String, pw_path: String) -> eyre::Result<ConsensusSigner> {
    let keystore = Keystore::from_json_file(ks_path).map_err(|_| eyre!("failed reading json"))?;
    let password =
        fs::read(pw_path.clone()).map_err(|e| eyre!("Failed to read password ({pw_path}): {e}"))?;
    let key =
        keystore.decrypt_keypair(&password).map_err(|_| eyre!("failed decrypting keypair"))?;
    ConsensusSigner::new_from_bytes(key.sk.serialize().as_bytes())
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
