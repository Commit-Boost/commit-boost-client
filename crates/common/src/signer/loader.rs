use std::{
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
};

use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes128,
};
use alloy::{primitives::hex::FromHex, rpc::types::beacon::BlsPublicKey};
use eth2_keystore::{json_keystore::JsonKeystore, Keystore};
use eyre::{eyre, Context};
use pbkdf2::{hmac, pbkdf2};
use rayon::prelude::*;
use serde::{de, Deserialize, Deserializer, Serialize};
use tracing::warn;
use unicode_normalization::UnicodeNormalization;

use super::{BlsSigner, EcdsaSigner, PrysmDecryptedKeystore, PrysmKeystore};
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
    #[serde(alias = "lighthouse")]
    Lighthouse,
    #[serde(alias = "teku")]
    Teku,
    #[serde(alias = "lodestar")]
    Lodestar,
    #[serde(alias = "prysm")]
    Prysm,
    #[serde(alias = "nimbus")]
    Nimbus,
}

impl SignerLoader {
    pub fn load_keys(self) -> eyre::Result<Vec<ConsensusSigner>> {
        self.load_from_env()
    }

    pub fn load_from_env(self) -> eyre::Result<Vec<ConsensusSigner>> {
        Ok(match self {
            SignerLoader::File { key_path } => {
                let path = load_env_var(SIGNER_KEYS_ENV).map(PathBuf::from).unwrap_or(key_path);
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
                let keys_path =
                    load_env_var(SIGNER_DIR_KEYS_ENV).map(PathBuf::from).unwrap_or(keys_path);
                let secrets_path =
                    load_env_var(SIGNER_DIR_SECRETS_ENV).map(PathBuf::from).unwrap_or(secrets_path);

                return match format {
                    ValidatorKeysFormat::Lighthouse => {
                        load_from_lighthouse_format(keys_path, secrets_path)
                    }
                    ValidatorKeysFormat::Teku => load_from_teku_format(keys_path, secrets_path),
                    ValidatorKeysFormat::Lodestar => {
                        load_from_lodestar_format(keys_path, secrets_path)
                    }
                    ValidatorKeysFormat::Prysm => load_from_prysm_format(keys_path, secrets_path),
                    ValidatorKeysFormat::Nimbus => load_from_nimbus_format(keys_path, secrets_path),
                };
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
    keys_path: PathBuf,
    secrets_path: PathBuf,
) -> eyre::Result<Vec<ConsensusSigner>> {
    let paths: Vec<_> =
        fs::read_dir(&keys_path)?.map(|res| res.map(|e| e.path())).collect::<Result<_, _>>()?;

    let signers = paths
        .into_par_iter()
        .filter_map(|path| {
            if !path.is_dir() {
                return None
            }

            let maybe_pubkey = path.file_name().and_then(|d| d.to_str())?;
            let Ok(pubkey) = BlsPublicKey::from_hex(maybe_pubkey) else {
                warn!("Invalid pubkey: {}", maybe_pubkey);
                return None
            };

            let ks_path = keys_path.join(maybe_pubkey).join("voting-keystore.json");
            let pw_path = secrets_path.join(pubkey.to_string());

            match load_one(ks_path, pw_path) {
                Ok(signer) => Some(signer),
                Err(e) => {
                    warn!("Failed to load signer for pubkey: {}, err: {}", pubkey, e);
                    None
                }
            }
        })
        .collect();

    Ok(signers)
}

fn load_from_teku_format(
    keys_path: PathBuf,
    secrets_path: PathBuf,
) -> eyre::Result<Vec<ConsensusSigner>> {
    let paths: Vec<_> =
        fs::read_dir(&keys_path)?.map(|res| res.map(|e| e.path())).collect::<Result<_, _>>()?;

    let signers = paths
        .into_par_iter()
        .filter_map(|path| {
            if path.is_dir() {
                warn!("Path {path:?} is a dir");
                return None;
            }

            let file_name = path.file_name()?.to_str()?.rsplit_once(".")?.0;

            match load_one(
                keys_path.join(format!("{file_name}.json")),
                secrets_path.join(format!("{file_name}.txt")),
            ) {
                Ok(signer) => Some(signer),
                Err(e) => {
                    warn!("Sign load error: {e}");
                    None
                }
            }
        })
        .collect();

    Ok(signers)
}

fn load_from_lodestar_format(
    keys_path: PathBuf,
    password_path: PathBuf,
) -> eyre::Result<Vec<ConsensusSigner>> {
    let paths: Vec<_> =
        fs::read_dir(&keys_path)?.map(|res| res.map(|e| e.path())).collect::<Result<_, _>>()?;

    let signers = paths
        .into_par_iter()
        .filter_map(|path| {
            if path.is_dir() {
                warn!("Path {path:?} is a dir");
                return None;
            }

            match load_one(path, password_path.clone()) {
                Ok(signer) => Some(signer),
                Err(e) => {
                    warn!("Sign load error: {e}");
                    None
                }
            }
        })
        .collect();

    Ok(signers)
}

/// Prysm's keystore is a json file with the keys encrypted with a password,
/// among with some metadata to decrypt them.
/// Once decrypted, the keys have the following structure:
/// ```json
/// {
///     "private_keys": [
///         "sk1_base64_encoded",
///         "sk2_base64_encoded",
///         ...
///     ],
///     "public_keys": [
///         "pk1_base64_encoded",
///         "pk2_base64_encoded",
///         ...
///     ]
/// }
/// ```
fn load_from_prysm_format(
    accounts_path: PathBuf,
    password_path: PathBuf,
) -> eyre::Result<Vec<ConsensusSigner>> {
    let accounts_file = File::open(accounts_path)?;
    let accounts_reader = BufReader::new(accounts_file);
    let keystore: PrysmKeystore =
        serde_json::from_reader(accounts_reader).map_err(|e| eyre!("Failed reading json: {e}"))?;

    let password = fs::read_to_string(password_path)?;
    // Normalized as required by EIP-2335
    // (https://eips.ethereum.org/EIPS/eip-2335#password-requirements)
    let normalized_password = password
        .nfkd()
        .collect::<String>()
        .bytes()
        .filter(|char| (*char > 0x1F && *char < 0x7F) || *char > 0x9F)
        .collect::<Vec<u8>>();

    let mut decryption_key = [0u8; 32];
    pbkdf2::<hmac::Hmac<sha2::Sha256>>(
        &normalized_password,
        &keystore.salt,
        keystore.c,
        &mut decryption_key,
    )?;

    let ciphertext = keystore.message;

    let mut cipher = ctr::Ctr128BE::<Aes128>::new_from_slices(&decryption_key[..16], &keystore.iv)
        .map_err(|_| eyre!("Invalid key or nonce"))?;

    let mut buf = vec![0u8; ciphertext.len()];
    cipher
        .apply_keystream_b2b(&ciphertext, &mut buf)
        .map_err(|_| eyre!("Failed decrypting accounts"))?;

    let decrypted_keystore: PrysmDecryptedKeystore =
        serde_json::from_slice(&buf).map_err(|e| eyre!("Failed reading json: {e}"))?;
    let signers = decrypted_keystore
        .private_keys
        .into_par_iter()
        .map(|pk| ConsensusSigner::new_from_bytes(&pk))
        .collect::<Result<Vec<_>, _>>()
        .context("failed to load signers")?;

    Ok(signers)
}

fn load_from_nimbus_format(
    keys_path: PathBuf,
    secrets_path: PathBuf,
) -> eyre::Result<Vec<ConsensusSigner>> {
    let paths: Vec<_> =
        fs::read_dir(&keys_path)?.map(|res| res.map(|e| e.path())).collect::<Result<_, _>>()?;

    let signers = paths
        .into_par_iter()
        .filter_map(|path| {
            if !path.is_dir() {
                return None
            }

            let maybe_pubkey = path.file_name().and_then(|d| d.to_str())?;
            let Ok(pubkey) = BlsPublicKey::from_hex(maybe_pubkey) else {
                warn!("Invalid pubkey: {}", maybe_pubkey);
                return None
            };

            let ks_path = keys_path.join(maybe_pubkey).join("keystore.json");
            let pw_path = secrets_path.join(pubkey.to_string());

            match load_one(ks_path, pw_path) {
                Ok(signer) => Some(signer),
                Err(e) => {
                    warn!("Failed to load signer for pubkey: {}, err: {}", pubkey, e);
                    None
                }
            }
        })
        .collect();

    Ok(signers)
}

fn load_one(ks_path: PathBuf, pw_path: PathBuf) -> eyre::Result<ConsensusSigner> {
    let keystore = Keystore::from_json_file(ks_path).map_err(|_| eyre!("failed reading json"))?;
    let password = fs::read(pw_path.clone())
        .map_err(|e| eyre!("Failed to read password ({}): {e}", pw_path.display()))?;
    let key =
        keystore.decrypt_keypair(&password).map_err(|_| eyre!("failed decrypting keypair"))?;
    ConsensusSigner::new_from_bytes(key.sk.serialize().as_bytes())
}

pub fn load_bls_signer(keys_path: PathBuf, secrets_path: PathBuf) -> eyre::Result<BlsSigner> {
    load_one(keys_path, secrets_path)
}

pub fn load_ecdsa_signer(keys_path: PathBuf, secrets_path: PathBuf) -> eyre::Result<EcdsaSigner> {
    let key_file = std::fs::File::open(keys_path)?;
    let key_reader = std::io::BufReader::new(key_file);
    let keystore: JsonKeystore = serde_json::from_reader(key_reader)?;
    let password = std::fs::read(secrets_path)?;
    let decrypted_password = eth2_keystore::decrypt(&password, &keystore.crypto)
        .map_err(|_| eyre::eyre!("Error decrypting ECDSA keystore"))?;

    EcdsaSigner::new_from_bytes(decrypted_password.as_bytes())
}

#[cfg(test)]
mod tests {

    use alloy::{hex, primitives::FixedBytes};

    use super::{load_from_lighthouse_format, load_from_lodestar_format, FileKey};
    use crate::signer::{
        loader::{load_from_nimbus_format, load_from_prysm_format, load_from_teku_format},
        BlsPublicKey, BlsSigner,
    };

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

    fn test_correct_load(signers: Vec<BlsSigner>) {
        assert_eq!(signers.len(), 2);
        assert!(signers.iter().any(|s| s.pubkey() == BlsPublicKey::from(FixedBytes::new(
            hex!("883827193f7627cd04e621e1e8d56498362a52b2a30c9a1c72036eb935c4278dee23d38a24d2f7dda62689886f0c39f4")
        ))));
        assert!(signers.iter().any(|s| s.pubkey() == BlsPublicKey::from(FixedBytes::new(
            hex!("b3a22e4a673ac7a153ab5b3c17a4dbef55f7e47210b20c0cbb0e66df5b36bb49ef808577610b034172e955d2312a61b9")
        ))));
    }

    #[test]
    fn test_load_lighthouse() {
        let result = load_from_lighthouse_format(
            "../../tests/data/keystores/keys".into(),
            "../../tests/data/keystores/secrets".into(),
        );

        assert!(result.is_ok());

        test_correct_load(result.unwrap());
    }

    #[test]
    fn test_load_teku() {
        let result = load_from_teku_format(
            "../../tests/data/keystores/teku-keys".into(),
            "../../tests/data/keystores/teku-secrets".into(),
        );

        assert!(result.is_ok());

        test_correct_load(result.unwrap());
    }

    #[test]
    fn test_load_prysm() {
        let result = load_from_prysm_format(
            "../../tests/data/keystores/prysm/direct/accounts/all-accounts.keystore.json".into(),
            "../../tests/data/keystores/prysm/empty_pass".into(),
        );

        assert!(result.is_ok());

        test_correct_load(result.unwrap());
    }

    #[test]
    fn test_load_lodestar() {
        let result = load_from_lodestar_format(
            "../../tests/data/keystores/teku-keys/".into(),
            "../../tests/data/keystores/secrets/0x883827193f7627cd04e621e1e8d56498362a52b2a30c9a1c72036eb935c4278dee23d38a24d2f7dda62689886f0c39f4".into()
        );

        assert!(result.is_ok());

        let signers = result.unwrap();

        assert_eq!(signers.len(), 1);
        assert!(signers[0].pubkey() == BlsPublicKey::from(FixedBytes::new(
            hex!("883827193f7627cd04e621e1e8d56498362a52b2a30c9a1c72036eb935c4278dee23d38a24d2f7dda62689886f0c39f4")
        )));

        let result = load_from_lodestar_format(
            "../../tests/data/keystores/teku-keys/".into(),
            "../../tests/data/keystores/secrets/0xb3a22e4a673ac7a153ab5b3c17a4dbef55f7e47210b20c0cbb0e66df5b36bb49ef808577610b034172e955d2312a61b9".into()
        );

        assert!(result.is_ok());

        let signers = result.unwrap();

        assert_eq!(signers.len(), 1);
        assert!(signers[0].pubkey() == BlsPublicKey::from(FixedBytes::new(
            hex!("b3a22e4a673ac7a153ab5b3c17a4dbef55f7e47210b20c0cbb0e66df5b36bb49ef808577610b034172e955d2312a61b9")
        )));
    }

    #[test]
    fn test_load_nimbus() {
        let result = load_from_nimbus_format(
            "../../tests/data/keystores/nimbus-keys".into(),
            "../../tests/data/keystores/secrets".into(),
        );

        assert!(result.is_ok());

        test_correct_load(result.unwrap());
    }
}
