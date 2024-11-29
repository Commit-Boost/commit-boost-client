use std::{
    collections::HashMap,
    fs::{create_dir_all, read_to_string},
    io::Write,
    path::PathBuf,
    str::FromStr,
};

use alloy::{
    hex,
    primitives::{Bytes, FixedBytes},
    rpc::types::beacon::constants::BLS_SIGNATURE_BYTES_LEN,
};
use eth2_keystore::{
    default_kdf,
    json_keystore::{
        Aes128Ctr, ChecksumModule, Cipher, CipherModule, Crypto, JsonKeystore, KdfModule,
        Sha256Checksum,
    },
    Uuid, IV_SIZE, SALT_SIZE,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    commit::request::{EncryptionScheme, ProxyDelegation, PublicKey, SignedProxyDelegation},
    config::{load_env_var, PROXY_DIR_ENV, PROXY_DIR_KEYS_ENV, PROXY_DIR_SECRETS_ENV},
    signer::{
        BlsProxySigner, BlsPublicKey, BlsSigner, EcdsaProxySigner, EcdsaPublicKey, EcdsaSigner,
        ProxySigners,
    },
    types::ModuleId,
};

use super::{load_bls_signer, load_ecdsa_signer};

#[derive(Debug, Serialize, Deserialize)]
struct KeyAndDelegation<T: PublicKey> {
    secret: Bytes,
    delegation: SignedProxyDelegation<T>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ProxyStore {
    /// Stores private keys in plaintext to a file, do not use in prod
    File {
        proxy_dir: PathBuf,
    },
    ERC2335 {
        keys_path: PathBuf,
        secrets_path: PathBuf,
    },
}

impl ProxyStore {
    pub fn init_from_env(self) -> eyre::Result<Self> {
        Ok(match self {
            ProxyStore::File { .. } => {
                let path = load_env_var(PROXY_DIR_ENV)?;
                ProxyStore::File { proxy_dir: PathBuf::from(path) }
            }
            ProxyStore::ERC2335 { .. } => {
                let keys_path = PathBuf::from_str(&load_env_var(PROXY_DIR_KEYS_ENV)?)?;
                let secrets_path = PathBuf::from_str(&load_env_var(PROXY_DIR_SECRETS_ENV)?)?;

                ProxyStore::ERC2335 { keys_path, secrets_path }
            }
        })
    }

    pub fn store_proxy_bls(
        &self,
        module_id: &ModuleId,
        proxy: &BlsProxySigner,
    ) -> eyre::Result<()> {
        match self {
            ProxyStore::File { proxy_dir } => {
                let file_path = proxy_dir
                    .join(module_id.to_string())
                    .join("bls")
                    .join(proxy.signer.pubkey().to_string());
                let secret = Bytes::from(proxy.signer.secret());
                let to_store = KeyAndDelegation { secret, delegation: proxy.delegation };
                let content = serde_json::to_vec(&to_store)?;

                if let Some(parent) = file_path.parent() {
                    create_dir_all(parent)?;
                }

                let mut file = std::fs::File::create(file_path)?;
                file.write_all(content.as_ref())?;
            }
            ProxyStore::ERC2335 { keys_path, secrets_path } => {
                store_erc2335_key(
                    module_id,
                    proxy.delegation,
                    proxy.secret().to_vec(),
                    keys_path,
                    secrets_path,
                    EncryptionScheme::Bls,
                )?;
            }
        }

        Ok(())
    }

    pub fn store_proxy_ecdsa(
        &self,
        module_id: &ModuleId,
        proxy: &EcdsaProxySigner,
    ) -> eyre::Result<()> {
        match self {
            ProxyStore::File { proxy_dir } => {
                let file_path = proxy_dir
                    .join(module_id.to_string())
                    .join("ecdsa")
                    .join(proxy.signer.pubkey().to_string());
                let secret = Bytes::from(proxy.signer.secret());
                let to_store = KeyAndDelegation { secret, delegation: proxy.delegation };
                let content = serde_json::to_vec(&to_store)?;

                if let Some(parent) = file_path.parent() {
                    create_dir_all(parent)?;
                }

                let mut file = std::fs::File::create(file_path)?;
                file.write_all(content.as_ref())?;
            }
            ProxyStore::ERC2335 { keys_path, secrets_path } => {
                store_erc2335_key(
                    module_id,
                    proxy.delegation,
                    proxy.secret(),
                    keys_path,
                    secrets_path,
                    EncryptionScheme::Ecdsa,
                )?;
            }
        }

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub fn load_proxies(
        &self,
    ) -> eyre::Result<(
        ProxySigners,
        HashMap<ModuleId, Vec<BlsPublicKey>>,
        HashMap<ModuleId, Vec<EcdsaPublicKey>>,
    )> {
        match self {
            ProxyStore::File { proxy_dir } => {
                // HashMaps to store module_id -> content mappings
                let mut proxy_signers = ProxySigners::default();
                let mut bls_map: HashMap<ModuleId, Vec<BlsPublicKey>> = HashMap::new();
                let mut ecdsa_map: HashMap<ModuleId, Vec<EcdsaPublicKey>> = HashMap::new();

                // Iterate over the entries in the base directory
                for entry in std::fs::read_dir(proxy_dir)? {
                    let entry = entry?;
                    let module_path = entry.path();

                    // Ensure that the entry is a directory
                    if module_path.is_dir() {
                        if let Some(module_id) =
                            module_path.file_name().and_then(|name| name.to_str())
                        {
                            let module_id = ModuleId(module_id.to_string());

                            // Paths to "bls" and "ecdsa" directories
                            let bls_path = module_path.join("bls");
                            let ecdsa_path = module_path.join("ecdsa");

                            // Read "bls" directory files
                            if bls_path.is_dir() {
                                for entry in std::fs::read_dir(bls_path)? {
                                    let entry = entry?;
                                    let path = entry.path();

                                    if path.is_file() {
                                        let file_content = read_to_string(&path)?;
                                        let key_and_delegation: KeyAndDelegation<BlsPublicKey> =
                                            serde_json::from_str(&file_content)?;
                                        let signer =
                                            BlsSigner::new_from_bytes(&key_and_delegation.secret)?;
                                        let pubkey = signer.pubkey();
                                        let proxy_signer = BlsProxySigner {
                                            signer,
                                            delegation: key_and_delegation.delegation,
                                        };

                                        proxy_signers.bls_signers.insert(pubkey, proxy_signer);
                                        bls_map.entry(module_id.clone()).or_default().push(pubkey);
                                    }
                                }
                            }

                            // Read "ecdsa" directory files
                            if ecdsa_path.is_dir() {
                                for entry in std::fs::read_dir(ecdsa_path)? {
                                    let entry = entry?;
                                    let path = entry.path();

                                    if path.is_file() {
                                        let file_content = read_to_string(&path)?;
                                        let key_and_delegation: KeyAndDelegation<EcdsaPublicKey> =
                                            serde_json::from_str(&file_content)?;
                                        let signer = EcdsaSigner::new_from_bytes(
                                            &key_and_delegation.secret,
                                        )?;
                                        let pubkey = signer.pubkey();
                                        let proxy_signer = EcdsaProxySigner {
                                            signer,
                                            delegation: key_and_delegation.delegation,
                                        };

                                        proxy_signers.ecdsa_signers.insert(pubkey, proxy_signer);
                                        ecdsa_map
                                            .entry(module_id.clone())
                                            .or_default()
                                            .push(pubkey);
                                    }
                                }
                            }
                        }
                    }
                }

                Ok((proxy_signers, bls_map, ecdsa_map))
            }
            ProxyStore::ERC2335 { keys_path, secrets_path } => {
                let mut proxy_signers = ProxySigners::default();
                let mut bls_map: HashMap<ModuleId, Vec<BlsPublicKey>> = HashMap::new();
                let mut ecdsa_map: HashMap<ModuleId, Vec<EcdsaPublicKey>> = HashMap::new();

                for entry in std::fs::read_dir(keys_path)? {
                    let entry = entry?;
                    let consensus_key_path = entry.path();
                    let consensus_pubkey = match FixedBytes::from_str(
                        &entry.file_name().to_string_lossy().to_string(),
                    ) {
                        Ok(bytes) => BlsPublicKey::from(bytes),
                        Err(e) => {
                            warn!("Failed to parse consensus pubkey: {e}");
                            continue;
                        }
                    };

                    if !consensus_key_path.is_dir() {
                        warn!("{consensus_key_path:?} is not a directory");
                        continue;
                    }

                    for entry in std::fs::read_dir(&consensus_key_path)? {
                        let entry = entry?;
                        let module_path = entry.path();
                        let module_id = entry.file_name().to_string_lossy().to_string();

                        if !module_path.is_dir() {
                            warn!("{module_path:?} is not a directory");
                            continue;
                        }

                        for entry in std::fs::read_dir(&module_path)? {
                            let entry = entry?;
                            let path = entry.path();
                            let scheme: EncryptionScheme = match entry
                                .file_name()
                                .to_string_lossy()
                                .to_string()
                                .rsplit_once(".")
                            {
                                Some((scheme, ext)) if ext == "json" => {
                                    EncryptionScheme::from_str(scheme)
                                        .map_err(|e| eyre::eyre!(e))?
                                }
                                _ => continue,
                            };

                            match scheme {
                                EncryptionScheme::Bls => {
                                    let signer = load_bls_signer(
                                        path,
                                        secrets_path
                                            .join(format!("{consensus_pubkey:#x}"))
                                            .join(&module_id)
                                            .join("bls"),
                                    )?;

                                    let delegation_signature = match std::fs::read_to_string(
                                        module_path.join("bls.sig"),
                                    ) {
                                        Ok(sig) => {
                                            FixedBytes::<BLS_SIGNATURE_BYTES_LEN>::from_str(&sig)?
                                        }
                                        Err(e) => {
                                            warn!("Failed to read delegation signature: {e}");
                                            continue;
                                        }
                                    };

                                    let proxy_signer = BlsProxySigner {
                                        signer: signer.clone(),
                                        delegation: SignedProxyDelegation {
                                            message: ProxyDelegation {
                                                delegator: consensus_pubkey,
                                                proxy: signer.pubkey(),
                                            },
                                            signature: delegation_signature,
                                        },
                                    };

                                    proxy_signers.bls_signers.insert(signer.pubkey(), proxy_signer);
                                    bls_map
                                        .entry(ModuleId(module_id.clone().into()))
                                        .or_default()
                                        .push(signer.pubkey());
                                }
                                EncryptionScheme::Ecdsa => {
                                    let signer = load_ecdsa_signer(
                                        path,
                                        secrets_path
                                            .join(format!("{consensus_pubkey:#x}"))
                                            .join(&module_id)
                                            .join("ecdsa"),
                                    )?;
                                    let delegation_signature = match std::fs::read_to_string(
                                        module_path.join("ecdsa.sig"),
                                    ) {
                                        Ok(sig) => {
                                            FixedBytes::<BLS_SIGNATURE_BYTES_LEN>::from_str(&sig)?
                                        }
                                        Err(e) => {
                                            warn!("Failed to read delegation signature: {e}");
                                            continue;
                                        }
                                    };

                                    let proxy_signer = EcdsaProxySigner {
                                        signer: signer.clone(),
                                        delegation: SignedProxyDelegation {
                                            message: ProxyDelegation {
                                                delegator: consensus_pubkey,
                                                proxy: signer.pubkey(),
                                            },
                                            signature: delegation_signature,
                                        },
                                    };

                                    proxy_signers
                                        .ecdsa_signers
                                        .insert(signer.pubkey(), proxy_signer);
                                    ecdsa_map
                                        .entry(ModuleId(module_id.clone().into()))
                                        .or_default()
                                        .push(signer.pubkey());
                                }
                            }
                        }
                    }
                }
                Ok((proxy_signers, bls_map, ecdsa_map))
            }
        }
    }
}

fn store_erc2335_key<T: PublicKey>(
    module_id: &ModuleId,
    delegation: SignedProxyDelegation<T>,
    secret: Vec<u8>,
    keys_path: &PathBuf,
    secrets_path: &PathBuf,
    scheme: EncryptionScheme,
) -> eyre::Result<()> {
    let password_bytes: [u8; 32] = rand::thread_rng().gen();
    let password = hex::encode(password_bytes);

    let pass_path =
        secrets_path.join(format!("{:#x}", delegation.message.delegator)).join(&module_id.0);
    std::fs::create_dir_all(&pass_path)?;
    let pass_path = pass_path.join(scheme.to_string());
    let mut pass_file = std::fs::File::create(&pass_path)?;
    pass_file.write_all(password.as_bytes())?;

    let sig_path =
        keys_path.join(format!("{:#x}", delegation.message.delegator)).join(&module_id.0);
    std::fs::create_dir_all(&sig_path)?;
    let sig_path = sig_path.join(format!("{}.sig", scheme.to_string()));

    let mut sig_file = std::fs::File::create(sig_path)?;
    sig_file.write_all(format!("{:#x}", delegation.signature).as_bytes())?;

    let salt: [u8; SALT_SIZE] = rand::thread_rng().gen();
    let iv: [u8; IV_SIZE] = rand::thread_rng().gen();
    let kdf = default_kdf(salt.to_vec());
    let cipher = Cipher::Aes128Ctr(Aes128Ctr { iv: iv.to_vec().into() });
    let (cipher_text, checksum) =
        eth2_keystore::encrypt(&secret, password.as_bytes(), &kdf, &cipher)
            .map_err(|_| eyre::eyre!("Error encrypting key"))?;

    let keystore = JsonKeystore {
        crypto: Crypto {
            kdf: KdfModule {
                function: kdf.function(),
                params: kdf,
                message: eth2_keystore::json_keystore::EmptyString,
            },
            checksum: ChecksumModule {
                function: Sha256Checksum::function(),
                params: eth2_keystore::json_keystore::EmptyMap,
                message: checksum.to_vec().into(),
            },
            cipher: CipherModule {
                function: cipher.function(),
                params: cipher,
                message: cipher_text.into(),
            },
        },
        uuid: Uuid::new_v4(),
        path: None,
        pubkey: format!("{:x}", delegation.message.proxy),
        version: eth2_keystore::json_keystore::Version::V4,
        description: Some(format!("{:#x}", delegation.message.proxy)),
        name: None,
    };

    let json_path =
        keys_path.join(format!("{:#x}", delegation.message.delegator)).join(&module_id.0);
    std::fs::create_dir_all(&json_path)?;
    let json_path = json_path.join(format!("{}.json", scheme.to_string()));
    let mut json_file = std::fs::File::create(&json_path)?;
    json_file.write_all(serde_json::to_string(&keystore)?.as_bytes())?;

    Ok(())
}
