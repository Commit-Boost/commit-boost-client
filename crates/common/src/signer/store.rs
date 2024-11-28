use std::{
    collections::HashMap,
    fs::{create_dir_all, read_to_string},
    io::Write,
    path::PathBuf,
    str::FromStr,
};

use alloy::{
    primitives::{Bytes, FixedBytes},
    rpc::types::beacon::constants::BLS_SIGNATURE_BYTES_LEN,
};
use serde::{Deserialize, Serialize};
use serde_utils::hex;
use tracing::warn;

use crate::{
    commit::request::{ProxyDelegation, PublicKey, SignedProxyDelegation},
    config::{load_env_var, PROXY_DIR_ENV, PROXY_DIR_KEYS_ENV, PROXY_DIR_SECRETS_ENV},
    signer::{
        BlsProxySigner, BlsPublicKey, BlsSigner, EcdsaProxySigner, EcdsaPublicKey, EcdsaSigner,
        ProxySigners,
    },
    types::ModuleId,
};

use super::load_one;

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
            ProxyStore::ERC2335 { keys_path, secrets_path } => {}
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
            ProxyStore::ERC2335 { keys_path, secrets_path } => {}
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
                    let consensus_pubkey =
                        match hex::decode(&entry.file_name().to_string_lossy().to_string()) {
                            Ok(pubkey) => BlsPublicKey::from(FixedBytes::from_slice(&pubkey)),
                            Err(e) => {
                                warn!("Failed to parse consensus pubkey: {e}");
                                continue;
                            }
                        };

                    if consensus_key_path.is_file() {
                        warn!("{consensus_key_path:?} is a file");
                        continue;
                    }

                    for entry in std::fs::read_dir(&consensus_key_path)? {
                        let entry = entry?;
                        let path = entry.path();
                        let file_name = entry.file_name().to_string_lossy().to_string();
                        let module_id = match file_name.rsplit_once(".") {
                            Some((module_id, ext)) if ext == "json" => module_id,
                            _ => continue,
                        };

                        if path.is_dir() {
                            warn!("{path:?} is a directory");
                            continue;
                        }

                        let signer = load_one(
                            path.to_string_lossy().to_string(),
                            secrets_path
                                .join(format!("{consensus_pubkey:#x}"))
                                .join(&module_id)
                                .to_string_lossy()
                                .to_string(),
                        )?;

                        let delegation_signature = match std::fs::read_to_string(
                            consensus_key_path.join(format!("{module_id}.sig")),
                        ) {
                            Ok(sig) => sig,
                            Err(e) => {
                                warn!("Failed to read delegation signature: {e}");
                                continue;
                            }
                        };
                        let delegation_signature =
                            FixedBytes::<BLS_SIGNATURE_BYTES_LEN>::from_str(&delegation_signature)?;

                        let proxy_signer = BlsProxySigner {
                            signer: signer.clone(),
                            delegation: SignedProxyDelegation::<BlsPublicKey> {
                                message: ProxyDelegation {
                                    delegator: consensus_pubkey,
                                    proxy: signer.pubkey(),
                                },
                                signature: delegation_signature,
                            },
                        };

                        proxy_signers.bls_signers.insert(signer.pubkey(), proxy_signer);
                        bls_map
                            .entry(ModuleId(module_id.into()))
                            .or_default()
                            .push(signer.pubkey());
                    }
                }
                Ok((proxy_signers, bls_map, ecdsa_map))
            }
        }
    }
}
