use std::{
    collections::HashMap,
    fs::{create_dir_all, read_to_string},
    io::Write,
    path::PathBuf,
};

use alloy::primitives::Bytes;
use serde::{Deserialize, Serialize};

use crate::{
    commit::request::{
        PublicKey, SignedProxyDelegation, SignedProxyDelegationBls, SignedProxyDelegationEcdsa,
    },
    config::{load_env_var, PROXY_DIR_ENV},
    signer::{
        types::{BlsProxySigner, EcdsaProxySigner, ProxySigners},
        BlsPublicKey, BlsSigner, EcdsaPublicKey, EcdsaSigner,
    },
    types::ModuleId,
};

#[derive(Debug, Serialize, Deserialize)]
struct KeyAndDelegation<T: PublicKey> {
    secret: Bytes,
    delegation: SignedProxyDelegation<T>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ProxyStore {
    /// Stores private keys in plaintext to a file, do not use in prod
    File { key_path: PathBuf },
}

impl ProxyStore {
    pub fn init_from_env(self) -> eyre::Result<Self> {
        Ok(match self {
            ProxyStore::File { .. } => {
                let path = load_env_var(PROXY_DIR_ENV)?;
                ProxyStore::File { key_path: PathBuf::from(path) }
            }
        })
    }

    pub fn store_proxy_bls(
        &self,
        module_id: &ModuleId,
        signer: &BlsSigner,
        delegation: SignedProxyDelegationBls,
    ) -> eyre::Result<()> {
        match self {
            ProxyStore::File { key_path } => {
                let file_path = key_path
                    .join(module_id.to_string())
                    .join("bls")
                    .join(signer.pubkey().to_string());
                let secret = Bytes::from(signer.secret());
                let to_store = KeyAndDelegation { secret, delegation };
                let content = serde_json::to_vec(&to_store)?;

                if let Some(parent) = file_path.parent() {
                    create_dir_all(parent)?;
                }

                let mut file = std::fs::File::create(file_path)?;
                file.write_all(content.as_ref())?;
            }
        }

        Ok(())
    }

    pub fn store_proxy_ecdsa(
        &self,
        module_id: &ModuleId,
        signer: &EcdsaSigner,
        delegation: SignedProxyDelegationEcdsa,
    ) -> eyre::Result<()> {
        match self {
            ProxyStore::File { key_path } => {
                let file_path = key_path
                    .join(module_id.to_string())
                    .join("ecdsa")
                    .join(signer.pubkey().to_string());
                let secret = Bytes::from(signer.secret());
                let to_store = KeyAndDelegation { secret, delegation };
                let content = serde_json::to_vec(&to_store)?;

                if let Some(parent) = file_path.parent() {
                    create_dir_all(parent)?;
                }

                let mut file = std::fs::File::create(file_path)?;
                file.write_all(content.as_ref())?;
            }
        }

        Ok(())
    }

    pub fn load_proxies(
        &self,
    ) -> eyre::Result<(
        ProxySigners,
        HashMap<ModuleId, Vec<BlsPublicKey>>,
        HashMap<ModuleId, Vec<EcdsaPublicKey>>,
    )> {
        match self {
            ProxyStore::File { key_path } => {
                // HashMaps to store module_id -> content mappings
                let mut proxy_signers = ProxySigners::default();
                let mut bls_map: HashMap<ModuleId, Vec<BlsPublicKey>> = HashMap::new();
                let mut ecdsa_map: HashMap<ModuleId, Vec<EcdsaPublicKey>> = HashMap::new();

                // Iterate over the entries in the base directory
                for entry in std::fs::read_dir(&key_path)? {
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
        }
    }
}
