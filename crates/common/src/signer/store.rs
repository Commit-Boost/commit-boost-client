use std::{
    collections::HashMap,
    fs::{create_dir_all, read_to_string},
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

use alloy::{
    hex,
    primitives::{Address, Bytes, FixedBytes},
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
use eyre::{Context, OptionExt};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::{trace, warn};

use super::{load_bls_signer, load_ecdsa_signer};
use crate::{
    commit::request::{EncryptionScheme, ProxyDelegation, ProxyId, SignedProxyDelegation},
    config::{load_env_var, PROXY_DIR_ENV, PROXY_DIR_KEYS_ENV, PROXY_DIR_SECRETS_ENV},
    signer::{
        BlsProxySigner, BlsPublicKey, BlsSigner, EcdsaProxySigner, EcdsaSigner, ProxySigners,
    },
    types::ModuleId,
};

#[derive(Debug, Serialize, Deserialize)]
struct KeyAndDelegation<T: ProxyId> {
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
            ProxyStore::File { proxy_dir } => {
                let path = load_env_var(PROXY_DIR_ENV)
                    .unwrap_or(proxy_dir.to_str().ok_or_eyre("Missing proxy dir")?.to_string());
                ProxyStore::File { proxy_dir: PathBuf::from(path) }
            }
            ProxyStore::ERC2335 { keys_path, secrets_path } => {
                let keys_path = if let Ok(path) = load_env_var(PROXY_DIR_KEYS_ENV) {
                    PathBuf::from_str(&path)?
                } else {
                    keys_path
                };
                let secrets_path = if let Ok(path) = load_env_var(PROXY_DIR_SECRETS_ENV) {
                    PathBuf::from_str(&path)?
                } else {
                    secrets_path
                };

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
                    .join(proxy.signer.address().to_string());
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

    pub fn store_proxy_bls_delegation(
        &self,
        module_id: &ModuleId,
        delegation: &SignedProxyDelegation<BlsPublicKey>,
    ) -> eyre::Result<()> {
        let base_path = match self {
            ProxyStore::File { proxy_dir } => proxy_dir,
            ProxyStore::ERC2335 { keys_path, .. } => keys_path,
        };
        let file_path = base_path
            .join("delegations")
            .join(module_id.to_string())
            .join("bls")
            .join(format!("{}.sig", delegation.message.proxy));
        let content = serde_json::to_vec(&delegation)?;
        trace!(?content, "Writing BLS delegation to {file_path:?}");

        if let Some(parent) = file_path.parent() {
            create_dir_all(parent)?;
        }

        let mut file = std::fs::File::create(file_path)?;
        file.write_all(content.as_ref())?;

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub fn load_proxies(
        &self,
    ) -> eyre::Result<(
        ProxySigners,
        HashMap<ModuleId, Vec<BlsPublicKey>>,
        HashMap<ModuleId, Vec<Address>>,
    )> {
        match self {
            ProxyStore::File { proxy_dir } => {
                // HashMaps to store module_id -> content mappings
                let mut proxy_signers = ProxySigners::default();
                let mut bls_map: HashMap<ModuleId, Vec<BlsPublicKey>> = HashMap::new();
                let mut ecdsa_map: HashMap<ModuleId, Vec<Address>> = HashMap::new();

                // Iterate over the entries in the base directory
                for entry in std::fs::read_dir(proxy_dir)
                    .wrap_err_with(|| format!("failed reading proxy dir: {proxy_dir:?}"))?
                {
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
                                        let key_and_delegation: KeyAndDelegation<Address> =
                                            serde_json::from_str(&file_content)?;
                                        let signer = EcdsaSigner::new_from_bytes(
                                            &key_and_delegation.secret,
                                        )?;
                                        let pubkey = signer.address();
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
                let mut ecdsa_map: HashMap<ModuleId, Vec<Address>> = HashMap::new();

                for entry in std::fs::read_dir(keys_path)? {
                    let entry = entry?;
                    let consensus_key_path = entry.path();
                    let consensus_pubkey =
                        match FixedBytes::from_str(&entry.file_name().to_string_lossy()) {
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

                        let bls_path = module_path.join("bls");
                        if let Ok(bls_keys) = std::fs::read_dir(&bls_path) {
                            for entry in bls_keys {
                                let entry = entry?;
                                let path = entry.path();

                                if !path.is_file() ||
                                    path.extension().is_none_or(|ext| ext != "json")
                                {
                                    continue;
                                }

                                let name = entry.file_name().to_string_lossy().to_string();
                                let name = name.trim_end_matches(".json");

                                let signer = load_bls_signer(
                                    path,
                                    secrets_path
                                        .join(consensus_pubkey.to_string())
                                        .join(&module_id)
                                        .join("bls")
                                        .join(name),
                                )
                                .map_err(|e| eyre::eyre!("Error loading BLS signer: {e}"))?;

                                let delegation_signature = match std::fs::read_to_string(
                                    bls_path.join(format!("{name}.sig")),
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
                                    .entry(ModuleId(module_id.clone()))
                                    .or_default()
                                    .push(signer.pubkey());
                            }
                        }

                        let ecdsa_path = module_path.join("ecdsa");
                        if let Ok(ecdsa_keys) = std::fs::read_dir(&ecdsa_path) {
                            for entry in ecdsa_keys {
                                let entry = entry?;
                                let path = entry.path();

                                if !path.is_file() ||
                                    path.extension().is_none_or(|ext| ext != "json")
                                {
                                    continue;
                                }

                                let name = entry.file_name().to_string_lossy().to_string();
                                let name = name.trim_end_matches(".json");

                                let signer = load_ecdsa_signer(
                                    path,
                                    secrets_path
                                        .join(consensus_pubkey.to_string())
                                        .join(&module_id)
                                        .join("ecdsa")
                                        .join(name),
                                )?;
                                let delegation_signature = match std::fs::read_to_string(
                                    ecdsa_path.join(format!("{name}.sig")),
                                ) {
                                    Ok(sig) => {
                                        FixedBytes::<BLS_SIGNATURE_BYTES_LEN>::from_str(&sig)?
                                    }
                                    Err(e) => {
                                        warn!("Failed to read delegation signature: {e}",);
                                        continue;
                                    }
                                };

                                let proxy_signer = EcdsaProxySigner {
                                    signer: signer.clone(),
                                    delegation: SignedProxyDelegation {
                                        message: ProxyDelegation {
                                            delegator: consensus_pubkey,
                                            proxy: signer.address(),
                                        },
                                        signature: delegation_signature,
                                    },
                                };

                                proxy_signers.ecdsa_signers.insert(signer.address(), proxy_signer);
                                ecdsa_map
                                    .entry(ModuleId(module_id.clone()))
                                    .or_default()
                                    .push(signer.address());
                            }
                        }
                    }
                }
                Ok((proxy_signers, bls_map, ecdsa_map))
            }
        }
    }
}

fn store_erc2335_key<T: ProxyId>(
    module_id: &ModuleId,
    delegation: SignedProxyDelegation<T>,
    secret: Vec<u8>,
    keys_path: &Path,
    secrets_path: &Path,
    scheme: EncryptionScheme,
) -> eyre::Result<()> {
    let proxy_delegation = delegation.message.proxy;

    let password_bytes: [u8; 32] = rand::rng().random();
    let password = hex::encode(password_bytes);

    let pass_path = secrets_path
        .join(delegation.message.delegator.to_string())
        .join(&module_id.0)
        .join(scheme.to_string());
    std::fs::create_dir_all(&pass_path)?;
    let pass_path = pass_path.join(proxy_delegation.to_string());
    let mut pass_file = std::fs::File::create(&pass_path)?;
    pass_file.write_all(password.as_bytes())?;

    let sig_path = keys_path
        .join(delegation.message.delegator.to_string())
        .join(&module_id.0)
        .join(scheme.to_string());
    std::fs::create_dir_all(&sig_path)?;
    let sig_path = sig_path.join(format!("{}.sig", proxy_delegation));

    let mut sig_file = std::fs::File::create(sig_path)?;
    sig_file.write_all(delegation.signature.to_string().as_bytes())?;

    let salt: [u8; SALT_SIZE] = rand::rng().random();
    let iv: [u8; IV_SIZE] = rand::rng().random();
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
        pubkey: alloy::hex::encode(delegation.message.proxy),
        version: eth2_keystore::json_keystore::Version::V4,
        description: Some(delegation.message.proxy.to_string()),
        name: None,
    };

    let json_path = keys_path
        .join(delegation.message.delegator.to_string())
        .join(&module_id.0)
        .join(scheme.to_string());
    std::fs::create_dir_all(&json_path)?;
    let json_path = json_path.join(format!("{}.json", proxy_delegation));
    let mut json_file = std::fs::File::create(&json_path)?;
    json_file.write_all(serde_json::to_string(&keystore)?.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod test {
    use hex::FromHex;
    use tree_hash::TreeHash;

    use super::*;
    use crate::{
        commit::request::{ProxyDelegationBls, SignedProxyDelegationBls},
        signer::ConsensusSigner,
        types::Chain,
    };

    #[tokio::test]
    async fn test_erc2335_storage_format() {
        let tmp_path = std::env::temp_dir().join("test_erc2335_storage_format");
        let keys_path = tmp_path.join("keys");
        let secrets_path = tmp_path.join("secrets");
        let store = ProxyStore::ERC2335 {
            keys_path: keys_path.clone(),
            secrets_path: secrets_path.clone(),
        };

        let module_id = ModuleId("TEST_MODULE".to_string());
        let consensus_signer = ConsensusSigner::new_from_bytes(&hex!(
            "0088e364a5396a81b50febbdc8784663fb9089b5e67cbdc173991a00c587673f"
        ))
        .unwrap();
        let proxy_signer = BlsSigner::new_from_bytes(&hex!(
            "13000f8b3d7747e7754022720d33d5b506490429f3d593162f00e254f97d2940"
        ))
        .unwrap();

        let message = ProxyDelegationBls {
            delegator: consensus_signer.pubkey(),
            proxy: proxy_signer.pubkey(),
        };
        let signature =
            consensus_signer.sign(Chain::Mainnet, &message.tree_hash_root(), None).await;
        let delegation = SignedProxyDelegationBls { signature, message };
        let proxy_signer = BlsProxySigner { signer: proxy_signer, delegation };

        store.store_proxy_bls(&module_id, &proxy_signer).unwrap();

        let json_path = keys_path
            .join(consensus_signer.pubkey().to_string())
            .join("TEST_MODULE")
            .join("bls")
            .join(format!("{}.json", proxy_signer.pubkey()));
        let sig_path = keys_path
            .join(consensus_signer.pubkey().to_string())
            .join("TEST_MODULE")
            .join("bls")
            .join(format!("{}.sig", proxy_signer.pubkey()));
        let pass_path = secrets_path
            .join(consensus_signer.pubkey().to_string())
            .join("TEST_MODULE")
            .join("bls")
            .join(proxy_signer.pubkey().to_string());

        assert!(json_path.exists());
        assert!(sig_path.exists());
        assert!(pass_path.exists());

        let keystore: JsonKeystore =
            serde_json::de::from_str(&std::fs::read_to_string(json_path).unwrap()).unwrap();

        assert_eq!(keystore.pubkey, proxy_signer.pubkey().to_string().trim_start_matches("0x"));

        let sig = FixedBytes::from_hex(std::fs::read_to_string(sig_path).unwrap());
        assert!(sig.is_ok());
        assert_eq!(sig.unwrap(), signature);
    }

    #[test]
    fn test_erc2335_load() {
        let keys_path = Path::new("../../tests/data/proxy/keys").to_path_buf();
        let secrets_path = Path::new("../../tests/data/proxy/secrets").to_path_buf();
        let store = ProxyStore::ERC2335 {
            keys_path: keys_path.clone(),
            secrets_path: secrets_path.clone(),
        };

        let (proxy_signers, bls_keys, ecdsa_keys) = store.load_proxies().unwrap();
        assert_eq!(bls_keys.len(), 1);
        assert_eq!(ecdsa_keys.len(), 0);
        assert_eq!(proxy_signers.bls_signers.len(), 1);
        assert_eq!(proxy_signers.ecdsa_signers.len(), 0);

        let proxy_key = BlsPublicKey::from(
            FixedBytes::from_hex(
                "a77084280678d9f1efe4ef47a3d62af27872ce82db19a35ee012c4fd5478e6b1123b8869032ba18b2383e8873294f0ba"
            ).unwrap()
        );
        let consensus_key = BlsPublicKey::from(
            FixedBytes::from_hex(
                "ac5e059177afc33263e95d0be0690138b9a1d79a6e19018086a0362e0c30a50bf9e05a08cb44785724d0b2718c5c7118"
            ).unwrap()
        );

        let proxy_signer = proxy_signers.bls_signers.get(&proxy_key);

        assert!(proxy_signer.is_some());
        let proxy_signer = proxy_signer.unwrap();

        assert_eq!(
            proxy_signer.delegation.signature,
            FixedBytes::from_hex(
                std::fs::read_to_string(
                    keys_path
                        .join(consensus_key.to_string())
                        .join("TEST_MODULE")
                        .join("bls")
                        .join(format!("{proxy_key}.sig"))
                )
                .unwrap()
            )
            .unwrap()
        );
        assert_eq!(proxy_signer.delegation.message.delegator, consensus_key);
        assert_eq!(proxy_signer.delegation.message.proxy, proxy_key);

        assert!(bls_keys
            .get(&ModuleId("TEST_MODULE".into()))
            .is_some_and(|keys| keys.contains(&proxy_key)));
    }

    #[tokio::test]
    async fn test_erc2335_store_and_load() {
        let tmp_path = std::env::temp_dir().join("test_erc2335_store_and_load");
        let keys_path = tmp_path.join("keys");
        let secrets_path = tmp_path.join("secrets");
        let store = ProxyStore::ERC2335 {
            keys_path: keys_path.clone(),
            secrets_path: secrets_path.clone(),
        };

        let module_id = ModuleId("TEST_MODULE".to_string());
        let consensus_signer = ConsensusSigner::new_from_bytes(&hex!(
            "0088e364a5396a81b50febbdc8784663fb9089b5e67cbdc173991a00c587673f"
        ))
        .unwrap();
        let proxy_signer = BlsSigner::new_from_bytes(&hex!(
            "13000f8b3d7747e7754022720d33d5b506490429f3d593162f00e254f97d2940"
        ))
        .unwrap();

        let message = ProxyDelegationBls {
            delegator: consensus_signer.pubkey(),
            proxy: proxy_signer.pubkey(),
        };
        let signature =
            consensus_signer.sign(Chain::Mainnet, &message.tree_hash_root(), None).await;
        let delegation = SignedProxyDelegationBls { signature, message };
        let proxy_signer = BlsProxySigner { signer: proxy_signer, delegation };

        store.store_proxy_bls(&module_id, &proxy_signer).unwrap();

        let load_result = store.load_proxies();
        assert!(load_result.is_ok());

        let (proxy_signers, bls_keys, ecdsa_keys) = load_result.unwrap();

        assert_eq!(bls_keys.len(), 1);
        assert_eq!(ecdsa_keys.len(), 0);
        assert_eq!(proxy_signers.bls_signers.len(), 1);
        assert_eq!(proxy_signers.ecdsa_signers.len(), 0);

        let loaded_proxy_signer = proxy_signers.bls_signers.get(&proxy_signer.pubkey());

        assert!(loaded_proxy_signer.is_some());
        let loaded_proxy_signer = loaded_proxy_signer.unwrap();

        assert_eq!(
            loaded_proxy_signer.delegation.signature,
            FixedBytes::from_hex(
                std::fs::read_to_string(
                    keys_path
                        .join(consensus_signer.pubkey().to_string())
                        .join("TEST_MODULE")
                        .join("bls")
                        .join(format!("{}.sig", proxy_signer.pubkey()))
                )
                .unwrap()
            )
            .unwrap()
        );
        assert_eq!(loaded_proxy_signer.delegation.message.delegator, consensus_signer.pubkey());
        assert_eq!(loaded_proxy_signer.delegation.message.proxy, proxy_signer.pubkey());

        assert!(bls_keys
            .get(&ModuleId("TEST_MODULE".into()))
            .is_some_and(|keys| keys.contains(&proxy_signer.pubkey())));
    }
}
