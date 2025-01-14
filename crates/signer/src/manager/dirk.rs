use std::{fs, path::PathBuf};

use alloy::{hex, primitives::FixedBytes};
use cb_common::{
    commit::request::{ConsensusProxyMap, ProxyDelegation, SignedProxyDelegation},
    config::DirkConfig,
    constants::COMMIT_BOOST_DOMAIN,
    signature::compute_domain,
    signer::{BlsPublicKey, BlsSignature, ProxyStore},
    types::{Chain, ModuleId},
};
use rand::Rng;
use tonic::transport::{Channel, ClientTlsConfig};
use tracing::info;
use tree_hash::TreeHash;

use crate::proto::v1::{
    account_manager_client::AccountManagerClient, lister_client::ListerClient,
    sign_request::Id as SignerId, signer_client::SignerClient, Account as DirkAccount,
    GenerateRequest, ListAccountsRequest, ResponseState, SignRequest, UnlockAccountRequest,
};

#[derive(Clone, Debug)]
struct Account {
    wallet: String,
    name: String,
    public_key: Option<BlsPublicKey>,
}

impl Account {
    pub fn complete_name(&self) -> String {
        format!("{}/{}", self.wallet, self.name)
    }
}

#[derive(Clone, Debug)]
pub struct DirkManager {
    chain: Chain,
    channel: Channel,
    accounts: Vec<Account>,
    unlock: bool,
    secrets_path: PathBuf,
    proxy_store: Option<ProxyStore>,
}

impl DirkManager {
    pub async fn new_from_config(chain: Chain, config: DirkConfig) -> eyre::Result<Self> {
        let mut tls_config = ClientTlsConfig::new().identity(config.client_cert);

        if let Some(ca) = config.cert_auth {
            tls_config = tls_config.ca_certificate(ca);
        }

        if let Some(server_domain) = config.server_domain {
            tls_config = tls_config.domain_name(server_domain);
        }

        let channel = Channel::from_shared(config.url.to_string())
            .map_err(|_| eyre::eyre!("Invalid Dirk URL"))?
            .tls_config(tls_config)
            .map_err(|_| eyre::eyre!("Invalid Dirk TLS config"))?
            .connect()
            .await
            .map_err(|e| eyre::eyre!("Couldn't connect to Dirk: {e}"))?;

        let dirk_accounts = get_accounts_in_wallets(
            channel.clone(),
            config
                .accounts
                .iter()
                .filter_map(|account| Some(account.split_once("/")?.0.to_string()))
                .collect(),
        )
        .await?;

        let mut accounts = Vec::with_capacity(config.accounts.len());
        for account in config.accounts {
            let (wallet, name) = account.split_once("/").ok_or(eyre::eyre!(
                "Invalid account name: {account}. It must be in format wallet/account"
            ))?;
            let public_key = dirk_accounts.iter().find_map(|a| {
                if a.name == account {
                    BlsPublicKey::try_from(a.public_key.as_slice()).ok()
                } else {
                    None
                }
            });

            accounts.push(Account {
                wallet: wallet.to_string(),
                name: name.to_string(),
                public_key,
            });
        }
        let wallets =
            accounts.iter().map(|account| account.wallet.clone()).collect::<Vec<String>>();
        let dirk_accounts = get_accounts_in_wallets(channel.clone(), wallets).await?;
        for account in accounts.iter_mut() {
            if let Some(dirk_account) =
                dirk_accounts.iter().find(|a| a.name == account.complete_name())
            {
                account.public_key =
                    Some(BlsPublicKey::try_from(dirk_account.public_key.as_slice())?);
            }
        }

        Ok(Self {
            chain,
            channel,
            accounts,
            unlock: config.unlock,
            secrets_path: config.secrets_path,
            proxy_store: None,
        })
    }

    pub fn with_proxy_store(self, proxy_store: ProxyStore) -> eyre::Result<Self> {
        Ok(Self { proxy_store: Some(proxy_store), ..self })
    }

    /// Get all available accounts in the `self.accounts` wallets
    async fn get_all_accounts(&self) -> eyre::Result<Vec<DirkAccount>> {
        get_accounts_in_wallets(
            self.channel.clone(),
            self.accounts.iter().map(|account| account.wallet.clone()).collect::<Vec<String>>(),
        )
        .await
    }

    /// Get the complete account name (`wallet/account`) for a public key.
    /// Returns `Ok(None)` if the account was not found.
    /// Returns `Err` if there was a communication error with Dirk.
    async fn get_pubkey_account(&self, pubkey: BlsPublicKey) -> eyre::Result<Option<String>> {
        match self
            .accounts
            .iter()
            .find(|account| account.public_key.is_some_and(|account_pk| account_pk == pubkey))
        {
            Some(account) => Ok(Some(account.complete_name())),
            None => {
                let accounts = self.get_all_accounts().await?;

                for account in accounts {
                    if account.public_key == pubkey.to_vec() {
                        return Ok(Some(account.name));
                    }
                }

                Ok(None)
            }
        }
    }

    /// Returns the public keys of the config-registered accounts
    pub async fn consensus_pubkeys(&self) -> eyre::Result<Vec<BlsPublicKey>> {
        let registered_pubkeys = self
            .accounts
            .iter()
            .filter_map(|account| account.public_key)
            .collect::<Vec<BlsPublicKey>>();

        if registered_pubkeys.len() == self.accounts.len() {
            Ok(registered_pubkeys)
        } else {
            let accounts = self.get_all_accounts().await?;

            let expected_accounts: Vec<String> =
                self.accounts.iter().map(|account| account.complete_name()).collect();

            Ok(accounts
                .iter()
                .filter_map(|account| {
                    if expected_accounts.contains(&account.name) {
                        BlsPublicKey::try_from(account.public_key.as_slice()).ok()
                    } else {
                        None
                    }
                })
                .collect())
        }
    }

    /// Returns the public keys of all the proxy accounts found in Dirk.
    /// An account is considered a proxy if its name has the format
    /// `consensus_account/module_id/uuid`, where `consensus_account` is the
    /// name of a config-registered account.
    pub async fn proxies(&self) -> eyre::Result<Vec<BlsPublicKey>> {
        let accounts = self.get_all_accounts().await?;

        Ok(accounts
            .iter()
            .filter_map(|account| {
                if self.accounts.iter().any(|consensus_account| {
                    account.name.starts_with(&format!("{}/", consensus_account.complete_name()))
                }) {
                    BlsPublicKey::try_from(account.public_key.as_slice()).ok()
                } else {
                    None
                }
            })
            .collect())
    }

    /// Returns a mapping of the proxy accounts' pubkeys by consensus account,
    /// for a given module.
    /// An account is considered a proxy if its name has the format
    /// `consensus_account/module_id/uuid`, where `consensus_account` is the
    /// name of a config-registered account.
    pub async fn get_consensus_proxy_maps(
        &self,
        module_id: &ModuleId,
    ) -> eyre::Result<Vec<ConsensusProxyMap>> {
        let accounts = self.get_all_accounts().await?;

        let mut proxy_maps = Vec::new();

        for consensus_account in self.accounts.iter() {
            let Some(consensus_key) = consensus_account.public_key else {
                continue;
            };

            let proxy_keys = accounts
                .iter()
                .filter_map(|account| {
                    if account
                        .name
                        .starts_with(&format!("{}/{module_id}/", consensus_account.complete_name()))
                    {
                        BlsPublicKey::try_from(account.public_key.as_slice()).ok()
                    } else {
                        None
                    }
                })
                .collect::<Vec<BlsPublicKey>>();
            proxy_maps.push(ConsensusProxyMap {
                consensus: consensus_key,
                proxy_bls: proxy_keys,
                proxy_ecdsa: vec![],
            });
        }

        Ok(proxy_maps)
    }

    /// Generate a random password of 64 hex-characters
    fn random_password() -> String {
        let password_bytes: [u8; 32] = rand::thread_rng().gen();
        hex::encode(password_bytes)
    }

    /// Read the password for an account from a file
    fn read_password(&self, account: String) -> eyre::Result<String> {
        fs::read_to_string(self.secrets_path.join(account))
            .map_err(|e| eyre::eyre!("Couldn't read password: {e}"))
    }

    /// Store the password for an account in a file
    fn store_password(&self, account: String, password: String) -> eyre::Result<()> {
        fs::create_dir_all(
            self.secrets_path
                .join(account.rsplit_once("/").ok_or(eyre::eyre!("Invalid account name"))?.0),
        )
        .map_err(|e| eyre::eyre!("Couldn't write password: {e}"))?;
        fs::write(self.secrets_path.join(account), password)
            .map_err(|e| eyre::eyre!("Couldn't write password: {e}"))
    }

    async fn unlock_account(&self, account: String, password: String) -> eyre::Result<()> {
        let mut client = AccountManagerClient::new(self.channel.clone());
        let unlock_request = tonic::Request::new(UnlockAccountRequest {
            account,
            passphrase: password.as_bytes().to_vec(),
        });

        let unlock_response = client.unlock(unlock_request).await?;
        if unlock_response.get_ref().state() != ResponseState::Succeeded {
            eyre::bail!("Unlock request failed");
        }

        Ok(())
    }

    pub async fn generate_proxy_key(
        &self,
        module_id: ModuleId,
        consensus_pubkey: BlsPublicKey,
    ) -> eyre::Result<SignedProxyDelegation<BlsPublicKey>> {
        let uuid = uuid::Uuid::new_v4();

        let consensus_account = self
            .get_pubkey_account(consensus_pubkey)
            .await?
            .ok_or(eyre::eyre!("Consensus public key not found"))?;

        if !self
            .accounts
            .iter()
            .map(|account| account.complete_name())
            .collect::<Vec<String>>()
            .contains(&consensus_account)
        {
            eyre::bail!("Consensus public key is not from a registered account");
        }

        let account_name = format!("{consensus_account}/{module_id}/{uuid}");
        let new_password = Self::random_password();

        let mut client = AccountManagerClient::new(self.channel.clone());
        let generate_request = tonic::Request::new(GenerateRequest {
            account: account_name.clone(),
            passphrase: new_password.as_bytes().to_vec(),
            participants: 1,
            signing_threshold: 1,
        });

        let generate_response = client.generate(generate_request).await?;
        if generate_response.get_ref().state() != ResponseState::Succeeded {
            eyre::bail!("Generate request failed");
        }

        self.store_password(account_name.clone(), new_password.clone())?;

        let proxy_key =
            BlsPublicKey::try_from(generate_response.into_inner().public_key.as_slice())?;

        self.unlock_account(account_name, new_password).await?;

        let message = ProxyDelegation { delegator: consensus_pubkey, proxy: proxy_key };
        let signature =
            self.request_signature(consensus_pubkey, message.tree_hash_root().0).await?;
        let delegation = SignedProxyDelegation { message, signature };

        if let Some(store) = &self.proxy_store {
            store.store_proxy_bls_delegation(&module_id, &delegation)?;
        }

        Ok(delegation)
    }

    pub async fn request_signature(
        &self,
        pubkey: BlsPublicKey,
        object_root: [u8; 32],
    ) -> eyre::Result<BlsSignature> {
        let domain = compute_domain(self.chain, COMMIT_BOOST_DOMAIN);

        let mut signer_client = SignerClient::new(self.channel.clone());
        let sign_request = tonic::Request::new(SignRequest {
            id: Some(SignerId::PublicKey(pubkey.to_vec())),
            domain: domain.to_vec(),
            data: object_root.to_vec(),
        });

        let sign_response = signer_client.sign(sign_request).await?;

        // Retry if unlock config is set
        let sign_response = match sign_response.get_ref().state() {
            ResponseState::Denied if self.unlock => {
                info!("Account {pubkey:#} may be locked, unlocking and retrying...");

                let account_name = self
                    .get_pubkey_account(pubkey)
                    .await?
                    .ok_or(eyre::eyre!("Public key not found"))?;
                self.unlock_account(account_name.clone(), self.read_password(account_name)?)
                    .await?;

                let sign_request = tonic::Request::new(SignRequest {
                    id: Some(SignerId::PublicKey(pubkey.to_vec())),
                    domain: domain.to_vec(),
                    data: object_root.to_vec(),
                });
                signer_client.sign(sign_request).await?
            }
            _ => sign_response,
        };

        if sign_response.get_ref().state() != ResponseState::Succeeded {
            eyre::bail!("Sign request failed");
        }

        Ok(BlsSignature::from(FixedBytes::try_from(
            sign_response.into_inner().signature.as_slice(),
        )?))
    }
}

/// Get the accounts for the wallets passed as argument
async fn get_accounts_in_wallets(
    channel: Channel,
    wallets: Vec<String>,
) -> eyre::Result<Vec<DirkAccount>> {
    let mut client = ListerClient::new(channel);
    let pubkeys_request = tonic::Request::new(ListAccountsRequest { paths: wallets });
    let pubkeys_response = client.list_accounts(pubkeys_request).await?;

    if pubkeys_response.get_ref().state() != ResponseState::Succeeded {
        eyre::bail!("Get pubkeys request failed".to_string());
    }

    Ok(pubkeys_response.into_inner().accounts)
}
