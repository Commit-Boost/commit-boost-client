use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    fs,
    path::PathBuf,
};

use alloy::{hex, primitives::FixedBytes, rpc::types::beacon::constants::BLS_SIGNATURE_BYTES_LEN};
use blsful::inner_types::{Field, G2Affine, G2Projective, Group, Scalar};
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
use tracing::{info, trace, warn};
use tree_hash::TreeHash;
use tokio::task::JoinSet;

use crate::{
    error::SignerModuleError::{self, DirkCommunicationError},
    proto::v1::{
        account_manager_client::AccountManagerClient, lister_client::ListerClient,
        sign_request::Id as SignerId, signer_client::SignerClient, Account as DirkAccount,
        DistributedAccount, GenerateRequest, ListAccountsRequest, ResponseState, SignRequest,
        UnlockAccountRequest,
    },
};

#[derive(Clone, Debug)]
enum WalletType {
    Simple,
    Distributed,
}

#[derive(Clone, Debug)]
struct HostInfo {
    server_name: String,
    participant_id: u64,
}

#[derive(Clone, Debug)]
struct Account {
    wallet: String,
    name: String,
    public_key: Option<BlsPublicKey>,
    hosts: Vec<HostInfo>,
    wallet_type: WalletType,
    signing_threshold: u32,
    is_proxy: bool,
}

impl Account {
    pub fn complete_name(&self) -> String {
        format!("{}/{}", self.wallet, self.name)
    }
}

#[derive(Clone, Debug)]
pub struct DirkManager {
    chain: Chain,
    channels: HashMap<String, Channel>, // server_name -> channel
    accounts: HashMap<String, Account>, // pubkey -> account
    unlock: bool,
    secrets_path: PathBuf,
    proxy_store: Option<ProxyStore>,
}

impl DirkManager {
    pub async fn new_from_config(chain: Chain, config: DirkConfig) -> eyre::Result<Self> {
        let mut tls_configs = Vec::with_capacity(config.hosts.len());

        // Create a TLS config for each host
        for host in config.hosts.clone() {
            let mut tls_config = ClientTlsConfig::new().identity(config.client_cert.clone());

            if let Some(ca) = &config.cert_auth {
                tls_config = tls_config.ca_certificate(ca.clone());
            } else {
                trace!(?host.server_name, "CA certificate for server name not found");
            }

            if let Some(server_name) = host.server_name.clone() {
                tls_config = tls_config.domain_name(server_name);
                tls_configs.push(tls_config);
            } else {
                trace!("Server name for host {0} not present", host.url);
            }
        }

        // Create a channel for each host, attempt to connect,
        // and save it into a hashmap Host->Channel
        let mut channels = HashMap::new();
        for (i, tls_config) in tls_configs.iter().enumerate() {
            let config_host = config.hosts[i].clone();
            let server_name = config_host.server_name.unwrap_or_default();
            match Channel::from_shared(config_host.url.to_string())
                .map_err(|_| eyre::eyre!("Invalid Dirk URL"))?
                .tls_config(tls_config.clone())
                .map_err(|_| eyre::eyre!("Invalid Dirk TLS config"))?
                .connect()
                .await
            {
                Ok(ch) => {
                    channels.insert(server_name, ch);
                }
                Err(e) => {
                    trace!("Couldn't connect to Dirk with server name {}: {e}", server_name);
                }
            }
        }

        let mut accounts: HashMap<String, Account> = HashMap::new();

        for host in config.hosts {
            let server_name = host.server_name.unwrap_or_default();
            let channel = channels
                .get(&server_name)
                .ok_or(eyre::eyre!("Couldn't connect to Dirk with server name {server_name}"))?
                .clone();

            let (dirk_accounts, dirk_distributed_accounts) = get_accounts_in_wallets(
                channel.clone(),
                host.accounts
                    .iter()
                    .filter_map(|account| Some(account.split_once("/")?.0.to_string()))
                    .collect(),
            )
            .await?;

            for account_name in host.accounts.clone() {
                let (wallet, _) = account_name.split_once("/").ok_or(eyre::eyre!(
                    "Invalid account name: {account_name}. It must be in format wallet/account"
                ))?;

                // Handle simple accounts
                for dirk_account in dirk_accounts.iter().filter(|a| {
                    a.name == account_name || a.name.starts_with(&format!("{}/", account_name))
                }) {
                    let public_key = BlsPublicKey::try_from(dirk_account.public_key.as_slice())?;
                    let key_name = dirk_account.name.split_once("/").map(|(_, n)| n).unwrap_or_default();
                    trace!(?dirk_account.name, "Adding account to hashmap");
                    
                    let is_proxy = is_proxy_key_name(key_name);

                    accounts.insert(hex::encode(public_key), Account {
                        wallet: wallet.to_string(),
                        name: key_name.to_string(),
                        public_key: Some(public_key),
                        hosts: vec![HostInfo { server_name: server_name.clone(), participant_id: 1 }],
                        wallet_type: WalletType::Simple,
                        signing_threshold: 1,
                        is_proxy,
                    });
                }

                // Handle distributed accounts
                for dist_account in dirk_distributed_accounts.iter().filter(|a| {
                    a.name == account_name || a.name.starts_with(&format!("{}/", account_name))
                }) {
                    let public_key = BlsPublicKey::try_from(dist_account.composite_public_key.as_slice())?;
                    let key_name = dist_account.name.split_once("/").map(|(_, n)| n).unwrap_or_default();
                    
                    let is_proxy = is_proxy_key_name(key_name);
                    
                    trace!(?dist_account.name, "Adding distributed account to hashmap");

                    // Find the participant ID for this host from the participants list
                    let participant_id = dist_account
                        .participants
                        .iter()
                        .find(|p| p.name == server_name)
                        .map(|p| p.id)
                        .ok_or_else(|| {
                            eyre::eyre!(
                                "Host {} not found in distributed account participants",
                                server_name
                            )
                        })?;

                    accounts
                        .entry(hex::encode(public_key))
                        .and_modify(|account| {
                            if !account.hosts.iter().any(|host| host.server_name == server_name) {
                                account
                                    .hosts
                                    .push(HostInfo { server_name: server_name.clone(), participant_id });
                            }
                        })
                        .or_insert_with(|| Account {
                            wallet: wallet.to_string(),
                            name: key_name.to_string(),
                            public_key: Some(public_key),
                            hosts: vec![HostInfo { server_name: server_name.clone(), participant_id }],
                            wallet_type: WalletType::Distributed,
                            signing_threshold: dist_account.signing_threshold,
                            is_proxy,
                        });
                }
            }
        }

        Ok(Self {
            chain,
            channels,
            accounts,
            unlock: config.unlock,
            secrets_path: config.secrets_path,
            proxy_store: None,
        })
    }

    fn accounts(&self) -> Vec<Account> {
        self.accounts.values().cloned().collect()
    }

    fn accounts_non_proxy(&self) -> Vec<Account> {
        self.accounts.values().filter(|a| !a.is_proxy).cloned().collect()
    }

    pub fn with_proxy_store(self, proxy_store: ProxyStore) -> eyre::Result<Self> {
        Ok(Self { proxy_store: Some(proxy_store), ..self })
    }

    /// Get the complete account name (`wallet/account`) for a public key.
    /// Returns `Ok(None)` if the account was not found.
    /// Returns `Err` if there was a communication error with Dirk.
    fn get_pubkey_account(
        &self,
        pubkey: BlsPublicKey,
    ) -> Option<String> {
        match self
            .accounts()
            .iter()
            .find(|account|
                      account.public_key.is_some_and(|account_pk| account_pk == pubkey)) {
                Some(account) => Some(account.complete_name()),
                None => None,
            }
    }

    /// Returns the public keys of the config-registered accounts
    pub async fn consensus_pubkeys(&self) -> Vec<BlsPublicKey> {
        self
            .accounts_non_proxy()
            .iter()
            .filter_map(|account| account.public_key)
            .collect::<Vec<BlsPublicKey>>()
    }

    /// Returns the public keys of all the proxy accounts found in Dirk.
    /// An account is considered a proxy if its name has the format
    /// `consensus_account/module_id/uuid`, where `consensus_account` is the
    /// name of a config-registered account.
    pub async fn proxies(&self) -> Vec<BlsPublicKey> {
        self
            .accounts()
            .iter()
            .filter(|account| account.is_proxy)
            .filter_map(|account| account.public_key)
            .collect::<Vec<BlsPublicKey>>()
    }

    /// Returns a mapping of the proxy accounts' pubkeys by consensus account,
    /// for a given module.
    /// An account is considered a proxy if its name has the format
    /// `consensus_account/module_id/uuid`, where `consensus_account` is the
    /// name of a config-registered account.
    pub async fn get_consensus_proxy_maps(
        &self,
        module_id: &ModuleId,
    ) -> Result<Vec<ConsensusProxyMap>, SignerModuleError> {
        let consensus_accounts = self.accounts_non_proxy();
        let accounts = self.accounts();
        let proxy_accounts: Vec<_> = accounts
            .iter()
            .filter(|account| account.is_proxy)
            .collect();

        let mut proxy_maps = Vec::new();
        for consensus_account in consensus_accounts {
            let Some(consensus_key) = consensus_account.public_key else {
                trace!("get_consensus_proxy_maps: skipping");
                continue;
            };
            let mut proxy_keys: Vec<BlsPublicKey> = vec![];
            let start_of_proxy_name = format!("{}/{module_id}", consensus_account.complete_name());
            for proxy in &proxy_accounts {
                trace!(%proxy.name, %start_of_proxy_name, "get_consensus_proxy_maps: checking if name starts with");
                if proxy.complete_name().starts_with(&start_of_proxy_name) {
                    if let Some(pubkey) = proxy.public_key {
                        proxy_keys.push(pubkey);
                    }
                }
            }
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
    fn read_password(&self, account: String) -> Result<String, SignerModuleError> {
        let path = self.secrets_path.join(format!("{account}.pass"));
        trace!(path = ?path, "Reading password from file");
        fs::read_to_string(self.secrets_path.join(format!("{account}.pass"))).map_err(|err| {
            SignerModuleError::Internal(format!(
                "error reading password for account '{account}': {err}"
            ))
        })
    }

    /// Store the password for an account in a file
    fn store_password(&self, account: String, password: String) -> Result<(), SignerModuleError> {
        let account_dir = self
            .secrets_path
            .join(
                account
                    .rsplit_once("/")
                    .ok_or(SignerModuleError::Internal(format!(
                        "account name '{account}' is invalid"
                    )))?
                    .0,
            )
            .to_string_lossy()
            .to_string();
        trace!(%account_dir, "Storing password in file");

        fs::create_dir_all(account_dir.clone()).map_err(|err| {
            SignerModuleError::Internal(format!("error creating dir '{account_dir}': {err}"))
        })?;
        fs::write(self.secrets_path.join(format!("{account}.pass")), password).map_err(|err| {
            SignerModuleError::Internal(format!(
                "error writing password for account '{account}': {err}"
            ))
        })
    }

    /// Get the associated channel for a public key
    fn get_channel_for_pubkey(&self, pubkey: &BlsPublicKey) -> Result<Channel, SignerModuleError> {
        trace!(%pubkey, "Getting channel for public key");
        let key = hex::encode(pubkey);
        let account = self
            .accounts
            .get(&key)
            .ok_or_else(|| SignerModuleError::UnknownConsensusSigner(pubkey.to_vec()))?;

        // Try to find any available host's channel
        for host in &account.hosts {
            if let Some(channel) = self.channels.get(&host.server_name) {
                return Ok(channel.clone());
            }
        }

        Err(SignerModuleError::Internal("No available channel found for any host".to_string()))
    }

    /// Unlock an account. For distributed accounts this is done for all it's
    /// hosts.
    async fn unlock_account(
        &self,
        account: String,
        password: String,
    ) -> Result<(), SignerModuleError> {
        let account_entry =
            self.accounts.values().find(|a| a.complete_name() == account).ok_or_else(|| {
                SignerModuleError::Internal(format!("Account not found: {}", account))
            })?;

        match account_entry.wallet_type {
            WalletType::Distributed => {
                // For distributed accounts, unlock on all hosts
                for host in &account_entry.hosts {
                    if let Some(channel) = self.channels.get(&host.server_name) {
                        self.unlock_account_on_channel(
                            channel,
                            &account,
                            &password,
                            Some(&host.server_name),
                        )
                        .await?;
                    }
                }
            }
            WalletType::Simple => {
                // For simple accounts, unlock on a single host
                let channel =
                    self.get_channel_for_pubkey(account_entry.public_key.as_ref().ok_or_else(
                        || SignerModuleError::Internal("Account has no public key".to_string()),
                    )?)?;
                self.unlock_account_on_channel(&channel, &account, &password, None).await?;
            }
        }
        Ok(())
    }

    /// Unlock an account on a specific channel
    async fn unlock_account_on_channel(
        &self,
        channel: &Channel,
        account: &str,
        password: &str,
        host_domain: Option<&str>,
    ) -> Result<(), SignerModuleError> {
        trace!(account, host = host_domain, "unlock_account_on_channel");
        const MAX_RETRIES: u32 = 5;
        let mut retry_count = 0;

        loop {
            let mut client = AccountManagerClient::new(channel.clone());
            let unlock_request = tonic::Request::new(UnlockAccountRequest {
                account: account.to_string(),
                passphrase: password.as_bytes().to_vec(),
            });

            match client.unlock(unlock_request).await {
                Ok(unlock_response) => {
                    if unlock_response.get_ref().state() == ResponseState::Succeeded {
                        return Ok(());
                    }
                    // We have connected but an error has been returned
                    let err = unlock_response.get_ref();
                    warn!(?err, "unlock_account_on_channel error response");
                    return Err(DirkCommunicationError(
                        "unlock_account_on_channel error response received".to_string(),
                    ));
                }
                Err(status) => {
                    retry_count += 1;
                    if retry_count >= MAX_RETRIES {
                        return Err(DirkCommunicationError(format!(
                            "Failed to connect after {MAX_RETRIES} attempts: {status}"
                        )));
                    }

                    warn!(
                        ?status,
                        retry_count,
                        host = host_domain,
                        "Connection failed, retrying in 3 seconds..."
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
            }
        }
    }

    pub async fn generate_proxy_key(
        &mut self,
        module_id: ModuleId,
        consensus_pubkey: BlsPublicKey,
    ) -> Result<SignedProxyDelegation<BlsPublicKey>, SignerModuleError> {
        let consensus_account = self
            .get_pubkey_account(consensus_pubkey)
            .ok_or(SignerModuleError::UnknownConsensusSigner(consensus_pubkey.to_vec()))?;

        let consensus_account_info = self
            .accounts()
            .into_iter()
            .find(|account| account.complete_name() == consensus_account)
            .ok_or_else(|| SignerModuleError::UnknownConsensusSigner(consensus_pubkey.to_vec()))?;

        let uuid = uuid::Uuid::new_v4();
        let account_name = format!("{consensus_account}/{module_id}/{uuid}");
        let new_password = Self::random_password();

        match consensus_account_info.wallet_type {
            WalletType::Simple => {
                trace!(account = account_name, "Sending AccountManager/Generate request to Dirk");
                let channel = self.get_channel_for_pubkey(&consensus_pubkey)?;
                let proxy_key = make_generate_proxy_request(
                    GenerateRequest {
                        account: account_name.clone(),
                        passphrase: new_password.as_bytes().to_vec(),
                        participants: 1,
                        signing_threshold: 1,
                    },
                    channel.clone(),
                )
                .await?;

                // Store the password for future use
                self.store_password(account_name.clone(), new_password.clone())?;

                // Get the consensus account info to copy host information
                let consensus_account =
                    self.accounts.get(&hex::encode(consensus_pubkey)).ok_or_else(|| {
                        SignerModuleError::UnknownConsensusSigner(consensus_pubkey.to_vec())
                    })?;

                let first_host = consensus_account.hosts.first().ok_or_else(|| {
                    SignerModuleError::Internal(
                        "Consensus account has no associated hosts".to_string(),
                    )
                })?;

                // Remove the wallet part from the name
                let account_name_without_wallet =
                    String::from(account_name.split_once("/").map(|(_, n)| n).unwrap_or_default());

                let delegation = self
                    .insert_proxy_account(proxy_key, consensus_pubkey, module_id, Account {
                        wallet: consensus_account.wallet.clone(),
                        name: account_name_without_wallet.clone(),
                        public_key: Some(proxy_key),
                        hosts: vec![HostInfo {
                            server_name: first_host.server_name.clone(),
                            participant_id: first_host.participant_id,
                        }],
                        wallet_type: WalletType::Simple,
                        signing_threshold: 1,
                        is_proxy: true,
                    })
                    .await?;

                // Unlock the account for immediate use
                self.unlock_account(account_name, new_password).await?;

                Ok(delegation)
            }
            WalletType::Distributed => {
                // Pick the first available host to generate the key, Dirk will handle the
                // peers.
                let host = consensus_account_info.hosts.first().ok_or_else(|| {
                    SignerModuleError::Internal(
                        "No hosts available for consensus account".to_string(),
                    )
                })?;
                let channel = self.channels.get(&host.server_name).cloned().ok_or_else(|| {
                    SignerModuleError::Internal(format!(
                        "No channel found for host {}",
                        host.server_name
                    ))
                })?;

                trace!(host = host.server_name, "Sending generate request for distributed proxy key");
                let proxy_key = make_generate_proxy_request(
                    GenerateRequest {
                        account: account_name.clone(),
                        passphrase: new_password.as_bytes().to_vec(),
                        participants: consensus_account_info.hosts.len() as u32,
                        signing_threshold: consensus_account_info.signing_threshold,
                    },
                    channel.clone(),
                )
                .await?;
                // Store the password for future use
                self.store_password(account_name.clone(), new_password.clone())?;

                let consensus_name = consensus_account_info.name;
                let delegation = self
                    .insert_proxy_account(proxy_key, consensus_pubkey, module_id.clone(), Account {
                        wallet: consensus_account_info.wallet.clone(),
                        name: format!("{consensus_name}/{module_id}/{uuid}"),
                        public_key: Some(proxy_key),
                        hosts: consensus_account_info.hosts.clone(),
                        wallet_type: WalletType::Distributed,
                        signing_threshold: consensus_account_info.signing_threshold,
                        is_proxy: true,
                    })
                    .await?;

                Ok(delegation)
            }
        }
    }

    async fn insert_proxy_account(
        &mut self,
        proxy_key: BlsPublicKey,
        delegator: BlsPublicKey,
        module_id: ModuleId,
        account: Account,
    ) -> Result<SignedProxyDelegation<BlsPublicKey>, SignerModuleError> {
        let hashmap_key = hex::encode(proxy_key);
        self.accounts.insert(hashmap_key.clone(), account);
        let added = self.accounts.get(&hashmap_key).ok_or(SignerModuleError::Internal(
            "Failed to add new proxy account to accounts map".to_string(),
        ))?;
        trace!(?hashmap_key, ?added, "Proxy account added");

        // Get delegation signature from the consensus account
        let message = ProxyDelegation { delegator, proxy: proxy_key };
        let signature = self.request_signature(delegator, message.tree_hash_root().0).await?;
        let delegation: SignedProxyDelegation<BlsPublicKey> =
            SignedProxyDelegation { message, signature };

        if let Some(store) = &self.proxy_store {
            store.store_proxy_bls_delegation(&module_id, &delegation).map_err(|err| {
                SignerModuleError::Internal(format!("error storing delegation signature: {err}"))
            })?;
        }

        Ok(delegation)
    }

    pub async fn request_signature(
        &self,
        pubkey: BlsPublicKey,
        object_root: [u8; 32],
    ) -> Result<BlsSignature, SignerModuleError> {
        let domain = compute_domain(self.chain, COMMIT_BOOST_DOMAIN);
        let key = hex::encode(pubkey);
        let account = self
            .accounts
            .get(&key)
            .ok_or_else(|| SignerModuleError::UnknownConsensusSigner(pubkey.to_vec()))?
            .clone();

        match account.wallet_type {
            WalletType::Simple => {
                let channel = self.get_channel_for_pubkey(&pubkey)?;
                self.sign_with_channel(channel, pubkey, &account, domain, object_root).await
            }
            WalletType::Distributed => {
                let num_hosts_needed = account.signing_threshold as usize;

                if account.hosts.len() < num_hosts_needed {
                    return Err(SignerModuleError::Internal(format!(
                        "Not enough hosts available. Need {} but only have {}",
                        num_hosts_needed,
                        account.hosts.len()
                    )));
                }

                let mut set = JoinSet::new();
                
                // Spawn tasks for each host
                for host in &account.hosts {
                    let Some(channel) = self.channels.get(&host.server_name).cloned() else {
                        continue;
                    };
                    let dirk = self.clone();
                    let account = account.clone();
                    let server_name = host.server_name.clone();
                    let participant_id = host.participant_id;

                    set.spawn(async move {
                        trace!(host = server_name, "Requesting signature shard for creating proxy");

                        match dirk
                            .sign_with_channel(channel, pubkey, &account, domain, object_root)
                            .await
                        {
                            Ok(signature) => {
                                trace!(
                                    host = server_name,
                                    participant_id = participant_id,
                                    "Got signature shard"
                                );
                                Ok((signature, participant_id))
                            }
                            Err(e) => {
                                warn!("Failed to get signature from host {}: {}", server_name, e);
                                Err(e)
                            }
                        }
                    });
                }

                let mut signatures = Vec::new();
                let mut identifiers = Vec::new();

                // Collect results until we have enough signatures
                while let Some(result) = set.join_next().await {
                    // Check if we already have enough signatures before processing more
                    if signatures.len() >= num_hosts_needed {
                        trace!("Already have enough signatures ({}/{}), cancelling remaining tasks", 
                            signatures.len(), num_hosts_needed);
                        set.abort_all();
                        break;
                    }

                    if let Ok(Ok((signature, id))) = result {
                        signatures.push(signature);
                        identifiers.push(id);
                        trace!("Got signature {}/{}", signatures.len(), num_hosts_needed);

                        if signatures.len() >= num_hosts_needed {
                            trace!("Already have enough signatures ({}/{}), cancelling remaining tasks",
                                signatures.len(), num_hosts_needed);
                            set.abort_all();
                            break;
                        }
                    }
                }

                if signatures.len() < num_hosts_needed {
                    return Err(SignerModuleError::Internal(format!(
                        "Could not collect enough signatures. Need {} but only got {}",
                        num_hosts_needed,
                        signatures.len()
                    )));
                }

                trace!(
                    num_shards = signatures.len(),
                    ?identifiers,
                    "Recovering master signature from shards"
                );

                aggregate_partial_signatures(&signatures, &identifiers).ok_or_else(|| {
                    SignerModuleError::Internal(
                        "Failed to recover master signature from shards".to_string(),
                    )
                })
            }
        }
    }

    // Helper method to sign with a specific channel
    async fn sign_with_channel(
        &self,
        channel: Channel,
        pubkey: BlsPublicKey,
        account: &Account,
        domain: [u8; 32],
        object_root: [u8; 32],
    ) -> Result<BlsSignature, SignerModuleError> {
        let id = match account.wallet_type {
            WalletType::Simple => SignerId::PublicKey(pubkey.to_vec()),
            WalletType::Distributed => SignerId::Account(account.complete_name()),
        };

        trace!(
            %pubkey,
            ?id,
            is_proxy = account.is_proxy,
            wallet_type = ?account.wallet_type,
            "Sending Signer/Sign request to Dirk"
        );

        let mut signer_client = SignerClient::new(channel.clone());
        let sign_request = tonic::Request::new(SignRequest {
            id: Some(id.clone()),
            domain: domain.to_vec(),
            data: object_root.to_vec(),
        });

        let sign_response = signer_client
            .sign(sign_request)
            .await
            .map_err(|err| DirkCommunicationError(format!("error on sign request: {err}")))?;

        // Retry if unlock config is set
        let sign_response = match sign_response.get_ref().state() {
            ResponseState::Denied if self.unlock => {
                info!("Failed to sign message, account {pubkey:#} may be locked. Unlocking and retrying.");

                let account_name = account.complete_name();
                self.unlock_account(
                    account_name.clone(),
                    self.read_password(account_name.clone())?,
                )
                .await?;

                let sign_request = tonic::Request::new(SignRequest {
                    id: Some(id),
                    domain: domain.to_vec(),
                    data: object_root.to_vec(),
                });
                signer_client.sign(sign_request).await.map_err(|err| {
                    DirkCommunicationError(format!("error on sign request: {err}"))
                })?
            }
            _ => sign_response,
        };

        if sign_response.get_ref().state() != ResponseState::Succeeded {
            return Err(DirkCommunicationError("sign request returned error".to_string()));
        }

        Ok(BlsSignature::from(
            FixedBytes::try_from(sign_response.into_inner().signature.as_slice()).map_err(
                |_| DirkCommunicationError("return value is not a valid signature".to_string()),
            )?,
        ))
    }
}

/// Get the accounts for the wallets passed as argument
async fn get_accounts_in_wallets(
    channel: Channel,
    wallets: Vec<String>,
) -> Result<(Vec<DirkAccount>, Vec<DistributedAccount>), SignerModuleError> {
    trace!(?wallets, "Sending Lister/ListAccounts request to Dirk");

    let mut client = ListerClient::new(channel);
    let pubkeys_request = tonic::Request::new(ListAccountsRequest { paths: wallets });
    let pubkeys_response = client
        .list_accounts(pubkeys_request)
        .await
        .map_err(|err| DirkCommunicationError(format!("error listing accounts: {err}")))?;

    if pubkeys_response.get_ref().state() != ResponseState::Succeeded {
        return Err(DirkCommunicationError("list accounts request returned error".to_string()));
    }

    let inner = pubkeys_response.into_inner();
    Ok((inner.accounts, inner.distributed_accounts))
}

pub fn aggregate_partial_signatures(
    partials: &[BlsSignature],
    identifiers: &[u64],
) -> Option<BlsSignature> {
    trace!("Aggregating partial signatures");
    // Ensure the number of partial signatures matches the number of identifiers
    if partials.len() != identifiers.len() {
        warn!("aggregate_partial_signatures: Invalid number of partial signatures");
        return None;
    }

    // Deserialize partial signatures into G2 points
    let mut points = Vec::new();
    for sig in partials {
        if sig.len() != BLS_SIGNATURE_BYTES_LEN {
            warn!("aggregate_partial_signatures: Invalid signature length");
            return None;
        }
        let arr: [u8; BLS_SIGNATURE_BYTES_LEN] = (*sig).into();
        let opt: Option<G2Affine> = G2Affine::from_compressed(&arr).into();
        let opt: Option<G2Projective> = G2Projective::from(&opt.unwrap()).into();
        if let Some(point) = opt {
            points.push(point);
        } else {
            warn!("aggregate_partial_signatures: Failed to deserialize signature");
            return None;
        }
    }

    // Create a map of identifiers to their corresponding points
    let mut shares: HashMap<u64, &G2Projective> = HashMap::new();
    for (id, point) in identifiers.iter().zip(points.iter()) {
        shares.insert(*id, point);
    }

    // Perform Lagrange interpolation to recover the master signature
    let mut recovered = G2Projective::identity();
    for (id, point) in &shares {
        // Compute the Lagrange coefficient for this identifier
        let mut numerator = Scalar::from(1u32);
        let mut denominator = Scalar::from(1u32);
        for other_id in shares.keys() {
            if other_id != id {
                numerator *= Scalar::from(*other_id);
                denominator *= Scalar::from(*other_id) - Scalar::from(*id);
            }
        }
        let lagrange_coeff = numerator * denominator.invert().unwrap();

        // Multiply the point by the Lagrange coefficient and add to the recovered point
        recovered += **point * lagrange_coeff;
    }

    // Serialize the recovered point back into a BlsSignature
    let bytes = recovered.to_compressed();
    Some(bytes.into())
}

async fn make_generate_proxy_request(
    request: GenerateRequest,
    channel: Channel,
) -> Result<BlsPublicKey, SignerModuleError> {
    let mut client = AccountManagerClient::new(channel.clone());
    let response = client
        .generate(request)
        .await
        .map_err(|err| DirkCommunicationError(format!("error on generate request: {err}")))?;
    if response.get_ref().state() != ResponseState::Succeeded {
        return Err(DirkCommunicationError("generate request returned error".to_string()));
    }
    trace!(?response, "Generated new proxy key");
    let proxy_key =
        BlsPublicKey::try_from(response.into_inner().public_key.as_slice()).map_err(|_| {
            DirkCommunicationError("return value is not a valid public key".to_string())
        })?;
    Ok(proxy_key)
}

/// Checks if a key name follows the proxy pattern <consensus>/<module_id>/<uuid>
fn is_proxy_key_name(key_name: &str) -> bool {
    key_name.split('/').count() == 3 && {
        let parts: Vec<&str> = key_name.split('/').collect();
        uuid::Uuid::parse_str(parts[2]).is_ok() // Verify the last part is a valid UUID
    }
}
