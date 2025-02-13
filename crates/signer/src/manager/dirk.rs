use std::{fs, path::PathBuf};
use std::collections::HashMap;
use std::fmt::{Debug};
use alloy::{hex, primitives::FixedBytes};
use alloy::rpc::types::beacon::constants::BLS_SIGNATURE_BYTES_LEN;
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
use tracing::{info, trace};
use tree_hash::TreeHash;
use crate::{
    error::SignerModuleError::{self, DirkCommunicationError},
    proto::v1::{
        account_manager_client::AccountManagerClient, lister_client::ListerClient,
        sign_request::Id as SignerId, signer_client::SignerClient, Account as DirkAccount,
        GenerateRequest, ListAccountsRequest, ResponseState, SignRequest, UnlockAccountRequest,
    },
};
use crate::proto::v1::DistributedAccount;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

#[derive(Clone, Debug)]
enum WalletType {
    Simple,
    Distributed
}

#[derive(Clone, Debug)]
struct HostInfo {
    domain: String,
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
}


impl Account {
    pub fn complete_name(&self) -> String {
        format!("{}/{}", self.wallet, self.name)
    }
}


#[derive(Clone, Debug)]
pub struct DirkManager {
    chain: Chain,
    channels: HashMap<String, Channel>, // domain -> channel
    accounts: HashMap<String, Account>, // pubkey -> account
    unlock: bool,
    secrets_path: PathBuf,
    proxy_store: Option<ProxyStore>,
}

impl DirkManager {
    pub async fn new_from_config(chain: Chain, config: DirkConfig) -> eyre::Result<Self> {
        let mut tls_configs = Vec::new();

        // Create a TLS config for each host
        for host in config.hosts.clone() {
            let mut tls_config = ClientTlsConfig::new().identity(config.client_cert.clone());

            if let Some(ca) = &config.cert_auth {
                tls_config = tls_config.ca_certificate(ca.clone());
                trace!("Using custom CA certificate");
            }

            trace!(host.domain, "Using custom server domain");
            tls_config = tls_config.domain_name(host.domain.unwrap_or_default());

            tls_configs.push(tls_config);
        }

        // Create a channel for each host, attempt to connect,
        // and save it into a hashmap Host->Channel
        let mut channels = HashMap::new();
        for (i, tls_config) in tls_configs.iter().enumerate() {
            let config_host = config.hosts[i].clone();
            let domain = config_host.domain.unwrap_or_default();
            match Channel::from_shared(config_host.url.to_string())
                .map_err(|_| eyre::eyre!("Invalid Dirk URL"))?
                .tls_config(tls_config.clone())
                .map_err(|_| eyre::eyre!("Invalid Dirk TLS config"))?
                .connect()
                .await
            {
                Ok(ch) => {
                    channels.insert(domain, ch);
                }
                Err(e) => {
                    trace!("Couldn't connect to Dirk with domain {}: {e}", domain);
                }
            }
        }

        // TODO remove this, should use all channels later
        let channel = channels
            .values()
            .next()
            .ok_or_else(|| eyre::eyre!("Couldn't connect to Dirk with any of the domains"))?
            .clone();

        let mut accounts: HashMap<String, Account> = HashMap::new();


        for host in config.hosts {
            let domain = host.domain.unwrap_or_default();
            let channel = channels.get(&domain).ok_or(eyre::eyre!(
                "Couldn't connect to Dirk with domain {domain}"
            ))?.clone();

            let (dirk_accounts, dirk_distributed_accounts) = get_accounts_in_wallets(
                channel.clone(),
                host.accounts.iter()
                    .filter_map(|account| Some(account.split_once("/")?.0.to_string()))
                    .collect(),
            ).await?;

            for account_name in host.accounts.clone() {
                let (wallet, name) = account_name.split_once("/").ok_or(eyre::eyre!(
                    "Invalid account name: {account_name}. It must be in format wallet/account"
                ))?;

                // Handle simple accounts
                if let Some(dirk_account) = dirk_accounts.iter()
                    .find(|a| a.name == account_name)
                {
                    let public_key = BlsPublicKey::try_from(dirk_account.public_key.as_slice())?;
                    let key = hex::encode(public_key);
                    
                    accounts.insert(key, Account {
                        wallet: wallet.to_string(),
                        name: name.to_string(),
                        public_key: Some(public_key),
                        hosts: vec![HostInfo { domain: domain.clone(), participant_id: 1 }],
                        wallet_type: WalletType::Simple,
                        signing_threshold: 1,
                    });
                }

                // Handle distributed accounts
                if let Some(dist_account) = dirk_distributed_accounts.iter()
                    .find(|a| a.name == account_name)
                {
                    let public_key = BlsPublicKey::try_from(dist_account.composite_public_key.as_slice())?;
                    let key = hex::encode(public_key);
                    
                    // Find the participant ID for this host from the participants list
                    let participant_id = dist_account.participants.iter()
                        .find(|p| p.name == domain)
                        .map(|p| p.id)
                        .ok_or_else(|| eyre::eyre!("Host {} not found in distributed account participants", domain))?;
                    
                    accounts
                        .entry(key)
                        .and_modify(|account| {
                            if !account.hosts.iter().any(|host| host.domain == domain) {
                                account.hosts.push(HostInfo { 
                                    domain: domain.clone(), 
                                    participant_id,
                                });
                            }
                        })
                        .or_insert_with(|| Account {
                            wallet: wallet.to_string(),
                            name: name.to_string(),
                            public_key: Some(public_key),
                            hosts: vec![HostInfo { 
                                domain: domain.clone(), 
                                participant_id,
                            }],
                            wallet_type: WalletType::Distributed,
                            signing_threshold: dist_account.signing_threshold,
                        });
                }
            }
        }

        trace!(?accounts, "Accounts by host");

        Ok(Self {
            chain,
            channels,
            accounts,
            unlock: config.unlock,
            secrets_path: config.secrets_path,
            proxy_store: None,
        })
    }

    // TODO might be temporary, for testing
    pub fn accounts(&self) -> Vec<Account> {
        self.accounts.values().cloned().collect()
    }

    pub fn with_proxy_store(self, proxy_store: ProxyStore) -> eyre::Result<Self> {
        Ok(Self { proxy_store: Some(proxy_store), ..self })
    }

    /// Get all available accounts in the `self.accounts` wallets
    pub async fn get_all_accounts(&self) -> Result<Vec<DirkAccount>, SignerModuleError> {
        let mut all_accounts = Vec::new();
        
        // Query all channels and combine results
        for channel in self.channels.values() {
            let (accounts, _) = get_accounts_in_wallets(
                channel.clone(),
                self.accounts().iter().map(|account| account.wallet.clone()).collect(),
            )
            .await?;
            all_accounts.extend(accounts);
        }
        
        Ok(all_accounts)
    }

    /// Get the complete account name (`wallet/account`) for a public key.
    /// Returns `Ok(None)` if the account was not found.
    /// Returns `Err` if there was a communication error with Dirk.
    async fn get_pubkey_account(
        &self,
        pubkey: BlsPublicKey,
    ) -> Result<Option<String>, SignerModuleError> {
        match self
            .accounts()
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
            .accounts()
            .iter()
            .filter_map(|account| account.public_key)
            .collect::<Vec<BlsPublicKey>>();

        if registered_pubkeys.len() == self.accounts.len() {
            Ok(registered_pubkeys)
        } else {
            let accounts = self.get_all_accounts().await?;

            let expected_accounts: Vec<String> =
                self.accounts().iter().map(|account| account.complete_name()).collect();

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
                if self.accounts().iter().any(|consensus_account| {
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
    ) -> Result<Vec<ConsensusProxyMap>, SignerModuleError> {
        let accounts = self.get_all_accounts().await?;

        let mut proxy_maps = Vec::new();

        for consensus_account in self.accounts().iter() {
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

        fs::create_dir_all(account_dir.clone()).map_err(|err| {
            SignerModuleError::Internal(format!("error creating dir '{account_dir}': {err}"))
        })?;
        fs::write(self.secrets_path.join(format!("{account}.pass")), password).map_err(|err| {
            SignerModuleError::Internal(format!(
                "error writing password for account '{account}': {err}"
            ))
        })
    }

    // Helper method to get channel for a public key
    fn get_channel_for_pubkey(&self, pubkey: &BlsPublicKey) -> Result<Channel, SignerModuleError> {
        let key = hex::encode(pubkey);
        let account = self.accounts.get(&key).ok_or_else(|| 
            SignerModuleError::UnknownConsensusSigner(pubkey.to_vec())
        )?;
        
        // Get first available host's channel
        let domain = account.hosts.first().ok_or_else(|| 
            SignerModuleError::Internal("Account has no associated hosts".to_string())
        )?.domain.clone();
        
        self.channels.get(&domain).cloned().ok_or_else(||
            SignerModuleError::Internal(format!("No channel found for domain {}", domain))
        )
    }

    async fn unlock_account(
        &self,
        account: String,
        password: String,
    ) -> Result<(), SignerModuleError> {
        // Find the public key associated with this account name
        let account_entry = self.accounts.values().find(|a| a.complete_name() == account)
            .ok_or_else(|| SignerModuleError::Internal(format!("Account not found: {}", account)))?;
        
        let channel = self.get_channel_for_pubkey(
            account_entry.public_key.as_ref().ok_or_else(|| 
                SignerModuleError::Internal("Account has no public key".to_string())
            )?
        )?;

        trace!(account, "Sending AccountManager/Unlock request to Dirk");
        let mut client = AccountManagerClient::new(channel);
        let unlock_request = tonic::Request::new(UnlockAccountRequest {
            account: account.clone(),
            passphrase: password.as_bytes().to_vec(),
        });

        let unlock_response = client.unlock(unlock_request).await.map_err(|err| {
            DirkCommunicationError(format!("error unlocking account '{account}': {err}"))
        })?;
        if unlock_response.get_ref().state() != ResponseState::Succeeded {
            return Err(DirkCommunicationError(format!(
                "unlock request for '{account}' returned error"
            )));
        }

        Ok(())
    }

    pub async fn generate_proxy_key(
        &self,
        module_id: ModuleId,
        consensus_pubkey: BlsPublicKey,
    ) -> Result<SignedProxyDelegation<BlsPublicKey>, SignerModuleError> {
        let channel = self.get_channel_for_pubkey(&consensus_pubkey)?;
        let uuid = uuid::Uuid::new_v4();

        let consensus_account = self
            .get_pubkey_account(consensus_pubkey)
            .await?
            .ok_or(SignerModuleError::UnknownConsensusSigner(consensus_pubkey.to_vec()))?;

        if !self
            .accounts()
            .iter()
            .map(|account| account.complete_name())
            .collect::<Vec<String>>()
            .contains(&consensus_account)
        {
            return Err(SignerModuleError::UnknownConsensusSigner(consensus_pubkey.to_vec()))?;
        }

        let account_name = format!("{consensus_account}/{module_id}/{uuid}");
        let new_password = Self::random_password();

        trace!(account = account_name, "Sending AccountManager/Generate request to Dirk");

        let mut client = AccountManagerClient::new(channel.clone());
        let generate_request = tonic::Request::new(GenerateRequest {
            account: account_name.clone(),
            passphrase: new_password.as_bytes().to_vec(),
            participants: 1,
            signing_threshold: 1,
        });

        let generate_response = client
            .generate(generate_request)
            .await
            .map_err(|err| DirkCommunicationError(format!("error on generate request: {err}")))?;

        if generate_response.get_ref().state() != ResponseState::Succeeded {
            return Err(DirkCommunicationError("generate request returned error".to_string()));
        }

        self.store_password(account_name.clone(), new_password.clone())?;

        let proxy_key =
            BlsPublicKey::try_from(generate_response.into_inner().public_key.as_slice()).map_err(
                |_| DirkCommunicationError("return value is not a valid public key".to_string()),
            )?;

        self.unlock_account(account_name, new_password).await?;

        let message = ProxyDelegation { delegator: consensus_pubkey, proxy: proxy_key };
        let signature =
            self.request_signature(consensus_pubkey, message.tree_hash_root().0).await?;
        let delegation = SignedProxyDelegation { message, signature };

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
        let account = self.accounts.get(&key).ok_or_else(|| 
            SignerModuleError::UnknownConsensusSigner(pubkey.to_vec())
        )?;

        match account.wallet_type {
            WalletType::Simple => {
                // Existing simple account logic
                let channel = self.get_channel_for_pubkey(&pubkey)?;
                self.sign_with_channel(channel, pubkey, account, domain, object_root).await
            }
            WalletType::Distributed => {
                let mut signatures = Vec::new();
                let mut identifiers = Vec::new();
                let num_hosts_needed = account.signing_threshold as usize;

                if account.hosts.len() < num_hosts_needed {
                    return Err(SignerModuleError::Internal(format!(
                        "Not enough hosts available. Need {} but only have {}",
                        num_hosts_needed,
                        account.hosts.len()
                    )));
                }

                // Try to get signatures from hosts
                for host in &account.hosts {
                    if signatures.len() >= num_hosts_needed {
                        break;
                    }

                    let channel = self.channels.get(&host.domain).cloned().ok_or_else(||
                        SignerModuleError::Internal(format!("No channel found for host {}", host.domain))
                    )?;

                    match self.sign_with_channel(channel, pubkey, account, domain, object_root).await {
                        Ok(signature) => {
                            signatures.push(signature);
                            identifiers.push(host.participant_id);
                            trace!(
                                host = host.domain,
                                participant_id = host.participant_id,
                                "Got signature shard"
                            );
                        },
                        Err(e) => {
                            trace!("Failed to get signature from host {}: {}", host.domain, e);
                            continue;
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

                aggregate_partial_signatures(&signatures, &identifiers)
                    .ok_or_else(|| SignerModuleError::Internal(
                        "Failed to recover master signature from shards".to_string()))
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
            object_root = hex::encode(object_root),
            domain = hex::encode(domain),
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
                trace!(account = account_name, "Unlocking account");
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
    // Ensure the number of partial signatures matches the number of identifiers
    if partials.len() != identifiers.len() {
        trace!("aggregate_partial_signatures: Invalid number of partial signatures");
        return None;
    }

    // Deserialize partial signatures into G2 points
    let mut points = Vec::new();
    for sig in partials {
        if sig.len() != BLS_SIGNATURE_BYTES_LEN {
            trace!("aggregate_partial_signatures: Invalid signature length");
            return None;
        }
        let arr: [u8; BLS_SIGNATURE_BYTES_LEN] = (*sig).into();
        let opt: Option<G2Affine> = G2Affine::from_compressed(&arr).into();
        let opt: Option<G2Projective> = G2Projective::from(&opt.unwrap()).into();
        if let Some(point) = opt {
            points.push(point);
        } else {
            trace!("aggregate_partial_signatures: Failed to deserialize signature");
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
        for (other_id, _) in &shares {
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
