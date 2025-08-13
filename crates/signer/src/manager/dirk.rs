use std::{collections::HashMap, io::Write, path::PathBuf};

use alloy::{
    hex,
    primitives::{aliases::B32, B256},
    rpc::types::beacon::constants::BLS_SIGNATURE_BYTES_LEN,
};
use blsful::inner_types::{Field, G2Affine, G2Projective, Group, Scalar};
use cb_common::{
    commit::request::{ConsensusProxyMap, ProxyDelegation, SignedProxyDelegation},
    config::{DirkConfig, DirkHostConfig},
    constants::COMMIT_BOOST_DOMAIN,
    signature::compute_domain,
    signer::{BlsPublicKey, BlsSignature, ProxyStore},
    types::{self, Chain, ModuleId},
};
use eyre::{bail, OptionExt};
use futures::{future::join_all, stream::FuturesUnordered, FutureExt, StreamExt};
use rand::Rng;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{debug, error, warn};
use tree_hash::TreeHash;

use crate::{
    error::SignerModuleError,
    proto::v1::{
        account_manager_client::AccountManagerClient, lister_client::ListerClient, sign_request,
        signer_client::SignerClient, Endpoint, GenerateRequest, ListAccountsRequest, ResponseState,
        SignRequest, UnlockAccountRequest,
    },
};

#[derive(Clone, Debug)]
enum Account {
    Simple(SimpleAccount),
    Distributed(DistributedAccount),
}

impl Account {
    pub fn name(&self) -> &str {
        match self {
            Account::Simple(account) => &account.name,
            Account::Distributed(account) => &account.name,
        }
    }
}

#[derive(Clone, Debug)]
struct SimpleAccount {
    public_key: BlsPublicKey,
    connection: Channel,
    name: String,
}

#[derive(Clone, Debug)]
struct DistributedAccount {
    composite_public_key: BlsPublicKey,
    participants: HashMap<u32, Channel>,
    threshold: u32,
    name: String,
}

impl Account {
    pub fn public_key(&self) -> BlsPublicKey {
        match self {
            Account::Simple(account) => account.public_key,
            Account::Distributed(account) => account.composite_public_key,
        }
    }
}

#[derive(Clone, Debug)]
struct ProxyAccount {
    consensus: Account,
    module: ModuleId,
    inner: Account,
}

#[derive(Clone, Debug)]
pub struct DirkManager {
    /// Chain config for the manager
    chain: Chain,
    /// Consensus accounts available for signing. The key is the public key of
    /// the account.
    consensus_accounts: HashMap<BlsPublicKey, Account>,
    /// Proxy accounts available for signing. The key is the public key of the
    /// account.
    proxy_accounts: HashMap<BlsPublicKey, ProxyAccount>,
    /// Path to store the passwords of the proxy accounts
    secrets_path: PathBuf,
    /// Store to save proxy delegations
    delegations_store: Option<ProxyStore>,
}

impl DirkManager {
    pub async fn new(chain: Chain, config: DirkConfig) -> eyre::Result<Self> {
        let mut consensus_accounts = HashMap::new();

        for host in config.hosts {
            let channel = match connect(&host, &config.client_cert, &config.cert_auth).await {
                Ok(channel) => channel,
                Err(e) => {
                    warn!("Failed to connect to Dirk host {}: {e}", host.url);
                    continue;
                }
            };

            let accounts_response = match ListerClient::new(channel.clone())
                .list_accounts(ListAccountsRequest { paths: host.wallets.clone() })
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    warn!("Failed to list accounts in server {}: {e}", host.url);
                    continue;
                }
            };

            if accounts_response.get_ref().state() != ResponseState::Succeeded {
                warn!("Failed to list accounts in server {}", host.url);
                continue;
            }

            let accounts_response = accounts_response.into_inner();
            load_simple_accounts(accounts_response.accounts, &channel, &mut consensus_accounts);
            load_distributed_accounts(
                accounts_response.distributed_accounts,
                &host,
                &channel,
                &mut consensus_accounts,
            )
            .map_err(|error| warn!("{error}"))
            .ok();
        }

        debug!(
            "Loaded {} consensus accounts: {}",
            consensus_accounts.len(),
            consensus_accounts.keys().map(|k| k.to_string()).collect::<Vec<_>>().join(", ")
        );

        Ok(Self {
            chain,
            consensus_accounts,
            proxy_accounts: HashMap::new(),
            secrets_path: config.secrets_path,
            delegations_store: None,
        })
    }

    /// Set the proxy store to use for storing proxy delegations
    pub fn with_proxy_store(self, store: ProxyStore) -> eyre::Result<Self> {
        if let ProxyStore::ERC2335 { .. } = store {
            return Err(eyre::eyre!("ERC2335 proxy store not supported"));
        }

        Ok(Self { delegations_store: Some(store), ..self })
    }

    /// Get the number of available consensus signers
    pub fn available_consensus_signers(&self) -> usize {
        self.consensus_accounts.len()
    }

    /// Get the number of available proxy signers
    pub fn available_proxy_signers(&self) -> usize {
        self.proxy_accounts.len()
    }

    /// Get the map structure for `get_pubkey` endpoint
    pub fn get_consensus_proxy_maps(&self, module: &ModuleId) -> Vec<ConsensusProxyMap> {
        self.consensus_accounts
            .values()
            .map(|account| ConsensusProxyMap {
                consensus: account.public_key(),
                proxy_bls: self
                    .proxy_accounts
                    .values()
                    .filter_map(|proxy| {
                        if proxy.module == *module &&
                            proxy.consensus.public_key() == account.public_key()
                        {
                            Some(proxy.inner.public_key())
                        } else {
                            None
                        }
                    })
                    .collect(),
                // ECDSA is not supported
                proxy_ecdsa: Vec::new(),
            })
            .collect()
    }

    /// Request a signature from a consensus signer
    pub async fn request_consensus_signature(
        &self,
        pubkey: &BlsPublicKey,
        object_root: &B256,
        module_signing_id: Option<&B256>,
    ) -> Result<BlsSignature, SignerModuleError> {
        match self.consensus_accounts.get(pubkey) {
            Some(Account::Simple(account)) => {
                self.request_simple_signature(account, object_root, module_signing_id).await
            }
            Some(Account::Distributed(account)) => {
                self.request_distributed_signature(account, object_root, module_signing_id).await
            }
            None => Err(SignerModuleError::UnknownConsensusSigner(pubkey.to_vec())),
        }
    }

    /// Request a signature from a proxy signer
    pub async fn request_proxy_signature(
        &self,
        pubkey: &BlsPublicKey,
        object_root: &B256,
        module_signing_id: Option<&B256>,
    ) -> Result<BlsSignature, SignerModuleError> {
        match self.proxy_accounts.get(pubkey) {
            Some(ProxyAccount { inner: Account::Simple(account), .. }) => {
                self.request_simple_signature(account, object_root, module_signing_id).await
            }
            Some(ProxyAccount { inner: Account::Distributed(account), .. }) => {
                self.request_distributed_signature(account, object_root, module_signing_id).await
            }
            None => Err(SignerModuleError::UnknownProxySigner(pubkey.to_vec())),
        }
    }

    /// Sign a message with a `SimpleAccount`
    async fn request_simple_signature(
        &self,
        account: &SimpleAccount,
        object_root: &B256,
        module_signing_id: Option<&B256>,
    ) -> Result<BlsSignature, SignerModuleError> {
        let domain = compute_domain(self.chain, &B32::from(COMMIT_BOOST_DOMAIN));

        let data = match module_signing_id {
            Some(id) => types::PropCommitSigningInfo { data: *object_root, module_signing_id: *id }
                .tree_hash_root()
                .to_vec(),
            None => object_root.to_vec(),
        };

        let response = SignerClient::new(account.connection.clone())
            .sign(SignRequest {
                data,
                domain: domain.to_vec(),
                id: Some(sign_request::Id::PublicKey(account.public_key.to_vec())),
            })
            .await
            .map_err(|e| {
                SignerModuleError::DirkCommunicationError(format!("Failed to sign object: {e}"))
            })?;

        if response.get_ref().state() != ResponseState::Succeeded {
            return Err(SignerModuleError::DirkCommunicationError(
                "Failed to sign object, server responded error".to_string(),
            ));
        }

        BlsSignature::try_from(response.into_inner().signature.as_slice()).map_err(|_| {
            SignerModuleError::DirkCommunicationError("Failed to parse signature".to_string())
        })
    }

    /// Sign a message with a `DistributedAccount`
    async fn request_distributed_signature(
        &self,
        account: &DistributedAccount,
        object_root: &B256,
        module_signing_id: Option<&B256>,
    ) -> Result<BlsSignature, SignerModuleError> {
        let mut partials = Vec::with_capacity(account.participants.len());
        let mut requests = Vec::with_capacity(account.participants.len());

        let data = match module_signing_id {
            Some(id) => types::PropCommitSigningInfo { data: *object_root, module_signing_id: *id }
                .tree_hash_root()
                .to_vec(),
            None => object_root.to_vec(),
        };

        for (id, channel) in account.participants.iter() {
            let data_copy = data.clone();
            let request = async move {
                SignerClient::new(channel.clone())
                    .sign(SignRequest {
                        data: data_copy,
                        domain: compute_domain(self.chain, &B32::from(COMMIT_BOOST_DOMAIN))
                            .to_vec(),
                        id: Some(sign_request::Id::Account(account.name.clone())),
                    })
                    .map(|res| (res, *id))
                    .await
            };
            requests.push(request);
        }

        let mut requests = requests.into_iter().collect::<FuturesUnordered<_>>();

        while let Some((response, participant_id)) = requests.next().await {
            let response = match response {
                Ok(res) => res,
                Err(e) => {
                    warn!("Failed to sign object with participant {participant_id}: {e}");
                    continue;
                }
            };

            if response.get_ref().state() != ResponseState::Succeeded {
                warn!("Failed to sign object with participant {participant_id}");
                continue;
            }

            let signature = match BlsSignature::try_from(response.into_inner().signature.as_slice())
            {
                Ok(sig) => sig,
                Err(e) => {
                    warn!("Failed to parse signature from participant {participant_id}: {e}");
                    continue;
                }
            };

            partials.push((signature, participant_id));

            if partials.len() >= account.threshold as usize {
                break;
            }
        }

        if partials.len() < account.threshold as usize {
            return Err(SignerModuleError::DirkCommunicationError(
                "Failed to get enough partial signatures".to_string(),
            ));
        }

        aggregate_partial_signatures(partials.as_slice())
            .map_err(|e| SignerModuleError::Internal(e.to_string()))
    }

    /// Generate a proxy key for a consensus signer
    pub async fn generate_proxy_key(
        &mut self,
        module: &ModuleId,
        consensus: BlsPublicKey,
    ) -> Result<SignedProxyDelegation<BlsPublicKey>, SignerModuleError> {
        let proxy_account = match self.consensus_accounts.get(&consensus) {
            Some(Account::Simple(account)) => {
                self.generate_simple_proxy_account(account, module).await?
            }
            Some(Account::Distributed(account)) => {
                self.generate_distributed_proxy_key(account, module).await?
            }
            None => return Err(SignerModuleError::UnknownConsensusSigner(consensus.to_vec())),
        };

        let message =
            ProxyDelegation { delegator: consensus, proxy: proxy_account.inner.public_key() };
        let delegation_signature =
            self.request_consensus_signature(&consensus, &message.tree_hash_root(), None).await?;

        let delegation = SignedProxyDelegation { message, signature: delegation_signature };

        if let Some(store) = &self.delegations_store {
            store.store_proxy_bls_delegation(module, &delegation).map_err(|e| {
                warn!("Couldn't store delegation signature: {e}");
                SignerModuleError::Internal("Couldn't store delegation signature".to_string())
            })?;
        }

        self.proxy_accounts.insert(proxy_account.inner.public_key(), proxy_account.clone());

        Ok(delegation)
    }

    /// Generate a proxy key for a `SimpleAccount` consensus signer
    async fn generate_simple_proxy_account(
        &self,
        consensus: &SimpleAccount,
        module: &ModuleId,
    ) -> Result<ProxyAccount, SignerModuleError> {
        let uuid = uuid::Uuid::new_v4();
        let password = random_password();

        let response = AccountManagerClient::new(consensus.connection.clone())
            .generate(GenerateRequest {
                account: format!("{}/{module}/{uuid}", consensus.name),
                passphrase: password.as_bytes().to_vec(),
                participants: 1,
                signing_threshold: 1,
            })
            .await
            .map_err(|e| SignerModuleError::DirkCommunicationError(e.to_string()))?;

        if response.get_ref().state() != ResponseState::Succeeded {
            return Err(SignerModuleError::DirkCommunicationError(format!(
                "Failed to generate proxy key: {}",
                response.get_ref().message
            )));
        }

        let proxy_key = BlsPublicKey::try_from(response.into_inner().public_key.as_slice())
            .map_err(|_| {
                SignerModuleError::DirkCommunicationError("Failed to parse proxy key".to_string())
            })?;

        let proxy_account = ProxyAccount {
            consensus: Account::Simple(consensus.clone()),
            module: module.clone(),
            inner: Account::Simple(SimpleAccount {
                public_key: proxy_key,
                connection: consensus.connection.clone(),
                name: format!("{}/{module}/{uuid}", consensus.name),
            }),
        };

        self.store_password(&proxy_account, password.clone()).map_err(|e| {
            error!("Failed to store password: {e}");
            SignerModuleError::Internal("Failed to store password".to_string())
        })?;

        if let Err(e) = self.unlock_account(&proxy_account.inner, password).await {
            error!("{e}");
            return Err(SignerModuleError::DirkCommunicationError(
                "Failed to unlock new account".to_string(),
            ));
        }

        Ok(proxy_account)
    }

    /// Generate a proxy key for a `DistributedAccount` consensus signer
    async fn generate_distributed_proxy_key(
        &self,
        consensus: &DistributedAccount,
        module: &ModuleId,
    ) -> Result<ProxyAccount, SignerModuleError> {
        let uuid = uuid::Uuid::new_v4();
        let password = random_password();

        for (id, channel) in consensus.participants.iter() {
            let Ok(response) = AccountManagerClient::new(channel.clone())
                .generate(GenerateRequest {
                    account: format!("{}/{module}/{uuid}", consensus.name),
                    passphrase: password.as_bytes().to_vec(),
                    participants: consensus.participants.len() as u32,
                    signing_threshold: consensus.threshold,
                })
                .await
            else {
                warn!("Couldn't generate proxy key with participant {id}");
                continue;
            };

            if response.get_ref().state() != ResponseState::Succeeded {
                warn!("Couldn't generate proxy key with participant {id}");
                continue;
            }

            let Ok(proxy_key) = BlsPublicKey::try_from(response.into_inner().public_key.as_slice())
            else {
                warn!("Failed to parse proxy key with participant {id}");
                continue;
            };

            let proxy_account = ProxyAccount {
                consensus: Account::Distributed(consensus.clone()),
                module: module.clone(),
                inner: Account::Distributed(DistributedAccount {
                    composite_public_key: proxy_key,
                    participants: consensus.participants.clone(),
                    threshold: consensus.threshold,
                    name: format!("{}/{module}/{uuid}", consensus.name),
                }),
            };

            self.store_password(&proxy_account, password.clone()).map_err(|e| {
                error!("Failed to store password: {e}");
                SignerModuleError::Internal("Failed to store password".to_string())
            })?;

            if let Err(e) = self.unlock_account(&proxy_account.inner, password).await {
                error!("{e}");
                return Err(SignerModuleError::DirkCommunicationError(
                    "Failed to unlock new account".to_string(),
                ));
            }

            return Ok(proxy_account);
        }

        Err(SignerModuleError::DirkCommunicationError(
            "All participant connections failed".to_string(),
        ))
    }

    /// Store the password for a proxy account in disk
    fn store_password(&self, account: &ProxyAccount, password: String) -> eyre::Result<()> {
        let name = account.inner.name();
        let (parent, name) = name.rsplit_once('/').ok_or_eyre("Invalid account name")?;
        let parent_path = self.secrets_path.join(parent);

        std::fs::create_dir_all(parent_path.clone())?;
        let mut file = std::fs::File::create(parent_path.join(format!("{name}.pass")))?;
        file.write_all(password.as_bytes())?;

        Ok(())
    }

    /// Unlock an account in Dirk
    async fn unlock_account(&self, account: &Account, password: String) -> eyre::Result<()> {
        let participants = match account {
            Account::Simple(account) => vec![&account.connection],
            Account::Distributed(account) => account.participants.values().collect(),
        };

        let mut requests = Vec::with_capacity(participants.len());
        for channel in participants {
            let password = password.clone();
            let request = async move {
                let response = AccountManagerClient::new(channel.clone())
                    .unlock(UnlockAccountRequest {
                        account: account.name().to_string(),
                        passphrase: password.as_bytes().to_vec(),
                    })
                    .await;

                response.is_ok_and(|res| res.into_inner().state() == ResponseState::Succeeded)
            };

            requests.push(request);
        }

        let responses = join_all(requests).await;
        match account {
            Account::Simple(_) => {
                if responses.first().is_some_and(|x| *x) {
                    Ok(())
                } else {
                    bail!("Failed to unlock account")
                }
            }
            Account::Distributed(account) => {
                if responses.into_iter().filter(|x| *x).count() >= account.threshold as usize {
                    Ok(())
                } else {
                    bail!("Failed to get enough unlocks")
                }
            }
        }
    }
}

/// Connect to a Dirk host
async fn connect(
    server: &DirkHostConfig,
    client: &Identity,
    ca: &Option<Certificate>,
) -> eyre::Result<Channel> {
    let mut tls_config = ClientTlsConfig::new().identity(client.clone());
    if let Some(ca) = ca {
        tls_config = tls_config.ca_certificate(ca.clone());
    }
    if let Some(server_name) = &server.server_name {
        tls_config = tls_config.domain_name(server_name);
    }

    Channel::from_shared(server.url.to_string())
        .map_err(eyre::Error::from)?
        .tls_config(tls_config)
        .map_err(eyre::Error::from)?
        .connect()
        .await
        .map_err(eyre::Error::from)
}

/// Load `SimpleAccount`s into the consensus accounts map
fn load_simple_accounts(
    accounts: Vec<crate::proto::v1::Account>,
    channel: &Channel,
    consensus_accounts: &mut HashMap<BlsPublicKey, Account>,
) {
    for account in accounts {
        if name_matches_proxy(&account.name) {
            debug!(account = account.name, "Ignoring account assuming it's a proxy key");
            continue;
        }

        match BlsPublicKey::try_from(account.public_key.as_slice()) {
            Ok(public_key) => {
                consensus_accounts.insert(
                    public_key,
                    Account::Simple(SimpleAccount {
                        public_key,
                        connection: channel.clone(),
                        name: account.name,
                    }),
                );
            }
            Err(_) => {
                warn!("Failed to parse public key for account {}", account.name);
                continue;
            }
        }
    }
}

/// Load `DistributedAccount`s into the consensus accounts map
fn load_distributed_accounts(
    accounts: Vec<crate::proto::v1::DistributedAccount>,
    host: &DirkHostConfig,
    channel: &Channel,
    consensus_accounts: &mut HashMap<BlsPublicKey, Account>,
) -> eyre::Result<()> {
    let host_name = host
        .server_name
        .clone()
        .or_else(|| host.url.host_str().map(String::from))
        .ok_or(eyre::eyre!("Host name not found for server {}", host.url))?;

    for account in accounts {
        if name_matches_proxy(&account.name) {
            debug!(account = account.name, "Ignoring account assuming it's a proxy key");
            continue;
        }

        let Ok(public_key) = BlsPublicKey::try_from(account.composite_public_key.as_slice()) else {
            warn!("Failed to parse composite public key for account {}", account.name);
            continue;
        };

        let Some(&Endpoint { id: participant_id, .. }) =
            account.participants.iter().find(|participant| participant.name == host_name)
        else {
            warn!("Host {host_name} not found as participant for account {}", account.name);
            continue;
        };

        if participant_id == 0 {
            warn!(
                "Skiping invalid participant ID (0) for account {} in host {host_name}",
                account.name
            );
            continue
        }

        match consensus_accounts.get_mut(&public_key) {
            Some(Account::Distributed(DistributedAccount { participants, .. })) => {
                if participants.insert(participant_id as u32, channel.clone()).is_some() {
                    warn!(
                        "Duplicated participant ID ({participant_id}) for account {} in host {host_name}. Keeping this host",
                        account.name
                    );
                }
            }
            None => {
                let mut participants = HashMap::with_capacity(account.participants.len());
                participants.insert(participant_id as u32, channel.clone());

                consensus_accounts.insert(
                    public_key,
                    Account::Distributed(DistributedAccount {
                        composite_public_key: public_key,
                        participants,
                        threshold: account.signing_threshold,
                        name: account.name,
                    }),
                );
            }
            Some(Account::Simple(_)) => {
                bail!("Distributed public key already exists for simple account");
            }
        }
    }

    Ok(())
}

/// Aggregate partial signatures into a master signature
fn aggregate_partial_signatures(partials: &[(BlsSignature, u32)]) -> eyre::Result<BlsSignature> {
    // Deserialize partial signatures into G2 points
    let mut shares: HashMap<u32, G2Projective> = HashMap::new();
    for (signature, id) in partials {
        if signature.len() != BLS_SIGNATURE_BYTES_LEN {
            bail!("Invalid signature length")
        }
        let affine = G2Affine::from_compressed(signature)
            .into_option()
            .ok_or_eyre("Failed to deserialize signature")?;
        shares.insert(*id, G2Projective::from(&affine));
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
        let lagrange_coeff = numerator *
            denominator
                .invert()
                .into_option()
                .ok_or_eyre("Failed to get lagrange coefficient")?;

        // Multiply the point by the Lagrange coefficient and add to the recovered point
        recovered += *point * lagrange_coeff;
    }

    // Serialize the recovered point back into a BlsSignature
    let bytes = recovered.to_compressed();
    Ok(bytes.into())
}

/// Generate a random password of 64 hex-characters
fn random_password() -> String {
    let password_bytes: [u8; 32] = rand::rng().random();
    hex::encode(password_bytes)
}

/// Returns whether the name of an account has a proxy name format.
///
/// i.e., `{wallet}/{consensus_proxy}/{module}/{uuid}`
fn name_matches_proxy(name: &str) -> bool {
    name.split("/").count() > 3 &&
        name.rsplit_once("/").is_some_and(|(_, name)| uuid::Uuid::parse_str(name).is_ok())
}

mod test {

    #[test]
    fn test_signature_aggregation() {
        use alloy::hex;
        use cb_common::signer::BlsSignature;

        use super::aggregate_partial_signatures;

        let partials = vec![
            (BlsSignature::from_slice(&hex::decode("aa16233b9e65b596caf070122d564ad7a021dad4fc2ed8508fccecfab010da80892fad7336e9fbada607c50e2d0d78e00c9961f26618334ec9f0e7ea225212f3c0c7d66f73ff1c2e555712a3e31f517b8329bd0ad9e15a9aeaa91521ba83502c").unwrap()), 1),
            (BlsSignature::from_slice(&hex::decode("b27dd4c088e386edc4d07b6b23c72ba87a34e04cffd4975e8cb679aa4640cec1d34ace3e2bf33ac0dffca023c82422840012bb6c92eab36ca7908a9f9519fa18b1ed2bdbc624a98e01ca217c318a021495cc6cc9c8b982d0afed2cd83dc8fe65").unwrap()), 2),
            (BlsSignature::from_slice(&hex::decode("aca4a71373df2f76369e8b242b0e2b1f41fc384feee3abe605ee8d6723f5fb11de1c9bd2408f4a09be981342352c523801e3beea73893a329204dd67fe84cb520220af33f7fa027b6bcc3b7c8e78647f2aa372145e4d3aec7682d2605040a64a").unwrap()), 3)
        ];
        let expected = BlsSignature::from_slice(&hex::decode("0x8e343f074f91d19fd5118d9301768e30cecb21fb96a1ad9539cbdeae8907e2e12a88c91fe1d7e1f6995dcde18fb0272b1512cd68800e14ebd1c7f189e7221ba238a0f196226385737157f4b72d348c1886ce18d0a9609ba0cd5503e41546286f").unwrap());

        // With all signers
        let signature = aggregate_partial_signatures(&partials).unwrap();
        assert_eq!(signature, expected);

        // With only 2 signers
        let signature = aggregate_partial_signatures(&partials[..2]).unwrap();
        assert_eq!(signature, expected);

        // With other 2 signers
        let signature = aggregate_partial_signatures(&partials[1..]).unwrap();
        assert_eq!(signature, expected);

        // Should fail with only 1 signer
        let signature = aggregate_partial_signatures(&partials[..1]).unwrap();
        assert_ne!(signature, expected);
    }
}
