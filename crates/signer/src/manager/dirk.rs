use std::{collections::HashMap, io::Write, path::PathBuf};

use alloy::{
    hex, rpc::types::beacon::constants::BLS_SIGNATURE_BYTES_LEN, transports::http::reqwest::Url,
};
use blsful::inner_types::{Field, G2Affine, G2Projective, Group, Scalar};
use cb_common::{
    commit::request::{ConsensusProxyMap, ProxyDelegation, SignedProxyDelegation},
    config::{DirkConfig, DirkHostConfig},
    constants::COMMIT_BOOST_DOMAIN,
    signature::compute_domain,
    signer::{BlsPublicKey, BlsSignature, ProxyStore},
    types::{Chain, ModuleId},
};
use eyre::bail;
use futures::{stream::FuturesUnordered, FutureExt, StreamExt};
use rand::Rng;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{debug, error, warn};
use tree_hash::TreeHash;

use crate::{
    error::SignerModuleError,
    proto::v1::{
        account_manager_client::AccountManagerClient, lister_client::ListerClient, sign_request,
        signer_client::SignerClient, Endpoint, GenerateRequest, ListAccountsRequest, ResponseState,
        SignRequest,
    },
};

#[derive(Clone, Debug)]
struct CertConfig {
    ca: Option<Certificate>,
    client: Identity,
}

#[derive(Clone, Debug)]
enum Account {
    Simple(SimpleAccount),
    Distributed(DistributedAccount),
}

impl Account {
    pub fn full_name(&self) -> String {
        match self {
            Account::Simple(account) => format!("{}/{}", account.wallet, account.name),
            Account::Distributed(account) => format!("{}/{}", account.wallet, account.name),
        }
    }
}

#[derive(Clone, Debug)]
struct SimpleAccount {
    public_key: BlsPublicKey,
    server: Url,
    wallet: String,
    name: String,
}

#[derive(Clone, Debug)]
struct DistributedAccount {
    composite_public_key: BlsPublicKey,
    participants: HashMap<u32, Url>,
    threshold: u32,
    wallet: String,
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
    chain: Chain,
    certs: CertConfig,
    connections: HashMap<Url, Channel>,
    consensus_accounts: HashMap<BlsPublicKey, Account>,
    proxy_accounts: HashMap<BlsPublicKey, ProxyAccount>,
    secrets_path: PathBuf,
    delegations_store: Option<ProxyStore>,
}

impl DirkManager {
    pub async fn new(chain: Chain, config: DirkConfig) -> eyre::Result<Self> {
        let certs = CertConfig { ca: config.cert_auth, client: config.client_cert };

        let mut connections = HashMap::with_capacity(config.hosts.len());
        let mut consensus_accounts = HashMap::new();

        for host in config.hosts {
            let Some(host_name) = host.name() else {
                warn!("Host name not found for server {}", host.url);
                continue;
            };

            let channel = match connect(&host, &certs).await {
                Ok(channel) => channel,
                Err(e) => {
                    warn!("Failed to connect to Dirk host {}: {e}", host.url);
                    continue;
                }
            };

            connections.insert(host.url.clone(), channel.clone());

            // TODO: Improve to minimize requests
            for account_name in host.accounts {
                let Ok((wallet, name)) = decompose_name(&account_name) else {
                    warn!("Invalid account name {account_name}");
                    continue;
                };

                let response = match ListerClient::new(channel.clone())
                    .list_accounts(ListAccountsRequest { paths: vec![account_name.clone()] })
                    .await
                {
                    Ok(res) => res,
                    Err(e) => {
                        warn!("Failed to get account {account_name}: {e}");
                        continue;
                    }
                };

                if response.get_ref().state() != ResponseState::Succeeded {
                    warn!("Failed to get account {account_name}");
                    continue;
                }

                if let Some(account) = response.get_ref().accounts.get(0) {
                    // The account is Simple
                    match BlsPublicKey::try_from(account.public_key.as_slice()) {
                        Ok(public_key) => {
                            consensus_accounts.insert(
                                public_key,
                                Account::Simple(SimpleAccount {
                                    public_key,
                                    server: host.url.clone(),
                                    wallet: wallet.to_string(),
                                    name: name.to_string(),
                                }),
                            );
                        }
                        Err(_) => {
                            warn!("Failed to parse public key for account {account_name}");
                            continue;
                        }
                    }
                } else if let Some(account) = response.get_ref().distributed_accounts.get(0) {
                    // The account is Distributed
                    let Ok(public_key) =
                        BlsPublicKey::try_from(account.composite_public_key.as_slice())
                    else {
                        warn!("Failed to parse composite public key for account {account_name}");
                        continue;
                    };

                    let Some(&Endpoint { id: participant_id, .. }) = account
                        .participants
                        .iter()
                        .find(|participant| participant.name == host_name)
                    else {
                        warn!(
                            "Host {host_name} not found as participant for account {account_name}"
                        );
                        continue;
                    };

                    match consensus_accounts.get_mut(&public_key) {
                        Some(Account::Distributed(DistributedAccount { participants, .. })) => {
                            participants.insert(participant_id as u32, host.url.clone());
                        }
                        Some(Account::Simple(_)) => {
                            bail!("Distributed public key already exists for simple account");
                        }
                        None => {
                            let mut participants =
                                HashMap::with_capacity(account.participants.len());
                            participants.insert(participant_id as u32, host.url.clone());
                            consensus_accounts.insert(
                                public_key,
                                Account::Distributed(DistributedAccount {
                                    composite_public_key: public_key,
                                    participants,
                                    threshold: account.signing_threshold,
                                    wallet: wallet.to_string(),
                                    name: name.to_string(),
                                }),
                            );
                        }
                    }
                } else {
                    warn!("Account {account_name} not found in server {}", host.url);
                }
            }
        }

        debug!(
            "Loaded {} consensus accounts: {}",
            consensus_accounts.len(),
            consensus_accounts.keys().map(|k| k.to_string()).collect::<Vec<_>>().join(", ")
        );

        Ok(Self {
            chain,
            certs,
            connections,
            consensus_accounts,
            proxy_accounts: HashMap::new(),
            secrets_path: config.secrets_path,
            delegations_store: None,
        })
    }

    pub fn with_proxy_store(self, store: ProxyStore) -> eyre::Result<Self> {
        if let ProxyStore::ERC2335 { .. } = store {
            return Err(eyre::eyre!("ERC2335 proxy store not supported"));
        }

        Ok(Self { delegations_store: Some(store), ..self })
    }

    pub fn available_consensus_signers(&self) -> usize {
        self.consensus_accounts.len()
    }

    pub fn available_proxy_signers(&self) -> usize {
        self.proxy_accounts.len()
    }

    pub fn get_consensus_proxy_maps(&self, module: &ModuleId) -> Vec<ConsensusProxyMap> {
        self.consensus_accounts
            .iter()
            .map(|(_, account)| ConsensusProxyMap {
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

    pub async fn request_consensus_signature(
        &self,
        pubkey: &BlsPublicKey,
        object_root: [u8; 32],
    ) -> Result<BlsSignature, SignerModuleError> {
        match self.consensus_accounts.get(pubkey) {
            Some(Account::Simple(account)) => {
                self.request_simple_signature(account, object_root).await
            }
            Some(Account::Distributed(account)) => {
                self.request_distributed_signature(account, object_root).await
            }
            None => Err(SignerModuleError::UnknownConsensusSigner(pubkey.to_vec())),
        }
    }

    pub async fn request_proxy_signature(
        &self,
        pubkey: &BlsPublicKey,
        object_root: [u8; 32],
    ) -> Result<BlsSignature, SignerModuleError> {
        match self.proxy_accounts.get(pubkey) {
            Some(ProxyAccount { inner: Account::Simple(account), .. }) => {
                self.request_simple_signature(account, object_root).await
            }
            Some(ProxyAccount { inner: Account::Distributed(account), .. }) => {
                self.request_distributed_signature(account, object_root).await
            }
            None => Err(SignerModuleError::UnknownProxySigner(pubkey.to_vec())),
        }
    }

    async fn request_simple_signature(
        &self,
        account: &SimpleAccount,
        object_root: [u8; 32],
    ) -> Result<BlsSignature, SignerModuleError> {
        let domain = compute_domain(self.chain, COMMIT_BOOST_DOMAIN);

        let channel = self
            .connections
            .get(&account.server)
            .ok_or(SignerModuleError::DirkCommunicationError("Unknown Dirk host".to_string()))?;

        let response = SignerClient::new(channel.clone())
            .sign(SignRequest {
                data: object_root.to_vec(),
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

    async fn request_distributed_signature(
        &self,
        account: &DistributedAccount,
        object_root: [u8; 32],
    ) -> Result<BlsSignature, SignerModuleError> {
        let mut partials = Vec::with_capacity(account.participants.len());
        let mut requests = Vec::with_capacity(account.participants.len());

        for (id, endpoint) in account.participants.iter() {
            let Some(channel) = self.connections.get(endpoint) else {
                warn!("Couldn't find server {endpoint}");
                continue;
            };

            let request = async move {
                SignerClient::new(channel.clone())
                    .sign(SignRequest {
                        data: object_root.to_vec(),
                        domain: compute_domain(self.chain, COMMIT_BOOST_DOMAIN).to_vec(),
                        id: Some(sign_request::Id::Account(format!(
                            "{}/{}",
                            account.wallet, account.name
                        ))),
                    })
                    .map(|res| (res, (*id, endpoint.clone())))
                    .await
            };
            requests.push(request);
        }

        let mut requests = requests.into_iter().collect::<FuturesUnordered<_>>();

        while let Some((response, participant)) = requests.next().await {
            let (id, endpoint) = participant;

            let response = match response {
                Ok(res) => res,
                Err(e) => {
                    warn!("Failed to sign object with server {endpoint}: {e}");
                    continue;
                }
            };

            if response.get_ref().state() != ResponseState::Succeeded {
                warn!("Failed to sign object with server {endpoint}");
                continue;
            }

            let signature = match BlsSignature::try_from(response.into_inner().signature.as_slice())
            {
                Ok(sig) => sig,
                Err(e) => {
                    warn!("Failed to parse signature from server {endpoint}: {e}");
                    continue;
                }
            };

            partials.push((signature, id));

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
            self.request_consensus_signature(&consensus, message.tree_hash_root().0).await?;

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

    async fn generate_simple_proxy_account(
        &self,
        consensus: &SimpleAccount,
        module: &ModuleId,
    ) -> Result<ProxyAccount, SignerModuleError> {
        let channel = self
            .connections
            .get(&consensus.server)
            .ok_or(SignerModuleError::DirkCommunicationError("Unknown Dirk host".to_string()))?;

        let uuid = uuid::Uuid::new_v4();
        let password = random_password();

        let response = AccountManagerClient::new(channel.clone())
            .generate(GenerateRequest {
                account: format!("{}/{}/{module}/{uuid}", consensus.wallet, consensus.name),
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
                server: consensus.server.clone(),
                wallet: consensus.wallet.clone(),
                name: format!("{}/{module}/{uuid}", consensus.name),
            }),
        };

        self.store_password(&proxy_account, password).map_err(|e| {
            error!("Failed to store password: {e}");
            SignerModuleError::Internal("Failed to store password".to_string())
        })?;

        Ok(proxy_account)
    }

    async fn generate_distributed_proxy_key(
        &self,
        consensus: &DistributedAccount,
        module: &ModuleId,
    ) -> Result<ProxyAccount, SignerModuleError> {
        let uuid = uuid::Uuid::new_v4();
        let password = random_password();

        for participant in consensus.participants.values() {
            let channel = self.connections.get(participant).unwrap();
            let Ok(response) = AccountManagerClient::new(channel.clone())
                .generate(GenerateRequest {
                    account: format!("{}/{}/{module}/{uuid}", consensus.wallet, consensus.name),
                    passphrase: password.as_bytes().to_vec(),
                    participants: consensus.participants.len() as u32,
                    signing_threshold: consensus.threshold,
                })
                .await
                .map_err(|e| {
                    SignerModuleError::DirkCommunicationError(e.to_string());
                })
            else {
                warn!("Couldn't generate proxy key with server {participant}");
                continue;
            };

            if response.get_ref().state() != ResponseState::Succeeded {
                warn!("Couldn't generate proxy key with server {participant}");
                continue;
            }

            let Ok(proxy_key) = BlsPublicKey::try_from(response.into_inner().public_key.as_slice())
            else {
                warn!("Failed to parse proxy key from server {participant}");
                continue;
            };

            let proxy_account = ProxyAccount {
                consensus: Account::Distributed(consensus.clone()),
                module: module.clone(),
                inner: Account::Distributed(DistributedAccount {
                    composite_public_key: proxy_key,
                    participants: consensus.participants.clone(),
                    threshold: consensus.threshold,
                    wallet: consensus.wallet.clone(),
                    name: format!("{}/{module}/{uuid}", consensus.name),
                }),
            };

            self.store_password(&proxy_account, password).map_err(|e| {
                error!("Failed to store password: {e}");
                SignerModuleError::Internal("Failed to store password".to_string())
            })?;

            return Ok(proxy_account);
        }

        return Err(SignerModuleError::DirkCommunicationError(
            "All participant connections failed".to_string(),
        ))
    }

    fn store_password(&self, account: &ProxyAccount, password: String) -> eyre::Result<()> {
        let path = self.secrets_path.join(account.inner.full_name());
        let mut file = std::fs::File::create(path)?;
        file.write_all(password.as_bytes())?;
        Ok(())
    }
}

async fn connect(server: &DirkHostConfig, certs: &CertConfig) -> eyre::Result<Channel> {
    let mut tls_config = ClientTlsConfig::new().identity(certs.client.clone());
    if let Some(ca) = &certs.ca {
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

fn decompose_name(full_name: &str) -> eyre::Result<(&str, &str)> {
    full_name.split_once('/').ok_or_else(|| eyre::eyre!("Invalid account name"))
}

pub fn aggregate_partial_signatures(
    partials: &[(BlsSignature, u32)],
) -> eyre::Result<BlsSignature> {
    // Deserialize partial signatures into G2 points
    let mut shares: HashMap<u32, G2Projective> = HashMap::new();
    for (sig, id) in partials {
        if sig.len() != BLS_SIGNATURE_BYTES_LEN {
            bail!("Invalid signature length")
        }
        let arr: [u8; BLS_SIGNATURE_BYTES_LEN] = (*sig).into();
        let opt: Option<G2Affine> = G2Affine::from_compressed(&arr).into();
        let opt: Option<G2Projective> = G2Projective::from(&opt.unwrap()).into();
        if let Some(point) = opt {
            shares.insert(*id, point);
        } else {
            bail!("Failed to deserialize signature")
        }
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
        recovered += *point * lagrange_coeff;
    }

    // Serialize the recovered point back into a BlsSignature
    let bytes = recovered.to_compressed();
    Ok(bytes.into())
}

/// Generate a random password of 64 hex-characters
fn random_password() -> String {
    let password_bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(password_bytes)
}
