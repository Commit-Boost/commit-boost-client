use alloy::primitives::FixedBytes;
use cb_common::{
    commit::request::{ConsensusProxyMap, ProxyDelegation, SignedProxyDelegation},
    config::DirkConfig,
    constants::COMMIT_BOOST_DOMAIN,
    signature::compute_domain,
    signer::{BlsPublicKey, BlsSignature},
    types::{Chain, ModuleId},
};
use tonic::transport::{Channel, ClientTlsConfig};

use crate::proto::v1::{
    account_manager_client::AccountManagerClient, lister_client::ListerClient,
    sign_request::Id as SignerId, signer_client::SignerClient, Account as DirkAccount,
    GenerateRequest, ListAccountsRequest, ResponseState, SignRequest, UnlockAccountRequest,
};

#[derive(Clone, Debug)]
pub struct DirkManager {
    chain: Chain,
    channel: Channel,
    wallets: Vec<String>,
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

        Ok(Self { chain, channel, wallets: config.wallets })
    }

    async fn get_all_accounts(&self) -> eyre::Result<Vec<DirkAccount>> {
        let mut client = ListerClient::new(self.channel.clone());
        let pubkeys_request =
            tonic::Request::new(ListAccountsRequest { paths: self.wallets.clone() });
        let pubkeys_response = client.list_accounts(pubkeys_request).await?;

        if pubkeys_response.get_ref().state() != ResponseState::Succeeded {
            eyre::bail!("Get pubkeys request failed".to_string());
        }

        Ok(pubkeys_response.into_inner().accounts)
    }

    async fn get_pubkey_wallet(&self, pubkey: BlsPublicKey) -> eyre::Result<Option<String>> {
        let accounts = self.get_all_accounts().await?;

        for account in accounts {
            if account.public_key == pubkey.to_vec() {
                return Ok(Some(account.name));
            }
        }

        Ok(None)
    }

    pub async fn consensus_pubkeys(&self) -> eyre::Result<Vec<BlsPublicKey>> {
        let accounts = self.get_all_accounts().await?;

        let expected_accounts: Vec<String> =
            self.wallets.iter().map(|wallet| format!("{wallet}/consensus")).collect();

        Ok(accounts
            .iter()
            .filter_map(|account| {
                if expected_accounts.contains(&account.name) {
                    Some(BlsPublicKey::from(FixedBytes::from_slice(&account.public_key)))
                } else {
                    None
                }
            })
            .collect())
    }

    pub async fn proxies(&self) -> eyre::Result<Vec<BlsPublicKey>> {
        let accounts = self.get_all_accounts().await?;

        Ok(accounts
            .iter()
            .filter_map(|account| {
                let wallet = account.name.split_once("/")?.0;
                if self.wallets.contains(&wallet.to_string()) &&
                    account.name != format!("{wallet}/consensus")
                {
                    Some(BlsPublicKey::from(FixedBytes::from_slice(&account.public_key)))
                } else {
                    None
                }
            })
            .collect())
    }

    pub async fn get_consensus_proxy_maps(
        &self,
        module_id: &ModuleId,
    ) -> eyre::Result<Vec<ConsensusProxyMap>> {
        let accounts = self.get_all_accounts().await?;

        let mut proxy_maps = Vec::new();

        for wallet in self.wallets.iter() {
            let Some(consensus_key) = accounts.iter().find_map(|account| {
                if account.name == format!("{wallet}/consensus") {
                    Some(BlsPublicKey::from(FixedBytes::from_slice(&account.public_key)))
                } else {
                    None
                }
            }) else {
                continue;
            };

            let proxy_keys = accounts
                .iter()
                .filter_map(|account| {
                    if account.name.starts_with(&format!("{wallet}/{module_id}")) {
                        Some(BlsPublicKey::from(FixedBytes::from_slice(&account.public_key)))
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

    pub async fn generate_proxy_key(
        &self,
        module_id: ModuleId,
        consensus_pubkey: BlsPublicKey,
    ) -> eyre::Result<SignedProxyDelegation<BlsPublicKey>> {
        let uuid = uuid::Uuid::new_v4();

        let wallet = self
            .get_pubkey_wallet(consensus_pubkey)
            .await?
            .ok_or(eyre::eyre!("Consensus public key not found"))?;

        let mut client = AccountManagerClient::new(self.channel.clone());
        let generate_request = tonic::Request::new(GenerateRequest {
            account: format!("{wallet}/{module_id}/{uuid}"),
            passphrase: vec![0x73, 0x65, 0x63, 0x72, 0x65, 0x74], // "secret"
            participants: 1,
            signing_threshold: 1,
        });

        let generate_response = client.generate(generate_request).await?;
        if generate_response.get_ref().state() != ResponseState::Succeeded {
            eyre::bail!("Generate request failed");
        }

        let proxy_key =
            BlsPublicKey::from(FixedBytes::from_slice(&generate_response.into_inner().public_key));

        let mut unlock_client = AccountManagerClient::new(self.channel.clone());
        let unlock_request = tonic::Request::new(UnlockAccountRequest {
            account: format!("{wallet}/{module_id}/{uuid}"),
            passphrase: vec![0x73, 0x65, 0x63, 0x72, 0x65, 0x74], // "secret"
        });

        let unlock_response = unlock_client.unlock(unlock_request).await?;
        if unlock_response.get_ref().state() != ResponseState::Succeeded {
            eyre::bail!("Unlock request failed");
        }

        Ok(SignedProxyDelegation {
            message: ProxyDelegation { delegator: consensus_pubkey, proxy: proxy_key },
            signature: BlsSignature::random(),
        })
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
        if sign_response.get_ref().state() != ResponseState::Succeeded {
            eyre::bail!("Sign request failed");
        }

        Ok(BlsSignature::from(FixedBytes::from_slice(&sign_response.into_inner().signature)))
    }
}
