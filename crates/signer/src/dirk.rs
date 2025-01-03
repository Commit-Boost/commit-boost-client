use alloy::primitives::FixedBytes;
use cb_common::{
    commit::request::{ConsensusProxyMap, ProxyDelegation, SignedProxyDelegation},
    config::DirkConfig,
    signer::{BlsPublicKey, BlsSignature},
    types::ModuleId,
};
use tonic::transport::{Channel, ClientTlsConfig};

use crate::proto::v1::{
    account_manager_client::AccountManagerClient, lister_client::ListerClient,
    sign_request::Id as SignerId, signer_client::SignerClient, Account as DirkAccount,
    GenerateRequest, ListAccountsRequest, ResponseState, SignRequest, UnlockAccountRequest,
};

#[derive(Clone, Debug)]
pub struct DirkClient {
    channel: Channel,
    wallet: String,
}

impl DirkClient {
    pub async fn new_from_config(config: DirkConfig) -> Result<Self, eyre::Error> {
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

        Ok(Self { channel, wallet: config.wallet })
    }

    async fn list_accounts(&self) -> eyre::Result<Vec<DirkAccount>> {
        let mut client = ListerClient::new(self.channel.clone());
        let pubkeys_request =
            tonic::Request::new(ListAccountsRequest { paths: vec![self.wallet.clone()] });
        let pubkeys_response = client.list_accounts(pubkeys_request).await.unwrap();

        if pubkeys_response.get_ref().state() != ResponseState::Succeeded {
            eyre::bail!("Get pubkeys request failed".to_string());
        }

        Ok(pubkeys_response.into_inner().accounts)
    }

    pub async fn get_pubkeys(&self) -> eyre::Result<Vec<ConsensusProxyMap>> {
        let accounts = self.list_accounts().await?;

        let keys = accounts
            .iter()
            .filter_map(|account| {
                if account.name == format!("{}/consensus", self.wallet.clone()) {
                    Some(ConsensusProxyMap::new(BlsPublicKey::from(FixedBytes::from_slice(
                        &account.public_key,
                    ))))
                } else {
                    None
                }
            })
            .collect();
        Ok(keys)
    }

    pub async fn get_consensus_proxy_maps(
        &self,
        module_id: &ModuleId,
    ) -> eyre::Result<Vec<ConsensusProxyMap>> {
        let accounts = self.list_accounts().await?;

        let consensus_pubkey = accounts
            .iter()
            .find(|account| account.name == format!("{}/consensus", self.wallet.clone()))
            .map(|account| BlsPublicKey::from(FixedBytes::from_slice(&account.public_key)))
            .ok_or_else(|| eyre::eyre!("No consensus key found"))?;

        let proxy_keys = accounts
            .iter()
            .filter(|account| account.name.starts_with(&format!("{}/{module_id}/", self.wallet)))
            .map(|account| BlsPublicKey::from(FixedBytes::from_slice(&account.public_key)))
            .collect::<Vec<BlsPublicKey>>();

        Ok(vec![ConsensusProxyMap {
            consensus: consensus_pubkey,
            proxy_bls: proxy_keys,
            proxy_ecdsa: vec![],
        }])
    }

    pub async fn generate_proxy_key(
        &self,
        module_id: ModuleId,
        consensus_pubkey: BlsPublicKey,
    ) -> Result<SignedProxyDelegation<BlsPublicKey>, eyre::Error> {
        let uuid = uuid::Uuid::new_v4();

        let mut client = AccountManagerClient::new(self.channel.clone());
        let generate_request = tonic::Request::new(GenerateRequest {
            account: format!("{}/{module_id}/{uuid}", self.wallet),
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
            account: format!("{}/{module_id}/{uuid}", self.wallet),
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

    async fn request_signature(
        &self,
        signer_id: SignerId,
        domain: [u8; 32],
        object_root: [u8; 32],
    ) -> Result<BlsSignature, eyre::Error> {
        let mut signer_client = SignerClient::new(self.channel.clone());
        let sign_request = tonic::Request::new(SignRequest {
            id: Some(signer_id),
            domain: domain.to_vec(),
            data: object_root.to_vec(),
        });

        let sign_response = signer_client.sign(sign_request).await.unwrap();
        if sign_response.get_ref().state() != ResponseState::Succeeded {
            eyre::bail!("Sign request failed");
        }

        Ok(BlsSignature::from(FixedBytes::from_slice(&sign_response.into_inner().signature)))
    }

    pub async fn request_consensus_signature(
        &self,
        domain: [u8; 32],
        object_root: [u8; 32],
    ) -> eyre::Result<BlsSignature> {
        self.request_signature(
            SignerId::Account(format!("{}/consensus", self.wallet.clone())),
            domain,
            object_root,
        )
        .await
    }

    pub async fn request_proxy_bls_signature(
        &self,
        bls_key: &BlsPublicKey,
        domain: [u8; 32],
        object_root: [u8; 32],
    ) -> eyre::Result<BlsSignature> {
        self.request_signature(SignerId::PublicKey(bls_key.0.to_vec()), domain, object_root).await
    }
}
