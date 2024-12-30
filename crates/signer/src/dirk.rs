use alloy::{hex, primitives::FixedBytes};
use cb_common::{
    commit::request::ConsensusProxyMap,
    config::DirkConfig,
    signer::{BlsPublicKey, BlsSignature},
    types::ModuleId,
};
use tonic::transport::{Channel, ClientTlsConfig};

use v1::{
    account_manager_client::AccountManagerClient, lister_client::ListerClient,
    sign_request::Id as SignerId, signer_client::SignerClient, ListAccountsRequest, ResponseState,
    UnlockAccountRequest,
};

pub mod v1 {
    tonic::include_proto!("v1");
}

#[derive(Clone, Debug)]
pub struct DirkClient {
    channel: Channel,
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
            .map_err(|_| eyre::eyre!("Invalid Dirk URL".to_string()))?
            .tls_config(tls_config)
            .map_err(|_| eyre::eyre!("Invalid Dirk URL".to_string()))?
            .connect()
            .await
            .map_err(|e| eyre::eyre!(format!("Couldn't connect to Dirk: {e}")))?;

        Ok(Self { channel })
    }

    pub async fn get_pubkeys(
        &self,
        module_id: ModuleId,
    ) -> Result<Vec<ConsensusProxyMap>, eyre::Error> {
        let mut client = ListerClient::new(self.channel.clone());
        let dirk_request = tonic::Request::new(ListAccountsRequest {
            paths: vec!["wallet1/account1".to_string()],
        });
        let dirk_response = client.list_accounts(dirk_request).await.unwrap();

        if dirk_response.get_ref().state() != ResponseState::Succeeded {
            eyre::bail!("Dirk request failed".to_string());
        }

        let mut keys = Vec::new();
        for account in dirk_response.into_inner().accounts.iter() {
            keys.push(ConsensusProxyMap::new(BlsPublicKey::from(FixedBytes::from_slice(
                &account.public_key,
            ))))
        }
        Ok(keys)
    }

    pub async fn request_signature(
        &self,
        id: SignerId,
        object_root: [u8; 32],
    ) -> Result<BlsSignature, eyre::Error> {
        let mut unlock_client = AccountManagerClient::new(self.channel.clone());
        let unlock_request = tonic::Request::new(UnlockAccountRequest {
            account: match &id {
                SignerId::Account(account) => account.to_string(),
                SignerId::PublicKey(_) => unimplemented!(),
            },
            passphrase: hex::decode("736563726574").unwrap(),
        });

        let unlock_response = unlock_client.unlock(unlock_request).await.unwrap();
        if unlock_response.get_ref().state() != ResponseState::Succeeded {
            eyre::bail!("Unlock request failed");
        }

        let mut signer_client = SignerClient::new(self.channel.clone());
        let sign_request = tonic::Request::new(v1::SignRequest {
            id: Some(id),
            data: object_root.to_vec(),
            domain: hex::decode("1ea343e3a29ec9b8de4981dc755220fa10635c6e2ad13a0df6abfc5663c66a88")
                .unwrap(),
        });

        let sign_response = signer_client.sign(sign_request).await.unwrap();
        if sign_response.get_ref().state() != ResponseState::Succeeded {
            eyre::bail!("Sign request failed");
        }

        Ok(BlsSignature::from(FixedBytes::from_slice(&sign_response.into_inner().signature)))
    }
}
