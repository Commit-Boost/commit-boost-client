use alloy::primitives::FixedBytes;
use cb_common::{
    commit::request::ConsensusProxyMap,
    config::DirkConfig,
    signer::{BlsPublicKey, BlsSignature},
    types::ModuleId,
};
use tonic::transport::{Channel, ClientTlsConfig};

use crate::proto::v1::{
    lister_client::ListerClient, sign_request::Id as SignerId, signer_client::SignerClient,
    ListAccountsRequest, ResponseState,
};

#[derive(Clone, Debug)]
pub struct DirkClient {
    channel: Channel,
    account: String,
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

        Ok(Self { channel, account: config.account })
    }

    pub async fn get_pubkeys(
        &self,
        module_id: ModuleId,
    ) -> Result<Vec<ConsensusProxyMap>, eyre::Error> {
        let mut client = ListerClient::new(self.channel.clone());
        let pubkeys_request =
            tonic::Request::new(ListAccountsRequest { paths: vec![self.account.clone()] });
        let pubkeys_response = client.list_accounts(pubkeys_request).await.unwrap();

        if pubkeys_response.get_ref().state() != ResponseState::Succeeded {
            eyre::bail!("Get pubkeys request failed".to_string());
        }

        let mut keys = Vec::new();
        for account in pubkeys_response.into_inner().accounts.iter() {
            keys.push(ConsensusProxyMap::new(BlsPublicKey::from(FixedBytes::from_slice(
                &account.public_key,
            ))))
        }
        Ok(keys)
    }

    pub async fn request_signature(
        &self,
        domain: [u8; 32],
        object_root: [u8; 32],
    ) -> Result<BlsSignature, eyre::Error> {
        let mut signer_client = SignerClient::new(self.channel.clone());
        let sign_request = tonic::Request::new(crate::proto::v1::SignRequest {
            id: Some(SignerId::Account(self.account.clone())),
            domain: domain.to_vec(),
            data: object_root.to_vec(),
        });

        let sign_response = signer_client.sign(sign_request).await.unwrap();
        if sign_response.get_ref().state() != ResponseState::Succeeded {
            eyre::bail!("Sign request failed");
        }

        Ok(BlsSignature::from(FixedBytes::from_slice(&sign_response.into_inner().signature)))
    }
}
