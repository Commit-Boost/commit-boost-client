use alloy::{primitives::FixedBytes, transports::http::reqwest::Url};
use cb_common::{commit::request::ConsensusProxyMap, signer::BlsPublicKey, types::ModuleId};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use v1::{lister_client::ListerClient, ListAccountsRequest, ResponseState};

pub mod v1 {
    tonic::include_proto!("v1");
}

#[derive(Clone)]
pub struct DirkConfig {
    pub url: Url,
    pub client_cert: Identity,
    pub cert_auth: Option<Certificate>,
    pub server_domain: Option<String>,
}

#[derive(Clone)]
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
        let dirk_request =
            tonic::Request::new(ListAccountsRequest { paths: vec![module_id.to_string()] });
        let dirk_response = client.list_accounts(dirk_request).await.unwrap();

        if dirk_response.get_ref().state() != ResponseState::Succeeded {
            return Err(eyre::eyre!("Dirk request failed".to_string()));
        }

        let mut keys = Vec::new();
        for account in dirk_response.into_inner().accounts.iter() {
            keys.push(ConsensusProxyMap::new(BlsPublicKey::from(FixedBytes::from_slice(
                &account.public_key,
            ))))
        }
        Ok(keys)
    }
}
