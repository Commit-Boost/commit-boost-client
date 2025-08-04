use std::collections::HashMap;

use alloy::{
    primitives::{Address, B256},
    rpc::types::beacon::BlsSignature,
};
use cb_common::{
    commit::request::{
        ConsensusProxyMap, ProxyDelegationBls, ProxyDelegationEcdsa, SignedProxyDelegationBls,
        SignedProxyDelegationEcdsa,
    },
    signer::{
        BlsProxySigner, BlsPublicKey, BlsSigner, ConsensusSigner, EcdsaProxySigner, EcdsaSignature,
        EcdsaSigner, ProxySigners, ProxyStore,
    },
    types::{Chain, ModuleId},
};
use tree_hash::TreeHash;

use crate::error::SignerModuleError;

#[derive(Clone)]
pub struct LocalSigningManager {
    chain: Chain,
    proxy_store: Option<ProxyStore>,
    consensus_signers: HashMap<BlsPublicKey, ConsensusSigner>,
    proxy_signers: ProxySigners,
    /// Map of module ids to their associated proxy pubkeys.
    /// Used to retrieve the corresponding proxy signer from the signing
    /// manager.
    proxy_pubkeys_bls: HashMap<ModuleId, Vec<BlsPublicKey>>,
    proxy_addresses_ecdsa: HashMap<ModuleId, Vec<Address>>,
}

impl LocalSigningManager {
    pub fn new(chain: Chain, proxy_store: Option<ProxyStore>) -> eyre::Result<Self> {
        let mut manager = Self {
            chain,
            proxy_store,
            consensus_signers: Default::default(),
            proxy_signers: Default::default(),
            proxy_pubkeys_bls: Default::default(),
            proxy_addresses_ecdsa: Default::default(),
        };

        if let Some(store) = &manager.proxy_store {
            let (proxies, bls, ecdsa) = store.load_proxies()?;
            manager.proxy_signers = proxies;
            manager.proxy_pubkeys_bls = bls;
            manager.proxy_addresses_ecdsa = ecdsa;
        }

        Ok(manager)
    }

    pub fn add_consensus_signer(&mut self, signer: ConsensusSigner) {
        self.consensus_signers.insert(signer.pubkey(), signer);
    }

    pub fn add_proxy_signer_bls(
        &mut self,
        proxy: BlsProxySigner,
        module_id: ModuleId,
    ) -> eyre::Result<()> {
        if let Some(store) = &self.proxy_store {
            store.store_proxy_bls(&module_id, &proxy)?;
        }

        let proxy_pubkey = proxy.pubkey();
        self.proxy_signers.bls_signers.insert(proxy.pubkey(), proxy);
        self.proxy_pubkeys_bls.entry(module_id).or_default().push(proxy_pubkey);

        Ok(())
    }

    pub fn add_proxy_signer_ecdsa(
        &mut self,
        proxy: EcdsaProxySigner,
        module_id: ModuleId,
    ) -> eyre::Result<()> {
        if let Some(store) = &self.proxy_store {
            store.store_proxy_ecdsa(&module_id, &proxy)?;
        }

        let proxy_address = proxy.address();
        self.proxy_signers.ecdsa_signers.insert(proxy.address(), proxy);
        self.proxy_addresses_ecdsa.entry(module_id).or_default().push(proxy_address);

        Ok(())
    }

    pub async fn create_proxy_bls(
        &mut self,
        module_id: ModuleId,
        delegator: BlsPublicKey,
    ) -> Result<SignedProxyDelegationBls, SignerModuleError> {
        let signer = BlsSigner::new_random();
        let proxy_pubkey = signer.pubkey();

        let message = ProxyDelegationBls { delegator, proxy: proxy_pubkey };
        let signature = self.sign_consensus(&delegator, &message.tree_hash_root(), None).await?;
        let delegation = SignedProxyDelegationBls { signature, message };
        let proxy_signer = BlsProxySigner { signer, delegation };

        self.add_proxy_signer_bls(proxy_signer, module_id)
            .map_err(|err| SignerModuleError::Internal(err.to_string()))?;

        Ok(delegation)
    }

    pub async fn create_proxy_ecdsa(
        &mut self,
        module_id: ModuleId,
        delegator: BlsPublicKey,
    ) -> Result<SignedProxyDelegationEcdsa, SignerModuleError> {
        let signer = EcdsaSigner::new_random();
        let proxy_address = signer.address();

        let message = ProxyDelegationEcdsa { delegator, proxy: proxy_address };
        let signature = self.sign_consensus(&delegator, &message.tree_hash_root(), None).await?;
        let delegation = SignedProxyDelegationEcdsa { signature, message };
        let proxy_signer = EcdsaProxySigner { signer, delegation };

        self.add_proxy_signer_ecdsa(proxy_signer, module_id)
            .map_err(|err| SignerModuleError::Internal(err.to_string()))?;

        Ok(delegation)
    }

    // TODO: double check what we can actually sign here with different providers eg
    // web3 signer
    pub async fn sign_consensus(
        &self,
        pubkey: &BlsPublicKey,
        object_root: &B256,
        module_signing_id: Option<&B256>,
    ) -> Result<BlsSignature, SignerModuleError> {
        let signer = self
            .consensus_signers
            .get(pubkey)
            .ok_or(SignerModuleError::UnknownConsensusSigner(pubkey.to_vec()))?;
        let signature = signer.sign(self.chain, object_root, module_signing_id).await;

        Ok(signature)
    }

    pub async fn sign_proxy_bls(
        &self,
        pubkey: &BlsPublicKey,
        object_root: &B256,
        module_signing_id: Option<&B256>,
    ) -> Result<BlsSignature, SignerModuleError> {
        let bls_proxy = self
            .proxy_signers
            .bls_signers
            .get(pubkey)
            .ok_or(SignerModuleError::UnknownProxySigner(pubkey.to_vec()))?;
        let signature = bls_proxy.sign(self.chain, object_root, module_signing_id).await;
        Ok(signature)
    }

    pub async fn sign_proxy_ecdsa(
        &self,
        address: &Address,
        object_root: &B256,
        module_signing_id: Option<&B256>,
    ) -> Result<EcdsaSignature, SignerModuleError> {
        let ecdsa_proxy = self
            .proxy_signers
            .ecdsa_signers
            .get(address)
            .ok_or(SignerModuleError::UnknownProxySigner(address.to_vec()))?;
        let signature = ecdsa_proxy.sign(self.chain, object_root, module_signing_id).await?;
        Ok(signature)
    }

    pub fn consensus_pubkeys(&self) -> Vec<BlsPublicKey> {
        self.consensus_signers.keys().cloned().collect()
    }

    pub fn proxy_pubkeys_bls(&self) -> &HashMap<ModuleId, Vec<BlsPublicKey>> {
        &self.proxy_pubkeys_bls
    }

    pub fn proxy_addresses_ecdsa(&self) -> &HashMap<ModuleId, Vec<Address>> {
        &self.proxy_addresses_ecdsa
    }

    pub fn has_consensus(&self, pubkey: &BlsPublicKey) -> bool {
        self.consensus_signers.contains_key(pubkey)
    }

    pub fn has_proxy_bls_for_module(&self, bls_pk: &BlsPublicKey, module_id: &ModuleId) -> bool {
        match self.proxy_pubkeys_bls.get(module_id) {
            Some(keys) => keys.contains(bls_pk),
            None => false,
        }
    }

    pub fn has_proxy_ecdsa_for_module(
        &self,
        ecdsa_address: &Address,
        module_id: &ModuleId,
    ) -> bool {
        match self.proxy_addresses_ecdsa.get(module_id) {
            Some(keys) => keys.contains(ecdsa_address),
            None => false,
        }
    }

    pub fn get_delegation_bls(
        &self,
        pubkey: &BlsPublicKey,
    ) -> Result<SignedProxyDelegationBls, SignerModuleError> {
        self.proxy_signers
            .bls_signers
            .get(pubkey)
            .map(|x| x.delegation)
            .ok_or(SignerModuleError::UnknownProxySigner(pubkey.to_vec()))
    }

    pub fn get_delegation_ecdsa(
        &self,
        address: &Address,
    ) -> Result<SignedProxyDelegationEcdsa, SignerModuleError> {
        self.proxy_signers
            .ecdsa_signers
            .get(address)
            .map(|x| x.delegation)
            .ok_or(SignerModuleError::UnknownProxySigner(address.to_vec()))
    }

    pub fn get_consensus_proxy_maps(
        &self,
        module_id: &ModuleId,
    ) -> Result<Vec<ConsensusProxyMap>, SignerModuleError> {
        let consensus = self.consensus_pubkeys();
        let proxy_bls = self.proxy_pubkeys_bls.get(module_id).cloned().unwrap_or_default();
        let proxy_ecdsa = self.proxy_addresses_ecdsa.get(module_id).cloned().unwrap_or_default();

        let mut keys: Vec<_> = consensus.into_iter().map(ConsensusProxyMap::new).collect();

        for bls in proxy_bls {
            let delegator = self.get_delegation_bls(&bls)?.message.delegator;
            let entry = keys
                .iter_mut()
                .find(|x| x.consensus == delegator)
                .ok_or(SignerModuleError::UnknownConsensusSigner(delegator.0.to_vec()))?;

            entry.proxy_bls.push(bls);
        }

        for ecdsa in proxy_ecdsa {
            let delegator = self.get_delegation_ecdsa(&ecdsa)?.message.delegator;
            let entry = keys
                .iter_mut()
                .find(|x| x.consensus == delegator)
                .ok_or(SignerModuleError::UnknownConsensusSigner(delegator.0.to_vec()))?;

            entry.proxy_ecdsa.push(ecdsa);
        }

        Ok(keys)
    }

    pub fn available_proxy_signers(&self) -> usize {
        self.proxy_signers.bls_signers.len() + self.proxy_signers.ecdsa_signers.len()
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::B256;
    use lazy_static::lazy_static;

    use super::*;

    const CHAIN: Chain = Chain::Holesky;

    lazy_static! {
        static ref MODULE_ID: ModuleId = ModuleId("SAMPLE_MODULE".to_string());
    }

    fn init_signing_manager() -> (LocalSigningManager, BlsPublicKey) {
        let mut signing_manager = LocalSigningManager::new(CHAIN, None).unwrap();

        let consensus_signer = ConsensusSigner::new_random();
        let consensus_pk = consensus_signer.pubkey();

        signing_manager.add_consensus_signer(consensus_signer.clone());

        (signing_manager, consensus_pk)
    }

    mod test_bls {
        use alloy::primitives::aliases::B32;
        use cb_common::{
            constants::COMMIT_BOOST_DOMAIN, signature::compute_domain,
            signer::verify_bls_signature, types,
        };

        use super::*;

        #[tokio::test]
        async fn test_key_signs_message() {
            let (signing_manager, consensus_pk) = init_signing_manager();

            let data_root = B256::random();
            let module_signing_id = B256::random();

            let sig = signing_manager
                .sign_consensus(&consensus_pk, &data_root, Some(&module_signing_id))
                .await
                .unwrap();

            // Verify signature
            let signing_domain = compute_domain(CHAIN, &B32::from(COMMIT_BOOST_DOMAIN));
            let object_root = types::PropCommitSigningInfo {
                data: data_root.tree_hash_root(),
                module_signing_id,
            }
            .tree_hash_root();
            let signing_root = types::SigningData { object_root, signing_domain }.tree_hash_root();

            let validation_result =
                verify_bls_signature(&consensus_pk, signing_root.as_slice(), &sig);

            assert!(validation_result.is_ok(), "Keypair must produce valid signatures of messages.")
        }
    }

    mod test_proxy_bls {
        use alloy::primitives::aliases::B32;
        use cb_common::{
            constants::COMMIT_BOOST_DOMAIN, signature::compute_domain,
            signer::verify_bls_signature, types,
        };

        use super::*;

        #[tokio::test]
        async fn test_proxy_key_is_valid_proxy_for_consensus_key() {
            let (mut signing_manager, consensus_pk) = init_signing_manager();

            let signed_delegation =
                signing_manager.create_proxy_bls(MODULE_ID.clone(), consensus_pk).await.unwrap();

            let validation_result = signed_delegation.validate(CHAIN);

            assert!(
                validation_result.is_ok(),
                "Proxy delegation signature must be valid for consensus key."
            );

            assert!(
                signing_manager
                    .has_proxy_bls_for_module(&signed_delegation.message.proxy, &MODULE_ID),
                "Newly generated proxy key must be present in the signing manager's registry."
            );
        }

        #[tokio::test]
        async fn test_tampered_proxy_key_is_invalid() {
            let (mut signing_manager, consensus_pk) = init_signing_manager();

            let mut signed_delegation =
                signing_manager.create_proxy_bls(MODULE_ID.clone(), consensus_pk).await.unwrap();

            let m = &mut signed_delegation.signature.0[0];
            (*m, _) = m.overflowing_add(1);

            let validation_result = signed_delegation.validate(CHAIN);

            assert!(validation_result.is_err(), "Tampered proxy key must be invalid.");
        }

        #[tokio::test]
        async fn test_proxy_key_signs_message() {
            let (mut signing_manager, consensus_pk) = init_signing_manager();

            let signed_delegation =
                signing_manager.create_proxy_bls(MODULE_ID.clone(), consensus_pk).await.unwrap();
            let proxy_pk = signed_delegation.message.proxy;

            let data_root = B256::random();
            let module_signing_id = B256::random();

            let sig = signing_manager
                .sign_proxy_bls(&proxy_pk, &data_root, Some(&module_signing_id))
                .await
                .unwrap();

            // Verify signature
            let signing_domain = compute_domain(CHAIN, &B32::from(COMMIT_BOOST_DOMAIN));
            let object_root = types::PropCommitSigningInfo {
                data: data_root.tree_hash_root(),
                module_signing_id,
            }
            .tree_hash_root();
            let signing_root = types::SigningData { object_root, signing_domain }.tree_hash_root();

            let validation_result = verify_bls_signature(&proxy_pk, signing_root.as_slice(), &sig);

            assert!(
                validation_result.is_ok(),
                "Proxy keypair must produce valid signatures of messages."
            )
        }
    }

    mod test_proxy_ecdsa {
        use alloy::primitives::aliases::B32;
        use cb_common::{
            constants::COMMIT_BOOST_DOMAIN, signature::compute_domain,
            signer::verify_ecdsa_signature, types,
        };

        use super::*;

        #[tokio::test]
        async fn test_proxy_key_is_valid_proxy_for_consensus_key() {
            let (mut signing_manager, consensus_pk) = init_signing_manager();

            let signed_delegation =
                signing_manager.create_proxy_ecdsa(MODULE_ID.clone(), consensus_pk).await.unwrap();

            let validation_result = signed_delegation.validate(CHAIN);

            assert!(
                validation_result.is_ok(),
                "Proxy delegation signature must be valid for consensus key."
            );

            assert!(
                signing_manager
                    .has_proxy_ecdsa_for_module(&signed_delegation.message.proxy, &MODULE_ID),
                "Newly generated proxy key must be present in the signing manager's registry."
            );
        }

        #[tokio::test]
        async fn test_tampered_proxy_key_is_invalid() {
            let (mut signing_manager, consensus_pk) = init_signing_manager();

            let mut signed_delegation =
                signing_manager.create_proxy_ecdsa(MODULE_ID.clone(), consensus_pk).await.unwrap();

            let m = &mut signed_delegation.signature.0[0];
            (*m, _) = m.overflowing_add(1);

            let validation_result = signed_delegation.validate(CHAIN);

            assert!(validation_result.is_err(), "Tampered proxy key must be invalid.");
        }

        #[tokio::test]
        async fn test_proxy_key_signs_message() {
            let (mut signing_manager, consensus_pk) = init_signing_manager();

            let signed_delegation =
                signing_manager.create_proxy_ecdsa(MODULE_ID.clone(), consensus_pk).await.unwrap();
            let proxy_pk = signed_delegation.message.proxy;

            let data_root = B256::random();
            let module_signing_id = B256::random();

            let sig = signing_manager
                .sign_proxy_ecdsa(&proxy_pk, &data_root, Some(&module_signing_id))
                .await
                .unwrap();

            // Verify signature
            let signing_domain = compute_domain(CHAIN, &B32::from(COMMIT_BOOST_DOMAIN));
            let object_root = types::PropCommitSigningInfo {
                data: data_root.tree_hash_root(),
                module_signing_id,
            }
            .tree_hash_root();
            let signing_root = types::SigningData { object_root, signing_domain }.tree_hash_root();

            let validation_result = verify_ecdsa_signature(&proxy_pk, &signing_root, &sig);

            assert!(
                validation_result.is_ok(),
                "Proxy keypair must produce valid signatures of messages."
            )
        }
    }
}
