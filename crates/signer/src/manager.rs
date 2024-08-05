use std::collections::HashMap;

use alloy::rpc::types::beacon::{BlsPublicKey, BlsSignature};
use cb_common::{
    commit::request::{ProxyDelegation, SignedProxyDelegation},
    signer::Signer,
    types::{Chain, ModuleId},
};
use tree_hash::TreeHash;

use crate::error::SignerModuleError;

// For extra safety and to avoid risking signing malicious messages, use a proxy
// setup: proposer creates a new ephemeral keypair which will be used to sign
// commit messages, it also signs a ProxyDelegation associating the new keypair
// with its consensus pubkey When a new commit module starts, pass the
// ProxyDelegation msg and then sign all future commit messages with the proxy
// key for slashing the faulty message + proxy delegation can be used
// Signed using builder domain

#[derive(Clone)]
pub struct ProxySigner {
    signer: Signer,
    delegation: SignedProxyDelegation,
}

pub struct SigningManager {
    chain: Chain,
    consensus_signers: HashMap<BlsPublicKey, Signer>,
    proxy_signers: HashMap<BlsPublicKey, ProxySigner>,
    /// Map of module ids to their associated proxy pubkeys.
    /// Used to retrieve the corresponding proxy signer from the signing
    /// manager.
    proxy_pubkeys: HashMap<ModuleId, Vec<BlsPublicKey>>,
}

impl SigningManager {
    pub fn new(chain: Chain) -> Self {
        Self {
            chain,
            consensus_signers: HashMap::new(),
            proxy_signers: HashMap::new(),
            proxy_pubkeys: HashMap::new(),
        }
    }

    pub fn add_consensus_signer(&mut self, signer: Signer) {
        self.consensus_signers.insert(signer.pubkey(), signer);
    }

    pub fn add_proxy_signer(&mut self, proxy: ProxySigner) {
        self.proxy_signers.insert(proxy.signer.pubkey(), proxy);
    }

    pub async fn create_proxy(
        &mut self,
        module_id: ModuleId,
        delegator: BlsPublicKey,
    ) -> Result<SignedProxyDelegation, SignerModuleError> {
        let signer = Signer::new_random();
        let proxy_pubkey = signer.pubkey();

        let message = ProxyDelegation { delegator, proxy: proxy_pubkey };
        let signature = self.sign_consensus(&delegator, &message.tree_hash_root().0).await?;
        let signed_delegation: SignedProxyDelegation = SignedProxyDelegation { signature, message };
        let proxy_signer = ProxySigner { signer, delegation: signed_delegation };

        // Add the new proxy key to the manager's internal state
        self.add_proxy_signer(proxy_signer);
        self.proxy_pubkeys.entry(module_id).or_default().push(proxy_pubkey);

        Ok(signed_delegation)
    }

    // TODO: double check what we can actually sign here with different providers eg
    // web3 signer
    pub async fn sign_consensus(
        &self,
        pubkey: &BlsPublicKey,
        msg: &[u8; 32],
    ) -> Result<BlsSignature, SignerModuleError> {
        let signer = self
            .consensus_signers
            .get(pubkey)
            .ok_or(SignerModuleError::UnknownConsensusSigner(*pubkey))?;
        let signature = signer.sign(self.chain, msg).await;

        Ok(signature)
    }

    pub async fn sign_proxy(
        &self,
        pubkey: &BlsPublicKey,
        msg: &[u8; 32],
    ) -> Result<BlsSignature, SignerModuleError> {
        let proxy =
            self.proxy_signers.get(pubkey).ok_or(SignerModuleError::UnknownProxySigner(*pubkey))?;
        let signature = proxy.signer.sign(self.chain, msg).await;

        Ok(signature)
    }

    pub fn consensus_pubkeys(&self) -> Vec<BlsPublicKey> {
        self.consensus_signers.keys().cloned().collect()
    }

    pub fn proxy_pubkeys(&self) -> &HashMap<ModuleId, Vec<BlsPublicKey>> {
        &self.proxy_pubkeys
    }

    pub fn delegations(&self) -> Vec<SignedProxyDelegation> {
        self.proxy_signers.values().map(|s| s.delegation).collect()
    }

    pub fn has_consensus(&self, pubkey: &BlsPublicKey) -> bool {
        self.consensus_signers.contains_key(pubkey)
    }

    pub fn has_proxy(&self, pubkey: &BlsPublicKey) -> bool {
        self.proxy_signers.contains_key(pubkey)
    }

    pub fn get_delegation(
        &self,
        proxy_pubkey: &BlsPublicKey,
    ) -> Result<SignedProxyDelegation, SignerModuleError> {
        let signer = self
            .proxy_signers
            .get(proxy_pubkey)
            .ok_or(SignerModuleError::UnknownProxySigner(*proxy_pubkey))?;
        Ok(signer.delegation)
    }
}

// TODO(David): Add more tests.
#[cfg(test)]
mod tests {
    use cb_common::signature::verify_signed_builder_message;
    use lazy_static::lazy_static;
    use tree_hash::Hash256;

    use super::*;

    lazy_static! {
        static ref CHAIN: Chain = Chain::Holesky;
        static ref MODULE_ID: ModuleId = ModuleId("SAMPLE_MODULE".to_string());
    }

    fn init_signing_manager() -> (SigningManager, BlsPublicKey) {
        let mut signing_manager = SigningManager::new(*CHAIN);

        let consensus_signer = Signer::new_random();
        let consensus_pk = consensus_signer.pubkey();

        signing_manager.add_consensus_signer(consensus_signer.clone());

        (signing_manager, consensus_pk)
    }

    #[tokio::test]
    async fn test_proxy_key_is_valid_proxy_for_consensus_key() {
        let (mut signing_manager, consensus_pk) = init_signing_manager();

        let signed_delegation = signing_manager.create_proxy(MODULE_ID.clone(), consensus_pk.clone()).await.unwrap();

        let validation_result = signed_delegation.validate(*CHAIN);

        assert!(
            validation_result.is_ok(),
            "Proxy delegation signature must be valid for consensus key."
        );

        assert!(
            signing_manager.has_proxy(&signed_delegation.message.proxy),
            "Newly generated proxy key must be present in the signing manager's registry."
        );
    }

    #[tokio::test]
    async fn test_tampered_proxy_key_is_invalid() {
        let (mut signing_manager, consensus_pk) = init_signing_manager();

        let mut signed_delegation = signing_manager.create_proxy(MODULE_ID.clone(), consensus_pk.clone()).await.unwrap();

        let m = &mut signed_delegation.signature.0[0];
        (*m, _) = m.overflowing_add(1);

        let validation_result = signed_delegation.validate(*CHAIN);

        assert!(
            validation_result.is_err(),
            "Tampered proxy key must be invalid."
        );
    }

    #[tokio::test]
    async fn test_proxy_key_signs_message() {
        let (mut signing_manager, consensus_pk) = init_signing_manager();

        let signed_delegation = signing_manager.create_proxy(MODULE_ID.clone(), consensus_pk.clone()).await.unwrap();
        let proxy_pk = signed_delegation.message.proxy;

        let data_root = Hash256::random();
        let data_root_bytes = data_root.as_fixed_bytes();

        let sig = signing_manager.sign_proxy(&proxy_pk, data_root_bytes).await.unwrap();

        let validation_result = verify_signed_builder_message(
            *CHAIN,
            &signed_delegation.message.proxy,
            &data_root_bytes,
            &sig,
        );

        assert!(
            validation_result.is_ok(),
            "Proxy keypair must produce valid signatures of messages."
        )
    }
}
