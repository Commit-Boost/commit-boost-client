use std::collections::HashMap;

use alloy::rpc::types::beacon::BlsSignature;
use cb_common::{
    commit::request::{
        ConsensusProxyMap, ProxyDelegationBls, ProxyDelegationEcdsa, SignedProxyDelegationBls,
        SignedProxyDelegationEcdsa,
    },
    signer::{
        schemes::{
            bls::BlsPublicKey,
            ecdsa::{EcdsaPublicKey, EcdsaSignature},
        },
        BlsSigner, ConsensusSigner, EcdsaSigner,
    },
    types::{Chain, ModuleId},
};
use derive_more::derive::Deref;
use eyre::OptionExt;
use tree_hash::TreeHash;

use crate::error::SignerModuleError;

// For extra safety and to avoid risking signing malicious messages, use a proxy
// setup: proposer creates a new ephemeral keypair which will be used to sign
// commit messages, it also signs a ProxyDelegation associating the new keypair
// with its consensus pubkey When a new commit module starts, pass the
// ProxyDelegation msg and then sign all future commit messages with the proxy
// key for slashing the faulty message + proxy delegation can be used
#[derive(Clone, Deref)]
pub struct BlsProxySigner {
    #[deref]
    signer: BlsSigner,
    delegation: SignedProxyDelegationBls,
}

#[derive(Clone, Deref)]
pub struct EcdsaProxySigner {
    #[deref]
    signer: EcdsaSigner,
    delegation: SignedProxyDelegationEcdsa,
}

#[derive(Default)]
struct ProxySigners {
    bls_signers: HashMap<BlsPublicKey, BlsProxySigner>,
    ecdsa_signers: HashMap<EcdsaPublicKey, EcdsaProxySigner>,
}

pub struct SigningManager {
    chain: Chain,
    consensus_signers: HashMap<BlsPublicKey, ConsensusSigner>,
    proxy_signers: ProxySigners,
    /// Map of module ids to their associated proxy pubkeys.
    /// Used to retrieve the corresponding proxy signer from the signing
    /// manager.
    proxy_pubkeys_bls: HashMap<ModuleId, Vec<BlsPublicKey>>,
    proxy_pubkeys_ecdsa: HashMap<ModuleId, Vec<EcdsaPublicKey>>,
}

impl SigningManager {
    pub fn new(chain: Chain) -> Self {
        Self {
            chain,
            consensus_signers: Default::default(),
            proxy_signers: Default::default(),
            proxy_pubkeys_bls: Default::default(),
            proxy_pubkeys_ecdsa: Default::default(),
        }
    }

    pub fn add_consensus_signer(&mut self, signer: ConsensusSigner) {
        self.consensus_signers.insert(signer.pubkey(), signer);
    }

    pub fn add_proxy_signer_bls(&mut self, proxy: BlsProxySigner, module_id: ModuleId) {
        let proxy_pubkey = proxy.pubkey();
        self.proxy_signers.bls_signers.insert(proxy.pubkey(), proxy);
        self.proxy_pubkeys_bls.entry(module_id).or_default().push(proxy_pubkey)
    }

    pub fn add_proxy_signer_ecdsa(&mut self, proxy: EcdsaProxySigner, module_id: ModuleId) {
        let proxy_pubkey = proxy.pubkey();
        self.proxy_signers.ecdsa_signers.insert(proxy.pubkey(), proxy);
        self.proxy_pubkeys_ecdsa.entry(module_id).or_default().push(proxy_pubkey)
    }

    pub async fn create_proxy_bls(
        &mut self,
        module_id: ModuleId,
        delegator: BlsPublicKey,
    ) -> Result<SignedProxyDelegationBls, SignerModuleError> {
        let signer = BlsSigner::new_random();
        let proxy_pubkey = signer.pubkey();

        let message = ProxyDelegationBls { delegator, proxy: proxy_pubkey };
        let signature = self.sign_consensus(&delegator, &message.tree_hash_root().0).await?;
        let delegation = SignedProxyDelegationBls { signature, message };
        let proxy_signer = BlsProxySigner { signer, delegation };

        self.add_proxy_signer_bls(proxy_signer, module_id);

        Ok(delegation)
    }

    pub async fn create_proxy_ecdsa(
        &mut self,
        module_id: ModuleId,
        delegator: BlsPublicKey,
    ) -> Result<SignedProxyDelegationEcdsa, SignerModuleError> {
        let signer = EcdsaSigner::new_random();
        let proxy_pubkey = signer.pubkey();

        let message = ProxyDelegationEcdsa { delegator, proxy: proxy_pubkey };
        let signature = self.sign_consensus(&delegator, &message.tree_hash_root().0).await?;
        let delegation = SignedProxyDelegationEcdsa { signature, message };
        let proxy_signer = EcdsaProxySigner { signer, delegation };

        self.add_proxy_signer_ecdsa(proxy_signer, module_id);

        Ok(delegation)
    }

    // TODO: double check what we can actually sign here with different providers eg
    // web3 signer
    pub async fn sign_consensus(
        &self,
        pubkey: &BlsPublicKey,
        object_root: &[u8; 32],
    ) -> Result<BlsSignature, SignerModuleError> {
        let signer = self
            .consensus_signers
            .get(pubkey)
            .ok_or(SignerModuleError::UnknownConsensusSigner(pubkey.to_vec()))?;
        let signature = signer.sign(self.chain, *object_root).await;

        Ok(signature)
    }

    pub async fn sign_proxy_bls(
        &self,
        pubkey: &BlsPublicKey,
        object_root: &[u8; 32],
    ) -> Result<BlsSignature, SignerModuleError> {
        let bls_proxy = self
            .proxy_signers
            .bls_signers
            .get(pubkey)
            .ok_or(SignerModuleError::UnknownProxySigner(pubkey.to_vec()))?;
        let signature = bls_proxy.sign(self.chain, *object_root).await;
        Ok(signature)
    }

    pub async fn sign_proxy_ecdsa(
        &self,
        pubkey: &EcdsaPublicKey,
        object_root: &[u8; 32],
    ) -> Result<EcdsaSignature, SignerModuleError> {
        let ecdsa_proxy = self
            .proxy_signers
            .ecdsa_signers
            .get(pubkey)
            .ok_or(SignerModuleError::UnknownProxySigner(pubkey.to_vec()))?;
        let signature = ecdsa_proxy.sign(self.chain, *object_root).await;
        Ok(signature)
    }

    pub fn consensus_pubkeys(&self) -> Vec<BlsPublicKey> {
        self.consensus_signers.keys().cloned().collect()
    }

    pub fn proxy_pubkeys_bls(&self) -> &HashMap<ModuleId, Vec<BlsPublicKey>> {
        &self.proxy_pubkeys_bls
    }

    pub fn proxy_pubkeys_ecdsa(&self) -> &HashMap<ModuleId, Vec<EcdsaPublicKey>> {
        &self.proxy_pubkeys_ecdsa
    }

    pub fn has_consensus(&self, pubkey: &BlsPublicKey) -> bool {
        self.consensus_signers.contains_key(pubkey)
    }

    pub fn has_proxy_ecdsa(&self, ecdsa_pk: &EcdsaPublicKey) -> bool {
        self.proxy_signers.ecdsa_signers.contains_key(ecdsa_pk)
    }

    pub fn has_proxy_bls(&self, bls_pk: &BlsPublicKey) -> bool {
        self.proxy_signers.bls_signers.contains_key(bls_pk)
    }

    pub fn get_delegation_bls(
        &self,
        pubkey: &BlsPublicKey,
    ) -> Result<SignedProxyDelegationBls, SignerModuleError> {
        self.proxy_signers
            .bls_signers
            .get(pubkey)
            .map(|x| x.delegation)
            .ok_or(SignerModuleError::UnknownProxySigner(pubkey.as_ref().to_vec()))
    }

    pub fn get_delegation_ecdsa(
        &self,
        pubkey: &EcdsaPublicKey,
    ) -> Result<SignedProxyDelegationEcdsa, SignerModuleError> {
        self.proxy_signers
            .ecdsa_signers
            .get(pubkey)
            .map(|x| x.delegation)
            .ok_or(SignerModuleError::UnknownProxySigner(pubkey.as_ref().to_vec()))
    }

    pub fn get_consensus_proxy_maps(
        &self,
        module_id: &ModuleId,
    ) -> eyre::Result<Vec<ConsensusProxyMap>> {
        let consensus = self.consensus_pubkeys();
        let proxy_bls = self.proxy_pubkeys_bls.get(module_id).cloned().unwrap_or_default();
        let proxy_ecdsa = self.proxy_pubkeys_ecdsa.get(module_id).cloned().unwrap_or_default();

        let mut keys: Vec<_> = consensus.into_iter().map(ConsensusProxyMap::new).collect();

        for bls in proxy_bls {
            let delegator = self.get_delegation_bls(&bls)?.message.delegator;
            let entry = keys
                .iter_mut()
                .find(|x| x.consensus == delegator)
                .ok_or_eyre("missing consensus")?;

            entry.proxy_bls.push(bls);
        }

        for ecdsa in proxy_ecdsa {
            let delegator = self.get_delegation_ecdsa(&ecdsa)?.message.delegator;
            let entry = keys
                .iter_mut()
                .find(|x| x.consensus == delegator)
                .ok_or_eyre("missing consensus")?;

            entry.proxy_ecdsa.push(ecdsa);
        }

        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use cb_common::signature::compute_signing_root;
    use lazy_static::lazy_static;
    use tree_hash::Hash256;

    use super::*;

    const CHAIN: Chain = Chain::Holesky;

    lazy_static! {
        static ref MODULE_ID: ModuleId = ModuleId("SAMPLE_MODULE".to_string());
    }

    fn init_signing_manager() -> (SigningManager, BlsPublicKey) {
        let mut signing_manager = SigningManager::new(CHAIN);

        let consensus_signer = ConsensusSigner::new_random();
        let consensus_pk = consensus_signer.pubkey();

        signing_manager.add_consensus_signer(consensus_signer.clone());

        (signing_manager, consensus_pk)
    }

    mod test_proxy_bls {
        use cb_common::{
            constants::COMMIT_BOOST_DOMAIN, signature::compute_domain,
            signer::schemes::bls::verify_bls_signature,
        };

        use super::*;

        #[tokio::test]
        async fn test_proxy_key_is_valid_proxy_for_consensus_key() {
            let (mut signing_manager, consensus_pk) = init_signing_manager();

            let signed_delegation = signing_manager
                .create_proxy_bls(MODULE_ID.clone(), consensus_pk.clone())
                .await
                .unwrap();

            let validation_result = signed_delegation.validate(CHAIN);

            assert!(
                validation_result.is_ok(),
                "Proxy delegation signature must be valid for consensus key."
            );

            assert!(
                signing_manager.has_proxy_bls(&signed_delegation.message.proxy),
                "Newly generated proxy key must be present in the signing manager's registry."
            );
        }

        #[tokio::test]
        async fn test_tampered_proxy_key_is_invalid() {
            let (mut signing_manager, consensus_pk) = init_signing_manager();

            let mut signed_delegation = signing_manager
                .create_proxy_bls(MODULE_ID.clone(), consensus_pk.clone())
                .await
                .unwrap();

            let m = &mut signed_delegation.signature.0[0];
            (*m, _) = m.overflowing_add(1);

            let validation_result = signed_delegation.validate(CHAIN);

            assert!(validation_result.is_err(), "Tampered proxy key must be invalid.");
        }

        #[tokio::test]
        async fn test_proxy_key_signs_message() {
            let (mut signing_manager, consensus_pk) = init_signing_manager();

            let signed_delegation = signing_manager
                .create_proxy_bls(MODULE_ID.clone(), consensus_pk.clone())
                .await
                .unwrap();
            let proxy_pk = signed_delegation.message.proxy;

            let data_root = Hash256::random();
            let data_root_bytes = data_root.as_fixed_bytes();

            let sig = signing_manager
                .sign_proxy_bls(&proxy_pk.try_into().unwrap(), data_root_bytes)
                .await
                .unwrap();

            // Verify signature
            let domain = compute_domain(CHAIN, COMMIT_BOOST_DOMAIN);
            let signing_root = compute_signing_root(data_root_bytes.tree_hash_root().0, domain);

            let validation_result = verify_bls_signature(&proxy_pk, &signing_root, &sig);

            assert!(
                validation_result.is_ok(),
                "Proxy keypair must produce valid signatures of messages."
            )
        }
    }

    mod test_proxy_ecdsa {
        use cb_common::{
            constants::COMMIT_BOOST_DOMAIN, signature::compute_domain,
            signer::schemes::ecdsa::verify_ecdsa_signature,
        };

        use super::*;

        #[tokio::test]
        async fn test_proxy_key_is_valid_proxy_for_consensus_key() {
            let (mut signing_manager, consensus_pk) = init_signing_manager();

            let signed_delegation = signing_manager
                .create_proxy_ecdsa(MODULE_ID.clone(), consensus_pk.clone())
                .await
                .unwrap();

            let validation_result = signed_delegation.validate(CHAIN);

            assert!(
                validation_result.is_ok(),
                "Proxy delegation signature must be valid for consensus key."
            );

            assert!(
                signing_manager.has_proxy_ecdsa(&signed_delegation.message.proxy),
                "Newly generated proxy key must be present in the signing manager's registry."
            );
        }

        #[tokio::test]
        async fn test_tampered_proxy_key_is_invalid() {
            let (mut signing_manager, consensus_pk) = init_signing_manager();

            let mut signed_delegation = signing_manager
                .create_proxy_ecdsa(MODULE_ID.clone(), consensus_pk.clone())
                .await
                .unwrap();

            let m = &mut signed_delegation.signature.0[0];
            (*m, _) = m.overflowing_add(1);

            let validation_result = signed_delegation.validate(CHAIN);

            assert!(validation_result.is_err(), "Tampered proxy key must be invalid.");
        }

        #[tokio::test]
        async fn test_proxy_key_signs_message() {
            let (mut signing_manager, consensus_pk) = init_signing_manager();

            let signed_delegation = signing_manager
                .create_proxy_ecdsa(MODULE_ID.clone(), consensus_pk.clone())
                .await
                .unwrap();
            let proxy_pk = signed_delegation.message.proxy;

            let data_root = Hash256::random();
            let data_root_bytes = data_root.as_fixed_bytes();

            let sig = signing_manager
                .sign_proxy_ecdsa(&proxy_pk.try_into().unwrap(), data_root_bytes)
                .await
                .unwrap();

            // Verify signature
            let domain = compute_domain(CHAIN, COMMIT_BOOST_DOMAIN);
            let signing_root = compute_signing_root(data_root_bytes.tree_hash_root().0, domain);

            let validation_result = verify_ecdsa_signature(&proxy_pk, &signing_root, &sig);

            assert!(
                validation_result.is_ok(),
                "Proxy keypair must produce valid signatures of messages."
            )
        }
    }
}
