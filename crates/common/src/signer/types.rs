use std::collections::HashMap;

use derive_more::derive::Deref;

use super::EcdsaSigner;
use crate::{
    commit::request::{SignedProxyDelegationBls, SignedProxyDelegationEcdsa},
    signer::{
        schemes::{bls::BlsPublicKey, ecdsa::EcdsaPublicKey},
        BlsSigner,
    },
};

// For extra safety and to avoid risking signing malicious messages, use a proxy
// setup: proposer creates a new ephemeral keypair which will be used to sign
// commit messages, it also signs a ProxyDelegation associating the new keypair
// with its consensus pubkey When a new commit module starts, pass the
// ProxyDelegation msg and then sign all future commit messages with the proxy
// key for slashing the faulty message + proxy delegation can be used
#[derive(Clone, Deref)]
pub struct BlsProxySigner {
    #[deref]
    pub signer: BlsSigner,
    pub delegation: SignedProxyDelegationBls,
}

#[derive(Clone, Deref)]
pub struct EcdsaProxySigner {
    #[deref]
    pub signer: EcdsaSigner,
    pub delegation: SignedProxyDelegationEcdsa,
}

#[derive(Default)]
pub struct ProxySigners {
    pub bls_signers: HashMap<BlsPublicKey, BlsProxySigner>,
    pub ecdsa_signers: HashMap<EcdsaPublicKey, EcdsaProxySigner>,
}
