// TODO(David): Remove module
pub use super::schemes::bls::BlsSigner;
pub type ConsensusSigner = BlsSigner;
pub type EcdsaSigner = super::schemes::ecdsa::EcdsaSigner;
