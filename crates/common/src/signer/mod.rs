pub mod schemes;
pub mod types;

pub use schemes::{
    bls::{BlsPublicKey, BlsSecretKey, BlsSignature, BlsSigner},
    ecdsa::{EcdsaPublicKey, EcdsaSecretKey, EcdsaSignature, EcdsaSigner},
};

pub type ConsensusSigner = BlsSigner;
