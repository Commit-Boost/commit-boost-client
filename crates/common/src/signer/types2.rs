use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct PrismKeystore {
    pub crypto: Crypto,
    pub uuid: String,
    pub version: u8,
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Crypto {
    pub kdf: KdfModule,
    pub checksum: ChecksumModule,
    pub cipher: CipherModule,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CipherModule {
    pub function: String,
    pub message: String,
    pub params: CipherParams,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CipherParams {
    pub iv: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KdfModule {
    pub function: String,
    pub message: String,
    pub params: KdfParams,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KdfParams {
    pub c: u32,
    pub dklen: u32,
    pub prf: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChecksumModule {
    pub function: String,
    pub message: String,
    pub params: ChecksumModuleParams,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChecksumModuleParams {
    a: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Signers {
    pub private_keys: Vec<String>,
    pub public_keys: Vec<String>,
}
