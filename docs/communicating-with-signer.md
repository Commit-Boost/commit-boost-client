# Communicating with the Signer Module
The core of any commitment module is its interaction with the signer API. 
Note:  Below examples will show snippets in Rust, however any language that allows for instantiation of an http client will work.
Note: A more complete example of the Signer Module usage can be found here
## Authentication 
Communication between the proposer commitment module and Commit-Boost is authenticated with a JWT token. This token will be provided as `CB_JWT_<MODULE_NAME>` by the Commit-Boost launcher at initialization time.
To discover which pubkeys a commitment can be made for call `/signer/v1/get_pubkeys`:
```use serde::Deserialize;

#[derive(Deserialize)]
pub struct GetPubkeysResponse {
    pub consensus: Vec<BlsPublicKey>,
    pub proxy: Vec<BlsPublicKey>,
}

let url = format!("{}/signer/v1/get_pubkeys", COMMIT_BOOST_HOST);

let pubkeys = reqwest::get(url)
    .await
    .unwrap()
    .json::<GetPubkeysResponse>()
    .unwrap()
    .consensus;```
Once you'd like to receive a signature to create a commitment, you'd create the request like so:
```use serde_json::json;
use alloy_rpc_types_beacon::BlsSignature

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub id: String,
    pub pubkey: BlsPublicKey,
    pub is_proxy: bool,
    pub object_root: [u8; 32],
}

let sign_request_body = json!({
	    "id": "0",
	    "pubkey": "0xa02ccf2b03d2ec87f4b2b2d0335cf010bf41b1be29ee1659e0f0aca4d167db7e2ca1bf1d15ce12c1fac5a60901fd41db",
	    "is_proxy": false,
	    "object_root": "your32commitmentbyteshere0000000"
	});

let url = format!("{}/signer/v1/request_signature", COMMIT_BOOST_HOST);
let client = reqwest::Client::new();
let res = client
	.post(url)
	.json(sign_request_body)
	.send()
	.await
	.unwrap();
	
let signature_bytes = res.bytes().await.unwrap();
let signature = BlsSignature::from_slice(&signature_bytes);```