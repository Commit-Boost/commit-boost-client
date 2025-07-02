# Requesting Proposer Commitment Signatures with Commit Boost

When you create a new validator on the Ethereum network, one of the steps is the generation of a new BLS private key (commonly known as the "validator key" or the "signer key") and its corresponding BLS public key (the "validator pubkey", used as an identifier). Typically this private key will be used by an Ethereum consensus client to sign things such as attestations and blocks for publication on the Beacon chain. These signatures prove that you, as the owner of that private key, approve of the data being signed. However, as general-purpose private keys, they can also be used to sign *other* arbitrary messages not destined for the Beacon chain.

Commit Boost takes advantage of this by offering a standard known as **proposer commitments**. These are arbitrary messages (albeit with some important rules), similar to the kind used on the Beacon chain, that have been signed by one of the owner's private keys. Modules interested in leveraging Commit Boost's proposer commitments can construct their own data in whatever format they like and request that Commit Boost's **signer service** generate a signature for it with a particular private key. The module can then use that signature to verify the data was signed by that user.

Commit Boost supports proposer commitment signatures for both BLS private keys (identified by their public key) and ECDSA private keys (identified by their Ethereum address).


## Rules of Preconfirmation Signatures

Preconfirmation signatures produced by Commit Boost's signer service conform to the following rules:

- Signatures are **unique** to a given EVM chain (identified by its [chain ID](https://chainlist.org/)). Signatures generated for one chain will not work on a different chain.
- Signatures are **unique** to Commit Boost proposer commitments. The signer service **cannot** be used to create signatures that could be used for other applications, such as for attestations on the Beacon chain. While the signer service has access to the same validator private keys used to attest on the Beacon chain, it cannot create signatures that would get you slashed on the Beacon chain.
- Signatures are **unique** to a particular module. One module cannot, for example, request an identical payload as another module and effectively "forge" a signature for the second module; identical payloads from two separate modules will result in two separate signatures.
- The data payload being signed must be a **32-byte array**, typically serializd as a 64-character hex string with an optional `0x` prefix. The value itself is arbitrary, as long as it has meaning to the requester - though it is typically the 256-bit hash of some kind of data.
- If requesting a signature from a BLS key, the resulting signature will be a standard BLS signature (96 bytes in length).
- If requesting a signature from an ECDSA key, the resulting signature will be a standard Ethereum RSV signature (65 bytes in length).


## Configuring a Module for Proposer Commitments

Commit Boost's signer service must be configured prior to launching to expect requests from your module. There are two main parts:

1. An entry for your module into [Commit Boost's configuration file](../get_started/configuration.md#custom-module). This must include a unique ID for your module, the line `type = "commit"`, and include a unique [signing ID](#the-signing-id) for your module. Generally you should provide values for these in your documentation, so your users can reference it when configuring their own Commit Boost node.

2. A JWT secret used by your module to authenticate with the signer in HTTP requests. This must be a string that both the Commit Boost signer can read and your module can read, but no other modules should be allowed to access it. The user should be responsible for determining an appropriate secret and providing it to the Commit Boost signer service securely; your module will need some way to accept this, typically via a command line argument that accepts a path to a file with the secret or as an environment variable.

Once the user has configured both Commit Boost and your module with these settings, your module will be able to authenticate with the signer service and request signatures.


## The Signing ID

Your module's signing ID is a 32-byte value that is used as a unique identifier within the signing process. Preconfirmation signatures incorporate this value along with the data being signed as a way to create signatures that are exclusive to your module, so other modules can't maliciously construct signatures that appear to be from your module. Your module must have this ID incorporated into itself ahead of time, and the user must include this same ID within their Commit Boost configuration file section for your module. Commit Boost does not maintain a global registry of signing IDs, so this is a value you should provide to your users in your documentation.

The Signing ID is decoupled from your module's human-readable name (the `module_id` field in the Commit Boost configuration file) so that any changes to your module name will not invalidate signatures from previous versions. Similarly, if you don't change the module ID but *want* to invalidate previous signatures, you can modify the signing ID and it will do so. Just ensure your users are made aware of the change, so they can update it in their Commit Boost configuration files accordingly.


## Structure of a Signature

The form proposer commitment signatures take depends on the type of signature being requested. BLS signatures take the [standard form](https://eth2book.info/latest/part2/building_blocks/signatures/) (96-byte values). ECDSA (Ethereum EL) signatures take the [standard Ethereum ECDSA `r,s,v` signature form](https://forum.openzeppelin.com/t/sign-it-like-you-mean-it-creating-and-verifying-ethereum-signatures/697). In both cases, the data being signed is a 32-byte hash - the root hash of an SSZ Merkle tree, described below:

<center>

<img src="../res/img/prop_commit_tree.png" width="800">

</center>

where:

- `Request Data` is a 32-byte array that serves as the data you want to sign. This is typically a hash of some more complex data on its own that your module constructs.

- `Signing ID` is your module's 32-byte signing ID. The signer service will load this for your module from its configuration file.

- `Domain` is the 32-byte output of the [compute_domain()](https://eth2book.info/capella/part2/building_blocks/signatures/#domain-separation-and-forks) function in the Beacon specification. The 4-byte domain type in this case is not a standard Beacon domain type, but rather Commit Boost's own domain type: `0x6D6D6F43`.

The data signed in a proposer commitment is the 32-byte root of this tree (the green `Root` box). Note that calculating this will involve calculating the Merkle Root of two separate trees: first the blue data subtree (with the original request data and the signing ID) to establish the blue `Root` value, and then again with a tree created from that value and the `Domain`. 

Many languages provide libraries for computing the root of an SSZ Merkle tree, such as [fastssz for Go](https://github.com/ferranbt/fastssz) or [tree_hash for Rust](https://docs.rs/tree_hash/latest/tree_hash/). When verifying proposer commitment signatures, use a library that supports Merkle tree root hashing, the `compute_domain()` operation, and validation for signatures generated by your key of choice.


## Requesting a Proposer Commitment from the Signer

Prior to requesting a signature from the signer service, first ensure that Commit Boost has been [configured](#configuring-a-module-for-proposer-commitments) with your module's signing ID and JWT secret.

The signer service can be accessed by an HTTP API. In Docker mode, this will be within the `cb_signer` container at the `/signer/v1/request_signature` route (for example, using the default port of `20000`, the endpoint will be `http://cb_signer:20000/signer/v1/request_signature`). Submitting a request must be done via the `POST` method.


### Headers

- Set `Content-Type` set to `application/json`.
- Set `Accept` to `application/json`, as responses are quoted strings. Other formats are not currently supported.
- Set `Authorization` to a standard JWT string representing your module's JWT authentication information. For the claims, you can add a `module` claim indicating the human-readable name of your module.


### BLS Proposer Keys

If requesting a signature directly from a proposer pubkey, use the following body specification:

```json
{
    "type": "consensus",
    "pubkey": "0x1234abcd...",
    "object_root": "0x01020304..."
}
```

where:

- `pubkey` is the 48-byte BLS public key, with optional `0x` prefix, of the proposer key that you want to request a signature from.
- `object_root` is the 32-byte data you want to sign, with optional `0x` prefix.


### BLS Proxy Keys

If requesting a signature indirectly from a proposer key via a [proxy key](./commit-module.md#with-a-proxy-key), use the following body specification:

```json
{
    "type": "proxy_bls",
    "proxy": "0x1234abcd...",
    "object_root": "0x01020304..."
}
```

where:

- `proxy` is the 48-byte BLS public key, with optional `0x` prefix, of the proxy key that you want to request a signature from.
- `object_root` is the 32-byte data you want to sign, with optional `0x` prefix.


### ECDSA Proxy Keys

**NOTE:** ECDSA proxy key support is not available when using Dirk.

If requesting a signature indirectly from an Ethereum private key via a [proxy key](./commit-module.md#with-a-proxy-key), use the following body specification:

```json
{
    "type": "proxy_ecdsa",
    "proxy": "0x1234abcd...",
    "object_root": "0x01020304..."
}
```

where:

- `proxy` is the 20-byte Ethereum address of the proxy key, with optional `0x` prefix, of the ECDSA private key that you want to request a signature from.
- `object_root` is the 32-byte data you want to sign, with optional `0x` prefix.


### Response

The response for any of the above will be one of the following, provided in plaintext format (not JSON).


#### `200 OK`

A successful signing request, with the signature provided as a plaintext quoted hex-encoded string, with a `0x` prefix. For example, the response body would look like:
```
"0xa43e623f009e615faa3987368f64d6286a4103de70e9a81d82562c50c91eae2d5d6fb9db9fe943aa8ee42fd92d8210c1149f25ed6aa72a557d74a0ed5646fdd0e8255ec58e3e2931695fe913863ba0cdf90d29f651bce0a34169a6f6ce5b3115"
```

#### `401 Unauthorized`

Your module did not provide a JWT string in the request's authorization header, or the JWT string was not configured in the signer service's configuration file as belonging to your module.


#### `400 Bad Request`

This can occur in several scenarios:

- You requested an operation while using the Dirk signer mode instead of locally-managed signer mode, but Dirk doesn't support that operation.
- Something went wrong while preparing your request; the error text will provide more information.


#### `502 Bad Gateway`

The signer service is running in Dirk signer mode, but Dirk could not be reached.


#### `404 Not Found`

You either requested a route that doesn't exist, or you requested a signature from a key that does not exist.


#### `429 Too Many Requests`

Your module attempted and failed JWT authentication too many times recently, and is currently timed out. It cannot make any more requests until the timeout ends.


#### `500 Internal Server Error`

Your request was valid, but something went wrong internally that prevented it from being fulfilled.