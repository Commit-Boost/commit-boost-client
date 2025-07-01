# Requesting Preconfirmation Signatures with Commit Boost

When you create a new validator on the Ethereum network, one of the steps is the generation of a new BLS private key (commonly known as the "validator key" or the "signer key") and its corresponding BLS public key (the "validator pubkey", used as an identifier). Typically this private key will be used by an Ethereum consensus client to sign things such as attestations and blocks for publication on the Beacon chain. These signatures prove that you, as the owner of that private key, approve of the data being signed. However, as general-purpose private keys, they can also be used to sign *other* arbitrary messages not destined for the Beacon chain.

Commit Boost takes advantage of this by offering a standard known as **preconfirmations**. These are arbitrary messages (albeit with some important rules), similar to the kind used on the Beacon chain, that have been signed by one of the owner's private keys. Modules interested in leveraging Commit Boost's preconfirmations can construct their own data in whatever format they like and request that Commit Boost's **signer service** generate a signature for it with a particular private key. The module can then use that signature to verify the data was signed by that user.

Commit Boost supports preconfirmation signatures for both BLS private keys (identified by their public key) and ECDSA private keys (identified by their Ethereum address).


## Rules of Preconfirmation Signatures

Preconfirmation signatures produced by Commit Boost's signer service conform to the following rules:

- Signatures are **unique** to a given EVM chain (identified by its [chain ID](https://chainlist.org/)). Signatures generated for one chain will not work on a different chain.
- Signatures are **unique** to Commit Boost preconfirmations. The signer service **cannot** be used to create signatures that could be used for other applications, such as for attestations on the Beacon chain. While the signer service has access to the same validator private keys used to attest on the Beacon chain, it cannot create signatures that would get you slashed on the Beacon chain.
- Signatures are **unique** to a particular module. One module cannot, for example, request an identical payload as another module and effectively "forge" a signature for the second module; identical payloads from two separate modules will result in two separate signatures.
- The data payload being signed must be a **32-byte array**, typically serializd as a 64-character hex string with an optional `0x` prefix. The value itself is arbitrary, as long as it has meaning to the requester - though it is typically the 256-bit hash of some kind of data.
- If requesting a signature from a BLS key, the resulting signature will be a standard BLS signature (96 bytes in length).
- If requesting a signature from an ECDSA key, the resulting signature will be a standard Ethereum RSV signature (65 bytes in length).


## Configuring a Module for Preconfirmations

Commit Boost's signer service must be configured prior to launching to expect requests from your module. There are two main parts:

1. An entry for your module into [Commit Boost's configuration file](../get_started/configuration.md#custom-module). This must include a unique ID for your module, the line `type = "commit"`, and include a unique [signing ID](#the-signing-id) for your module. Generally you should provide values for these in your documentation, so your users can reference it when configuring their own Commit Boost node.

2. A JWT secret used by your module to authenticate with the signer in HTTP requests. *{Placeholder for more details on setting this here}*

Once the user has configured both Commit Boost and your module with these settings, your module will be able to authenticate with the signer service and request signatures.


## The Signing ID

Your module's signing ID is a 32-byte value that is used as a unique identifier within the signing process. Preconfirmation signatures incorporate this value along with the data being signed as a way to create signatures that are exclusive to your module, so other modules can't maliciously construct signatures that appear to be from your module. Your module must have this ID incorporated into itself ahead of time, and the user must include this same ID within their Commit Boost configuration file section for your module. Commit Boost does not maintain a global registry of signing IDs, so this is a value you should provide to your users in your documentation.

The Signing ID is decoupled from your module's human-readable name (the `module_id` field in the Commit Boost configuration file) so that any changes to your module name will not invalidate signatures from previous versions. Similarly, if you don't change the module ID but *want* to invalidate previous signatures, you can modify the signing ID and it will do so. Just ensure your users are made aware of the change, so they can update it in their Commit Boost configuration files accordingly.


## Structure of a Signature

The form preconfirmation signatures take depends on the type of signature being requested.


### BLS Signatures

Signatures requested from BLS keys take the standard form (96-byte values). Generating them is done by constructing a 32-byte signing root from the hash of an SSZ Merkle tree that , which is typical of BLS signatures used by the Beacon chain:











## Requesting a Signature from the Signer
