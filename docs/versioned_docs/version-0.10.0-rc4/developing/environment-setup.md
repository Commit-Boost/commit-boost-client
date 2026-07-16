---
sidebar_position: 3
---
# Environment setup

## Dirk signer

In order to test Commit-Boost with a Dirk signer, you need to have a running Dirk instance. You can find a complete step-by-step guide on how to setup one in the Dirk's docs [here](https://github.com/attestantio/dirk/blob/master/docs/distributed_key_generation.md).

If you are using a custom certificate authority, don't forget to add the CA certificate to the TOML config under `signer.dirk.ca_cert_path`.
