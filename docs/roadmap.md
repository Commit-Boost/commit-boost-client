# Discussion Points / Roadmap
- Signer: Least explored area, right now Commit-Boost is built to leverage a proxy key of the validator but we are post ETH CC / this post hope to engage on how best to safely design this

- Docker and Binary: right now we just have support for Docker to instantiate modules, but shortly after ETH CC we plan to expand this to support binary (i.e., both Docker and binary will be enabled allowing the proper to select its preferred approach given the set-up)

- More detailed telemetry and logging: We have some standard metrics reporting already, but plan to continue to expand this based on feedback / development work from a few teams across the community

- Support for additional key managers (web3signer, ERC-2335, keystores, proxy): Right now we just have support for remote key signers, but are expanding this post ETH CC alongside the broader R&D efforts for the signer

- Post ETH CC we plan to Increase modularity for services, including in-process monitoring and extensive configurability by the validator

- Support both BLS and ECDSA