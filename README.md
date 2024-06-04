# Commit-Boost
### Note
- Commit-Boost is still in alpha development, all APIs are subject to change
- The code is unaudited and NOT ready for production

## What is Commit-Boost?
- Open source public good that is backwards compatible to help standardize the communication mechanism for the last mile of proposers’ commitments. 
- The goal is to develop and then sustain a standard software that will limit fragmentation, reduce complexity for core devs, and decrease risks for proposers making commitments–but, still allow for open innovation / not limiting designs developed by proposer commitment protocols
- Specifically, Commit-Boost is a new Ethereum validator sidecar focused on standardizing the last mile of communication between validators and third parties. It has been designed with modularity at its core, with the goal of supporting a broad range of different use cases and protocols.
- Read more [here](https://ethresear.ch/t/based-proposer-commitments-ethereum-s-marketplace-for-proposer-commitments/19517)

## Goals
- **Open Source**: Developed in the open and under open-source licensing 
- **Optionality**: Ensure that the final design does not limit innovation or ossify certain downstream stakeholders / proposer commitments
- **Safety**: Thoroughly tested and audited, with full backwards compatibility with previous clients 
- **Modularity**: Allow developers and protocol teams to easily test, iterate, and deploy new protocols and software for proposer commitments without needing to implement everything from scratch 
- **Observability**: Allow node operators to collect and quickly analyze detailed telemetry about sidecar services 
- **Transparency**: Provide open access and good documentations to allow maximal verifiability and ease of integration

## Developing
With Commit-Boost you can:
- Spin up a Commit Module, requesting arbitrary signatures from the proposer (`examples/da_commit.rs`)
- Extend or replace the default BuilderApi implementation (`examples/custom_boost.rs`)
- Subscribe to BuilderApi events and trigger arbitrary pipelines (`examples/alert_hook.rs`)

### High-level architecture
By default, Commit-Boost will start a [MEV-boost](https://github.com/flashbots/mev-boost) compatible service. If any commit module is registered, then a signing manager is also started. The signing manager abstracts away the different signing methods and keystores.

![architecture](docs/architecture.png)

## Roadmap
- [ ] Detailed telemetry and logging
- [ ] Support for additional key managers (web3, ERC-2335, keystores, proxy)
- [ ] Increased modularity of services, including in-process monitoring and extensive configurability

## Acknowledgements
- [MEV boost](https://github.com/flashbots/mev-boost)
- [Reth](https://github.com/paradigmxyz/reth)
- [Lighthouse](https://github.com/sigp/lighthouse)


## License
MIT + Apache-2.0