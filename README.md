# Commit-Boost

[![Ci](https://github.com/Commit-Boost/commit-boost-client/actions/workflows/ci.yml/badge.svg)](https://github.com/Commit-Boost/commit-boost-client/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://commit-boost.github.io/commit-boost-client/)
[![Release](https://img.shields.io/github/v/release/Commit-Boost/commit-boost-client)](https://github.com/Commit-Boost/commit-boost-client/releases)
[![Chat](https://img.shields.io/endpoint?color=neon&logo=telegram&label=chat&url=https%3A%2F%2Ftg.sumanjay.workers.dev%2F%2BPcs9bykxK3BiMzk5)](https://t.me/+Pcs9bykxK3BiMzk5)
[![X](https://img.shields.io/twitter/follow/Commit_Boost)](https://x.com/Commit_Boost)

A new Ethereum validator sidecar focused on standardizing the last mile of communication between validators and third-party protocols.

## Overview
Commit-Boost is a modular sidecar that allows Ethereum validators to opt-in to different commitment protocols

### For node operators
- Run a single sidecar with support for MEV-Boost and other proposer commitments protocols, such as preconfirmations and inclusion lists
- Out-of-the-box support for metrics reporting and dashboards to have clear insight into what is happening in your validator
- Plug-in system to add custom modules, e.g. receive a notification on Telegram if a relay fails to deliver a block

### For developers
- A modular platform to develop and distribute proposer commitments protocols
- A single API to interact with validators
- Support for hard-forks and new protocol requirements

## Get started
- [Node operators](https://commit-boost.github.io/commit-boost-client/category/get-started)
- [Developers](https://commit-boost.github.io/commit-boost-client/category/developing). Check out also the [examples](/examples)

## Audit
Commit-Boost received an audit from [Sigma Prime](https://sigmaprime.io/). Find the report [here](/audit/Sigma_Prime_Commit_Boost_Client_Security_Assessment_Report_v2_0.pdf).

## Acknowledgements
- [MEV boost](https://github.com/flashbots/mev-boost)
- [Reth](https://github.com/paradigmxyz/reth)
- [Lighthouse](https://github.com/sigp/lighthouse)

## License
MIT + Apache-2.0
