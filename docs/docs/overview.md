---
sidebar_position: 2
---

# Overview

## Background
- Proposer commitments have been an important part of Ethereum’s history and continue to be a powerful unlock for Ethereum validators
- Today, more than 90% of Ethereum validators make a wholesale commitment by outsourcing block production to external third parties via [MEV-Boost](https://github.com/flashbots/mev-boost)
- By outsourcing completely block production, validators lose autonomy over the block. Allowing validators to make more granular commitments unlocks a significant design space and opportunity for validators and Ethereum at large
- There is already great interest in the use cases enabled by granular proposer commitments, for example preconfirmations and inclusion lists
- This interest and the proliferation of different commitment protocols carries an inherent risk of fragmentation and cross-protocol compatibility issues
- Commit-Boost aims to standardize how proposer commitment protocols communicate with the proposer, by providing a unified interface implemented in a single validator sidecar with the goal of reducing fragmentations

## Goals
- Create a neutral, open-source, public good for the safe development and distribution of proposer commitments protocols
- Provide a well-tested, reliable validator sidecar with support for advanced observability and telemetry

## Why Commit-Boost?

### For validators
- Run a single sidecar with support for MEV-Boost and other proposer commitments protocols, such as preconfirmations and inclusion lists
- Out-of-the-box support for metrics reporting and dashboards to have clear insight into what is happening in your validator
- Plug-in system to add custom modules, e.g. receive a notification on Telegram if a relay fails to deliver a block

### For developers
- A modular platform to develop and distribute proposer commitments protocols
- A single API to interact with validators
- Support for hard-forks and new protocol requirements