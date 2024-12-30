---
id: introduction
sidebar_position: 1
slug: /
---

# Introduction

import CommitBoostLogo from '/img/logo.png';
import Overview from '/img/overview.png';

<img src={CommitBoostLogo} alt="Commit Boost Logo" style={{width: 500, borderRadius: '20px'}} />

<br/>
<br/>

Commit-Boost is a new Ethereum validator sidecar focused on standardizing the communication between validators and third-party protocols. This open-source public good is fully compatible with [MEV-Boost](https://github.com/flashbots/mev-boost) and acts as a light-weight platform to allow validators to safely make commitments.

Commit-Boost runs as a single sidecar composed of multiple modules:

<img src={Overview} alt="Commit Boost Overview" style={{width: 600, borderRadius: '20px'}} />

<br/>
<br/>

Commit-Boost is being developed in Rust from scratch, and has been designed with safety and modularity at its core, with the goal of not limiting the market downstream including stakeholders, flows, proposer commitments, enforcement mechanisms, etc.
