---
sidebar_position: 2
---

# Overview

## Background
- Proposer commitments have been an important part of Ethereum’s history. Today, we already see the power of commitments where over 90% of validators give up their autonomy and make a wholesale commitment that outsources block building to a sophisticated actor called a block builder.
- However, most are starting to agree on a common denominator: in the future, beacon proposers will face a broader set of options of what they may “commit" to–be it inclusions lists or preconfs or other types of commitments such as long-dated blockspace futures–compared to just an external or local payload they see today.
- A recent post from Barnabe captures this well; during block construction, the validator “…creates the specs, or the template, by which the resulting block must be created, and the builders engaged by the proposer are tasked with delivering the block according to its specifications”.
- While this all seems great, the challenge is that many teams building commitments are creating new sidecars driving fragmentation and risks for Ethereum.
- For Ethereum, there are going to be significant challenges and increased risks during upgrades if there are a handful of sidecars validators are running.
- For validators, these risks potentially take us to a world where proposers will need to make decisions on which teams to “bet on” and which sidecars they will need to run to participate in what those teams are offering.
- For homestakers, this is difficult and they likely will be unable to participate in more than one of these commitments.
- For sophisticated actors, this increases the attack vector and operational complexity as more and more sidecars are required to be run.
- Another side effect of this is validators are somewhat locked into using a specific sidecar due to limited operational capacity and the switching costs of running a different sidecar (i.e., vendor lock-in). The higher the switching costs, the more embedded network effects could become if these sidecars only support certain downstream actors / proposer commitment protocols.
- This also could create a dynamic where core out-of-protocol infrastructure supporting Ethereum which should be a public good, starts being used for monetization, distribution, or other purposes.
- Commit-Boost aims to standardize how proposer commitment protocols communicate with the proposer, by providing a unified interface implemented in a single validator sidecar with the goal of reducing fragmentation.

## Goals
- Unify behind a software / standard to reduce fragmentation risks for Ethereum and its validators, while ensuring open innovation downstream from the proposer can flourish.
- Create a neutral, open-source, public good for the safe development and distribution of proposer commitments protocols.
- Provide a well-tested, reliable validator sidecar with support for advanced observability and telemetry.

## Why Commit-Boost?

### For validators
- Run a single sidecar with support for MEV-Boost and other proposer commitments protocols, such as preconfirmations and inclusion lists.
- Out-of-the-box support for metrics reporting and dashboards to have clear insight into what is happening in your validator.
- Plug-in system to add custom modules, e.g. receive a notification on Telegram if a relay fails to deliver a block.

### For developers
- A modular platform to develop and distribute proposer commitments protocols.
- A single API to interact with validators.
- Support for hard-forks and new protocol requirements.
