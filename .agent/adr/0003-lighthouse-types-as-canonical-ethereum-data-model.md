---
id: 0003
title: "Lighthouse types as canonical Ethereum data model"
status: "accepted"  # proposed | accepted | deprecated | superseded
date: 2026-05-11T20:09:30.453Z
---

# ADR-0003: Lighthouse types as canonical Ethereum data model

Use Lighthouse (`lh_types`, `lh_eth2`) as the canonical source for Ethereum beacon chain types. Types are aliased through `cb-common::pbs::types` (e.g., `SignedBlindedBeaconBlock = lh_types::SignedBlindedBeaconBlock<MainnetEthSpec>`). This ensures wire-format compatibility with Lighthouse beacon nodes and benefits from Lighthouse's fork-aware dispatch.

## Context

Commit-Boost implements the Ethereum Builder API which uses SSZ-serialized beacon chain types (blinded blocks, execution payloads, builder bids). Need canonical type definitions that match the beacon node's encoding. Types must handle fork transitions (Electra → Fulu) where block body shape changes.

## Consequences

All Beacon API types (SignedBlindedBeaconBlock, ExecutionPayloadHeader, etc.) are lighthouse type aliases. Fork-aware types like ForkVersionedResponse come from lighthouse. SSZ serialization, tree-hash derivation, and fork dispatch all use lighthouse infrastructure. Trade-off: lighthouse dependency is heavyweight; version coupling means lighthouse upgrades may force Commit-Boost upgrades even if Builder API didn't change.

## Alternatives considered

- Define own Ethereum types from spec
- Use alloy/ethereum-consensus crate
- Use reth primitives