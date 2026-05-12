---
id: 0004
title: "Fork-versioned response pattern for hard fork compatibility"
status: "accepted"  # proposed | accepted | deprecated | superseded
date: 2026-05-11T20:09:46.785Z
---

# ADR-0004: Fork-versioned response pattern for hard fork compatibility

Use `ForkVersionedResponse<T>` (from lighthouse) as the response wrapper for `get_header` and `submit_block`. The wrapper carries a fork version discriminator (`ForkName`). Route handlers pattern-match on fork to dispatch to the correct type variant. Two API versions: V1 (standard, route `/eth/v1/builder/`) and V2 (extended with execution requests, route `/eth/v2/builder/`).

## Context

The Builder API must handle multiple Ethereum hard forks. Block headers have different shapes in Electra (no execution requests) vs Fulu (with execution requests). Need to support both forks simultaneously during transition periods without duplicating endpoints.

## Consequences

Single endpoint handles all forks. Client/server negotiate fork version via response wrapper. Adding a new fork (e.g., Fulu) requires extending match arms but not new endpoints. V2 builder path exists for execution-request-aware endpoint. Trade-off: fork dispatch is implicit in response handling; wrong fork mismatch is a runtime error, not caught at compile time.

## Alternatives considered

- Separate endpoints per fork (e.g., /eth/v1/builder/header and /eth/v2/builder/header_electra)
- Always use the latest fork format, rejecting old formats
- Fully dynamic dispatch based on slot number