---
id: 0002
title: "Mux-based relay routing with pubkey-to-config HashMap"
status: "accepted"  # proposed | accepted | deprecated | superseded
date: 2026-05-11T20:09:15.478Z
---

# ADR-0002: Mux-based relay routing with pubkey-to-config HashMap

PBS Mux system: each mux has an id, a list of validator pubkeys, a relay list, and optional timeout overrides. `PbsState::mux_config_and_relays(pubkey)` does O(1) HashMap lookup to find the mux for a given validator. Mux pubkeys loaded from: static JSON file, HTTP endpoint, or Registry (Lido CSM/curated, SSV operator). Registry muxes support auto-refresh on a configurable interval. Default relay list used for pubkeys not in any mux.

## Context

Node operators run validators with different needs: some need fast relay response, others run timing games, some belong to SSV clusters or Lido curated modules. A single relay configuration for all validators is too coarse. Need to route different validator pubkeys to different relay sets with different timing/config.

## Consequences

Validators can be grouped into different relay/timing configurations without running multiple sidecars. Registry-based muxes (Lido, SSV) auto-discover pubkeys, reducing config maintenance. Mux pubkey sets must be disjoint (validated at config load). Config reload updates mux mappings live. Trade-off: config complexity increases with mux count; mux config is eagerly loaded at startup (blocking).

## Alternatives considered

- Single flat relay list for all validators
- Per-validator config file with all relay settings
- Dynamic relay selection based on bid history/performance