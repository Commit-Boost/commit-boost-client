---
id: 0005
title: "Docker-based module system with TOML configuration and HTTP signer API"
status: "accepted"  # proposed | accepted | deprecated | superseded
date: 2026-05-11T20:10:01.568Z
---

# ADR-0005: Docker-based module system with TOML configuration and HTTP signer API

Modules are Docker containers configured via TOML `[[modules]]` entries. Each module gets environment variables: `MODULE_ID`, `MODULE_JWT`, `SIGNER_URL`, `CB_CONFIG`. Communication with the Signer uses JWT-authenticated HTTP (defined in `cb-common::commit`). Builder API modules implement the `BuilderApi` trait via a generic type parameter on `PbsService::run`, allowing custom routing and bid processing.

## Context

Commit-Boost needs a module system where third-party developers can build proposer commitment protocols (preconfirmations, inclusion lists) without modifying the core codebase. Modules need to be independently deployable and language-agnostic.

## Consequences

Module authors don't need to know Rust. Any language with HTTP + JWT works. Module lifecycle managed externally (Docker). Con: requires Docker; module config is TOML-specific; no compile-time type checking for module configuration.

## Alternatives considered

- Config-only (static TOML)
- Full gRPC API with protobuf types
- C library FFI bindings