---
id: 0001
title: "Signer as separate service with JWT-auth and proxy key model"
status: "accepted"  # proposed | accepted | deprecated | superseded
date: 2026-05-11T20:08:58.555Z
---

# ADR-0001: Signer as separate service with JWT-auth and proxy key model

Signer runs as a separate service holding consensus keys. Modules authenticate via per-module JWT secrets. Signer exposes HTTP endpoints for: BLS consensus signing, BLS proxy signing, ECDSA proxy signing, proxy key generation. Proxy keys are derived from consensus keys using a signing ID + module ID. Optional Dirk backend for remote signing with local proxy key generation fallback.

## Context

Commit-Boost modules (preconfirmations, inclusion lists, etc.) need to sign messages with validator consensus keys. Giving modules direct access to keys is insecure — modules are third-party Docker containers. Need a way to sign without key exposure, and to derive per-module keys for non-consensus signing.

## Consequences

Modules never hold or see consensus private keys. Signer can be a separate process with its own security boundary. JWT auth per module enables access control and revocation. Rate limiting on JWT failure prevents brute-force. Proxy key model allows modules to generate delegated keys without exposing consensus keys. Trade-off: extra network hop for every signature request, operational complexity of running signer sidecar.

## Alternatives considered

- Embed signing in each module (each module holds its own keys)
- Use a shared in-process signing library
- Use an external Web3Signer-compatible service only