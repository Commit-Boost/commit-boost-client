# AGENTS.md

Guidance for AI coding agents working in this repository.

## What Commit-Boost is

Commit-Boost is an Ethereum validator sidecar that standardizes how proposers make commitments
to third-party protocols, MEV-boost-style block building being the primary one. It is a Rust
workspace whose release artifact is the `commit-boost` binary, one subcommand per service, run
either as generated Docker services or as native processes.

The services cooperate, wired together by one TOML config file:

- **PBS service**: implements the Builder API toward the consensus client (header retrieval,
  blinded-block submission, validator registration, status) and fans requests out to the
  configured relays, applying selection, validation, and timing logic. Custom PBS builds can
  replace the request/response logic while reusing the service scaffolding.
- **Signer service**: holds validator (consensus) keys and module-requested proxy keys,
  generated behind the signer boundary. It exposes an authenticated HTTP API for signing
  commitment data and never releases private keys; modules receive signatures and signed
  delegation objects only.
- **Commit modules**: separate processes, first- or third-party, that implement commitment
  protocols. They consume the SDK (the workspace's prelude library) to load config, talk to
  the signer, and register metrics. Modules authenticate to the signer with per-module
  pre-shared HMAC secrets from which short-lived JWTs are minted; separate admin credentials
  protect the signer's administrative endpoints.

`commit-boost init` reads the TOML config and generates a Docker Compose setup (services,
networks, an env file carrying generated secrets); each service also runs directly via its own
subcommand, with configuration passed through `CB_*` environment variables. Every service
exposes Prometheus metrics.

## Repository map

The authoritative workspace layout is `[workspace].members` in the root `Cargo.toml`. Roles:

- `bin/`: the `commit-boost` binary and the prelude library that modules import.
- `crates/`: the library crates. Shared config, types, signing, and wire formats live in the
  crate every other crate depends on (`common`); service logic lives in per-service crates;
  compose generation lives in the CLI crate.
- `tests/`: the workspace integration suite (mock relays, validators, signer service).
  Service-behavior regression tests go here; `just test` runs them.
- `benches/`: microbenchmarks and a Docker-based PBS load-benchmark harness (see the
  justfile bench recipes).
- `examples/`: runnable module examples and config presets; docs snippets mirror these, so
  changing an example implies checking the docs that quote it.
- `provisioning/`: Dockerfiles, the build container, the Helm chart, Grafana dashboards.
- `docs/`: the Docusaurus site.
- `api/`: the signer OpenAPI spec. The docs' API page renders it with SwaggerUI fetching the
  main-branch copy from GitHub raw at page load, so spec changes are user-visible on merge and
  the docs build does not validate the spec; unreleased behavior needs its marker inside the
  spec's own description text.
- `.releases/`: one YAML per release naming the released commit; the anchor for every
  version-line question (see Ground truth).
- `justfile`: the canonical developer commands; prefer its recipes over hand-rolled
  invocations.

## Working on the code

- Format with `just fmt`, lint with `just clippy`, run the suite with `just test` (the
  justfile pins its own toolchain and mirrors CI's lint invocation; the recipes are the source
  of truth). Building requires `protoc`; `just install-protoc` provides it. `just build-bin
  <version>` builds through the Docker build container, not the local toolchain; a plain local
  build is `cargo build --release`.
- Match the existing code style: comments are minimal and state constraints, not narration;
  error-binding names differ per crate, so follow the surrounding crate; struct field names
  match wire names.
- Config keys are user-facing API. Only relay entries reject unknown keys (`[[relays]]`,
  including relay entries inside `[[mux]]`); every other config section silently ignores
  them, so a typo or an unreleased key outside a
  relay entry does nothing rather than failing. Adding, renaming, or defaulting a key is a
  compatibility decision, and `config.example.toml` plus the owning docs page change in the
  same commit.
- Wire-visible strings (error bodies, log lines users are told to grep for, metric names and
  labels) are documented surface: changing one means updating the docs pages and OpenAPI specs
  that quote it.

## Ground truth

- The code is the source of truth. A documentation claim is wrong until the code proves it;
  when reviewing or writing docs, ground every behavioral claim in a specific code location.
- Two lines always exist: the **released line** and **main**. The released commit is the
  `commit:` field of the semver-newest file in `.releases/` (file names are exact tags,
  including `-rcN` pre-releases; order by semantic version, never lexically or by mtime, since
  `v0.9.*` sorts after `v0.10.*` as a string; naming rules in `.releases/README.md`). The docs
  voice tracks the newest stable (non-rc) release. Release pins live on release-branch
  lineages and are generally **not ancestors of main**, so never use `git merge-base
  --is-ancestor` to decide whether a feature is released. Probe content instead:
  `git show <release-commit>:<path>`.
- While the docs site is unversioned (no `versioned_docs/` under `docs/`), one tree serves
  users of the released binaries, so docs speak in the **released version's voice**. Behavior
  that exists only on main is marked with a `:::info Unreleased` admonition (for sections) or
  an inline marker naming the first version that will ship it, `(unreleased, from vX.Y)`,
  stated once and tersely. When that release ships, deleting its markers is the whole docs
  update. If the site gains versioned docs, per-version trees supersede this policy.
- `config.example.toml` is copied verbatim by users of released binaries. Unreleased keys
  appear there **commented out**, with the unreleased marker in the comment: an uncommented
  unreleased key either breaks released binaries at startup (inside relay entries) or is
  silently ignored (everywhere else), and both mislead.
- Example and log values must be reproducible by a real binary: version strings exactly as
  binaries self-report them, commit hashes equal to the release commit (annotated tag objects
  are never printable by any build), timestamps/slots/block numbers arithmetically consistent
  with each other, placeholder hosts from RFC 2606 (`example.com`), `https://` schemes, and
  secrets shown truncated and obviously non-functional.

## Writing style (docs and prose)

- Plain operator prose, American English. No em dashes. No "Note that" lead-ins. No marketing
  or filler vocabulary (leverage, seamlessly, robust, powerful, comprehensive, utilize). No
  sentences that announce what the reader is about to read.
- Don't explain absences. When removing content, splice the neighbors and move on; never add
  text justifying why something is no longer there.
- Terminology: "PBS service", "Signer service"; "commit module(s)" in running prose ("Commit
  Modules" only in headings; never hyphenated). Heading case follows the page's dominant style.
- **One home per fact.** Every contract or nuance gets one full statement on the page that
  owns its topic; every other mention is a one-line pointer to that home. Before adding a
  fact, find where existing mentions of the topic already point and follow them. As of
  writing: `configuration.md` owns config semantics (including hot reload, TLS, rate limiting,
  keystore layouts); `mux-key-loaders.md` owns mux mechanics; `running/binary.md` owns
  environment variables; `metrics-catalog.md` owns per-metric reference rows;
  `troubleshooting.md` owns log walkthroughs and symptom tables; `developing/*` own SDK and
  module-API contracts. `config.example.toml` comments stay one line per key plus a docs link:
  it is the annotated reference for values, not a second prose home.
- Long runs of bold-label bullets are hard to scan; prefer prose or a real table.

## Verifying changes

- Docs build gate: run the docs build the way CI does (`.github/workflows/`; today
  `npm install && npm run build` in `docs/`). Broken links fail the build; broken
  anchors only warn, so also grep the build output case-insensitively for "broken anchor".
- Parse every fenced `toml`/`yaml`/`json` block in changed pages, and `config.example.toml`
  itself (python `tomllib` / `yaml.safe_load`).
- Spellcheck prose with code spans and fences stripped.
- Examples must run. Prefer executing a documented flow (generate the compose setup from the
  documented config, perform the documented auth round-trip) over reading it; executed
  walkthroughs find breaks that reading does not. Check Rust snippets against the real SDK
  signatures in the workspace or the `examples/` crates they mirror.

## Trap classes

Recurring bug shapes in this repository. Check for the class, not just the past instance.

- **Released-vs-main drift**: a behavior claim may hold on only one line. Any claim about wire
  formats, error bodies, config keys, or metrics needs checking against both the released
  commit and main; cite the code location that supports it.
- **Secret vs token**: several environment variables hold HMAC *secrets* from which
  short-lived tokens are minted. Calling them tokens produces curl examples that can never
  authenticate. Verify what the receiving middleware actually validates before documenting an
  auth flow.
- **Startup-frozen environment**: environment variables are read at process start; reload
  endpoints cannot observe new values. Verify the actual data flow before documenting any
  hot-rotation or reload pattern, and state what a reload can and cannot pick up.
- **Silently ignored config**: outside relay entries, unknown config keys are accepted and
  dropped, so a misplaced or misspelled key looks configured while doing nothing. Verify a key
  is consumed at the nesting level where the docs place it.
- **Dead knobs**: config fields, chart values, or flags consumed by no code path (Helm
  templates are especially prone). Verify each documented option is actually read before
  listing it.
- **Documented intent, not behavior**: comments and older docs sometimes describe features
  that were planned but never implemented. Trust only the code path you can cite.

## Maintenance of this file

This file holds only orientation, conventions, methods, and trap classes, so it stays valid as
features are added. If an edit records a fact about a specific version or feature, that fact
belongs in the docs themselves, a code comment, or the issue tracker instead.
