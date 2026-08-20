# Used ONLY by fmt/fmt-check: rustfmt.toml relies on nightly-only options.
# check/clippy/test run on stable via rust-toolchain.toml, so lints always
# match the shipped compiler.
fmt_toolchain := "nightly-2026-01-01"

# Used ONLY to resolve dependency updates: min-publish-age needs a newer
# nightly than the fmt pin above.
resolver_toolchain := "nightly-2026-06-21"

[doc("""
  Update dependencies under the publish-age cooldown (.cargo/config.toml):
  versions published less than 14 days ago are excluded from resolution.
  Resolution done on stable (cargo add, plain cargo update) is NOT covered;
  this recipe is the intended path for routine updates. Git dependencies
  have no publish age and are refreshed WITHOUT any cooldown: review their
  lockfile rev changes manually.
""")]
update *args:
  rustup toolchain install {{resolver_toolchain}} > /dev/null 2>&1 &&   cargo +{{resolver_toolchain}} update -Z min-publish-age {{args}}

[doc("""
  Escape hatch for an urgent update to a version younger than the cooldown,
  e.g. `just update-allow h2 0.4.16`. The bypass applies to the WHOLE
  resolution of this invocation (transitive picks included), so review the
  full Cargo.lock diff, not just the target package.
""")]
update-allow package version:
  @echo "NOTE: the cooldown bypass is invocation-global; review the full Cargo.lock diff.
  rustup toolchain install {{resolver_toolchain}} > /dev/null 2>&1 &&   CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow   cargo +{{resolver_toolchain}} update -Z min-publish-age -p {{package}} --precise {{version}}

fmt:
  rustup toolchain install {{fmt_toolchain}} > /dev/null 2>&1 && \
  cargo +{{fmt_toolchain}} fmt

fmt-check:
  rustup toolchain install {{fmt_toolchain}} > /dev/null 2>&1 && \
  cargo +{{fmt_toolchain}} fmt --check

clippy:
  cargo clippy --locked --all-features --no-deps -- -D warnings

# Everything needed to run before pushing
checklist:
  cargo check --locked || (echo "Cargo.lock out of date: resolve with 'just update' (publish-age cooldown), not plain cargo update" && exit 1)
  just fmt
  just clippy
  just test
  cargo audit
  @out=$(cargo +{{resolver_toolchain}} update --dry-run -Z min-publish-age 2>&1 | grep -E "Downgrading|is too new" || true); \
  if [ -n "$out" ]; then echo "WARNING: lockfile pins crates younger than the publish-age cooldown:"; echo "$out"; fi

# ===================================
# === Build Commands for Services ===
# ===================================

[doc("""
  Builds the commit-boost binary to './build/<version>'.
""")]
build-bin version: \
  (_docker-build-binary version "commit-boost")

[doc("""
  Builds amd64 and arm64 binaries for the commit-boost crate to './build/<version>/<platform>', where '<platform>' is the
  OS / arch platform of the binary (linux_amd64 and linux_arm64).
  Used when creating the pbs Docker image.
""")]
build-bin-multiarch version: \
  (_docker-build-binary-multiarch version "commit-boost")

[doc("""
  Builds the commit-boost binary to './build/<version>' and creates a Docker image named 'commit-boost/commit-boost:<version>'.
""")]
build-all version: \
  (build-bin version) \
  (_docker-build-image version "commit-boost")

[doc("""
  Builds amd64 and arm64 flavors of the commit-boost binary and creates a unified multiarch Docker image manifest for the specified version.
  The binaries will be placed in './build/<version>/<platform>', where '<platform>' is the
  OS / arch platform of the binary (linux_amd64 and linux_arm64).
  Also pushes the image to a custom Docker registry (such as '192.168.1.10:5000').
  Used for testing multiarch images locally instead of using a public registry like GHCR or Docker Hub.
""")]
build-all-multiarch version local-docker-registry: \
  (build-bin-multiarch version) \
  (_docker-build-image-multiarch version "commit-boost" local-docker-registry)

# ===============================
# === Builder Implementations ===
# ===============================

# Creates a Docker buildx builder if it doesn't already exist
_create-docker-builder:
  docker buildx create --name multiarch-builder --driver docker-container --use > /dev/null 2>&1 || true

# Builds a binary for a specific crate and version
_docker-build-binary version crate: _create-docker-builder
  export PLATFORM=$(docker buildx inspect --bootstrap | awk -F': ' '/Platforms/ {print $2}' | cut -d',' -f1 | xargs | tr '/' '_'); \
  docker buildx build --rm --platform=local -f provisioning/build.Dockerfile --output "build/{{version}}/$PLATFORM" --target output --build-arg TARGET_CRATE=commit-boost .

# Builds a Docker image for a specific crate and version
_docker-build-image version crate: _create-docker-builder
  docker buildx build --rm --load --build-arg BINARIES_PATH=build/{{version}} -t commit-boost/{{crate}}:{{version}} -f provisioning/{{crate}}.Dockerfile .

# Builds multiple binaries (for Linux amd64 and arm64 architectures) for a specific crate and version
_docker-build-binary-multiarch version crate: _create-docker-builder
  docker buildx build --rm --platform=linux/amd64,linux/arm64 -f provisioning/build.Dockerfile --output build/{{version}} --target output --build-arg TARGET_CRATE=commit-boost .

# Builds a multi-architecture (Linux amd64 and arm64) Docker manifest for a specific crate and version.
# Uploads to the custom Docker registry (such as '192.168.1.10:5000') instead of a public registry like GHCR or Docker Hub.
_docker-build-image-multiarch version crate local-docker-registry: _create-docker-builder
  docker buildx build --rm --platform=linux/amd64,linux/arm64 --build-arg BINARIES_PATH=build/{{version}} -t {{local-docker-registry}}/commit-boost/{{crate}}:{{version}} -f provisioning/{{crate}}.Dockerfile --push .

# =================
# === Utilities ===
# =================

install-protoc:
  provisioning/protoc.sh

docker-build-test-modules:
  docker build -t test_da_commit . -f examples/da_commit/Dockerfile
  docker build -t test_status_api . -f examples/status_api/Dockerfile

# Cleans the build directory, removing all built binaries.
# Docker images are not removed by this command.
clean:
  rm -rf build

# Runs the suite of tests for all commit-boost crates.
test:
    cargo test --locked --all-features

# =====================
# === Test Coverage ===
# =====================

# Generate an HTML test coverage report and open it in the browser.
# Recompiles the workspace with LLVM coverage instrumentation, runs all tests,
# and writes the report to target/llvm-cov/html/index.html.
# Incremental recompilation works normally — no need to clean between runs.
# If results look wrong after upgrading cargo-llvm-cov, run `just coverage-clean` first.
# Requires: cargo install cargo-llvm-cov && rustup component add llvm-tools-preview
coverage:
  cargo llvm-cov --locked --all-features --html --open

# Print a quick coverage summary to the terminal without opening a browser.
coverage-summary:
  cargo llvm-cov --locked --all-features --summary-only

# Remove all coverage instrumentation artifacts produced by cargo-llvm-cov.
coverage-clean:
  cargo llvm-cov clean --workspace

# =======================
# === Microbenchmarks ===
# =======================
#
# Development Loop:
#   1. Run the current bench:  just bench dev
#   2. Update code
#   3. Re-run the bench, logging the diff from the last run:  just bench dev

# Regression Test:
#   1. Save a baseline on the main branch:  just bench main
#   2. On a PR branch, compare against it:  just bench-compare main

[doc("""
  Install tools required by the bench-* commands.
  - cargo-criterion: CLI runner for Criterion benchmarks with richer output
  - critcmp:         baseline diffing tool used by bench-compare
""")]
bench-install-tools:
  cargo install --locked cargo-criterion critcmp

[doc("""
  Run microbenchmarks and save results as a named baseline. Example: just bench main

  Compares against the last benchmark run of any kind, not the previous save of
  this baseline name. Useful for tracking incremental changes since your last run.
  For accurate baseline comparisons, use bench-compare instead.
""")]
bench baseline:
  cargo bench --locked --package cb-bench-micro -- --save-baseline {{baseline}}

[doc("""
  Run microbenchmarks, save results as "current", then diff against a named baseline.
  Example: just bench-compare main
""")]
bench-compare baseline:
  cargo bench --locked --package cb-bench-micro -- --save-baseline current
  critcmp {{baseline}} current

# =================
# === Kurtosis ===
# =================

# Tear down and clean up all enclaves
kurtosis-clean:
  kurtosis clean -a

# Clean all enclaves and restart the testnet
kurtosis-restart:
  just kurtosis-clean
  kurtosis run github.com/ethpandaops/ethereum-package \
    --enclave CB-Testnet \
    --args-file provisioning/kurtosis-config.yml

# Build local docker images and restart testnet
kurtosis-build:
  just build-all kurtosis
  just kurtosis-restart

# Inspect running enclave
kurtosis-inspect:
  kurtosis enclave inspect CB-Testnet

# Tail logs for a specific service: just kurtosis-logs <service>
kurtosis-logs service:
  kurtosis service logs CB-Testnet {{service}} --follow

# Shell into a specific service: just kurtosis-shell <service>
kurtosis-shell service:
  kurtosis service shell CB-Testnet {{service}}

# Dump enclave state to disk for post-mortem
kurtosis-dump:
  kurtosis enclave dump CB-Testnet ./kurtosis-dump
