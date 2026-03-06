toolchain := "nightly-2025-06-26"

fmt:
  rustup toolchain install {{toolchain}} > /dev/null 2>&1 && \
  cargo +{{toolchain}} fmt

fmt-check:
  rustup toolchain install {{toolchain}} > /dev/null 2>&1 && \
  cargo +{{toolchain}} fmt --check

clippy:
  cargo +{{toolchain}} clippy --all-features --no-deps -- -D warnings

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
  Creates a Docker image named 'commit-boost/pbs:<version>' and loads it to the local Docker repository.
  Requires the binary to be built first, but this command won't build it automatically if you just need to build the
  Docker image without recompiling the binary.
""")]
build-pbs-img version: \
  (_docker-build-image version "pbs")

[doc("""
  Builds the commit-boost binary to './build/<version>' and creates a Docker image named 'commit-boost/pbs:<version>'.
""")]
build-pbs version: \
  (build-bin version) \
  (build-pbs-img version)

[doc("""
  Creates a multiarch Docker image manifest named 'commit-boost/pbs:<version>' and pushes it to a custom Docker registry
  (such as '192.168.1.10:5000').
  Used for testing multiarch images locally instead of using a public registry like GHCR or Docker Hub.
""")]
build-pbs-img-multiarch version local-docker-registry: \
  (_docker-build-image-multiarch version "pbs" local-docker-registry)

[doc("""
  Builds amd64 and arm64 binaries for the commit-boost crate to './build/<version>/<platform>', where '<platform>' is the
  OS / arch platform of the binary (linux_amd64 and linux_arm64).
  Creates a multiarch Docker image manifest named 'commit-boost/pbs:<version>' and pushes it to a custom Docker registry
  (such as '192.168.1.10:5000').
  Used for testing multiarch images locally instead of using a public registry like GHCR or Docker Hub.
""")]
build-pbs-multiarch version local-docker-registry: \
  (build-bin-multiarch version) \
  (build-pbs-img-multiarch version local-docker-registry)

[doc("""
  Creates a Docker image named 'commit-boost/signer:<version>' and loads it to the local Docker repository.
  Requires the binary to be built first, but this command won't build it automatically if you just need to build the
  Docker image without recompiling the binary.
""")]
build-signer-img version: \
  (_docker-build-image version "signer")

[doc("""
  Builds the commit-boost binary to './build/<version>' and creates a Docker image named 'commit-boost/signer:<version>'.
""")]
build-signer version: \
  (build-bin version) \
  (build-signer-img version)

[doc("""
  Creates a multiarch Docker image manifest named 'commit-boost/signer:<version>' and pushes it to a custom Docker registry
  (such as '192.168.1.10:5000').
  Used for testing multiarch images locally instead of using a public registry like GHCR or Docker Hub.
""")]
build-signer-img-multiarch version local-docker-registry: \
  (_docker-build-image-multiarch version "signer" local-docker-registry)

[doc("""
  Builds amd64 and arm64 binaries for the commit-boost crate to './build/<version>/<platform>', where '<platform>' is
  the OS / arch platform of the binary (linux_amd64 and linux_arm64).
  Creates a multiarch Docker image manifest named 'commit-boost/signer:<version>' and pushes it to a custom Docker registry
  (such as '192.168.1.10:5000').
  Used for testing multiarch images locally instead of using a public registry like GHCR or Docker Hub.
""")]
build-signer-multiarch version local-docker-registry: \
  (build-bin-multiarch version) \
  (build-signer-img-multiarch version local-docker-registry)

[doc("""
  Builds the CLI, PBS, and Signer binaries and Docker images for the specified version.
  The binaries will be placed in './build/<version>'.
  The Docker images will be named 'commit-boost/cli:<version>', 'commit-boost/pbs:<version>', and
  'commit-boost/signer:<version>'.
""")]
build-all version: \
  (build-bin version) \
  (build-pbs-img version) \
  (build-signer-img version)

[doc("""
  Builds amd64 and arm64 flavors of the CLI, PBS, and Signer binaries and Docker images for the specified version.
  The binaries will be placed in './build/<version>/<platform>', where '<platform>' is the
  OS / arch platform of the binary (linux_amd64 and linux_arm64).
  Also creates multiarch Docker image manifests for each crate and pushes them to a custom Docker registry
  (such as '192.168.1.10:5000').
  Used for testing multiarch images locally instead of using a public registry like GHCR or Docker Hub.
""")]
build-all-multiarch version local-docker-registry: \
  (build-bin-multiarch version) \
  (build-pbs-img-multiarch version local-docker-registry) \
  (build-signer-img-multiarch version local-docker-registry)

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
    cargo test --all-features

# =================
# === Kurtosis ===
# =================

# Tear down and clean up all enclaves
clean-kurtosis:
  kurtosis clean -a

# Clean all enclaves and restart the testnet
restart-kurtosis:
  just clean-kurtosis
  kurtosis run github.com/ethpandaops/ethereum-package \
    --enclave CB-Testnet \
    --args-file provisioning/kurtosis-config.yml

# Build local docker images and restart testnet
build-kurtosis:
  just build-all kurtosis
  just restart-kurtosis

# Inspect running enclave
inspect-kurtosis:
  kurtosis enclave inspect CB-Testnet

# Tail logs for a specific service: just logs-kurtosis <service>
logs-kurtosis service:
  kurtosis service logs CB-Testnet {{service}} --follow

# Shell into a specific service: just shell-kurtosis <service>
shell-kurtosis service:
  kurtosis service shell CB-Testnet {{service}}

# Dump enclave state to disk for post-mortem
dump-kurtosis:
  kurtosis enclave dump CB-Testnet ./kurtosis-dump