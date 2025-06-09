# Makes sure the nightly-2025-02-26 toolchain is installed
toolchain := "nightly-2025-02-26"

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
  Builds the commit-boost-cli binary to './build/<version>'.
""")]
build-cli version: \
  (_docker-build-binary version "cli")

[doc("""
  Builds amd64 and arm64 binaries for the commit-boost-cli crate to './build/<version>/<platform>', where '<platform>' is
  the OS / arch platform of the binary (linux_amd64 and linux_arm64).
""")]
build-cli-multiarch version: \
  (_docker-build-binary-multiarch version "cli")

[doc("""
  Builds the commit-boost-pbs binary to './build/<version>'.
""")]
build-pbs-bin version: \
  (_docker-build-binary version "pbs")

[doc("""
  Creates a Docker image named 'commit-boost/pbs:<version>' and loads it to the local Docker repository.
  Requires the binary to be built first, but this command won't build it automatically if you just need to build the
  Docker image without recompiling the binary.
""")]
build-pbs-img version: \
  (_docker-build-image version "pbs")

[doc("""
  Builds the commit-boost-pbs binary to './build/<version>' and creates a Docker image named 'commit-boost/pbs:<version>'.
""")]
build-pbs version: \
  (build-pbs-bin version) \
  (build-pbs-img version)

[doc("""
  Builds amd64 and arm64 binaries for the commit-boost-pbs crate to './build/<version>/<platform>', where '<platform>' is the
  OS / arch platform of the binary (linux_amd64 and linux_arm64).
  Used when creating the pbs Docker image.
""")]
build-pbs-bin-multiarch version: \
  (_docker-build-binary-multiarch version "pbs")

[doc("""
  Creates a multiarch Docker image manifest named 'commit-boost/pbs:<version>' and pushes it to a custom Docker registry
  (such as '192.168.1.10:5000').
  Used for testing multiarch images locally instead of using a public registry like GHCR or Docker Hub.
""")]
build-pbs-img-multiarch version local-docker-registry: \
  (_docker-build-image-multiarch version "pbs" local-docker-registry)

[doc("""
  Builds amd64 and arm64 binaries for the commit-boost-pbs crate to './build/<version>/<platform>', where '<platform>' is the
  OS / arch platform of the binary (linux_amd64 and linux_arm64).
  Creates a multiarch Docker image manifest named 'commit-boost/pbs:<version>' and pushes it to a custom Docker registry
  (such as '192.168.1.10:5000').
  Used for testing multiarch images locally instead of using a public registry like GHCR or Docker Hub.
""")]
build-pbs-multiarch version local-docker-registry: \
  (build-pbs-bin-multiarch version) \
  (build-pbs-img-multiarch version local-docker-registry)

[doc("""
  Builds the commit-boost-signer binary to './build/<version>'.
""")]
build-signer-bin version: \
  (_docker-build-binary version "signer")

[doc("""
  Creates a Docker image named 'commit-boost/signer:<version>' and loads it to the local Docker repository.
  Requires the binary to be built first, but this command won't build it automatically if you just need to build the
  Docker image without recompiling the binary.
""")]
build-signer-img version: \
  (_docker-build-image version "signer")

[doc("""
  Builds the commit-boost-signer binary to './build/<version>' and creates a Docker image named 'commit-boost/signer:<version>'.
""")]
build-signer version: \
  (build-signer-bin version) \
  (build-signer-img version)

[doc("""
  Builds amd64 and arm64 binaries for the commit-boost-signer crate to './build/<version>/<platform>', where '<platform>' is 
  the OS / arch platform of the binary (linux_amd64 and linux_arm64).
  Used when creating the signer Docker image.
""")]
build-signer-bin-multiarch version: \
  (_docker-build-binary-multiarch version "signer")

[doc("""
  Creates a multiarch Docker image manifest named 'commit-boost/signer:<version>' and pushes it to a custom Docker registry
  (such as '192.168.1.10:5000').
  Used for testing multiarch images locally instead of using a public registry like GHCR or Docker Hub.
""")]
build-signer-img-multiarch version local-docker-registry: \
  (_docker-build-image-multiarch version "signer" local-docker-registry)

[doc("""
  Builds amd64 and arm64 binaries for the commit-boost-signer crate to './build/<version>/<platform>', where '<platform>' is
  the OS / arch platform of the binary (linux_amd64 and linux_arm64).
  Creates a multiarch Docker image manifest named 'commit-boost/signer:<version>' and pushes it to a custom Docker registry
  (such as '192.168.1.10:5000').
  Used for testing multiarch images locally instead of using a public registry like GHCR or Docker Hub.
""")]
build-signer-multiarch version local-docker-registry: \
  (build-signer-bin-multiarch version) \
  (build-signer-img-multiarch version local-docker-registry)

[doc("""
  Builds the CLI, PBS, and Signer binaries and Docker images for the specified version.
  The binaries will be placed in './build/<version>'.
  The Docker images will be named 'commit-boost/cli:<version>', 'commit-boost/pbs:<version>', and
  'commit-boost/signer:<version>'.
""")]
build-all version: \
  (build-cli version) \
  (build-pbs version) \
  (build-signer version)

[doc("""
  Builds amd64 and arm64 flavors of the CLI, PBS, and Signer binaries and Docker images for the specified version.
  The binaries will be placed in './build/<version>/<platform>', where '<platform>' is the
  OS / arch platform of the binary (linux_amd64 and linux_arm64).
  Also creates multiarch Docker image manifests for each crate and pushes them to a custom Docker registry
  (such as '192.168.1.10:5000').
  Used for testing multiarch images locally instead of using a public registry like GHCR or Docker Hub.
""")]
build-all-multiarch version local-docker-registry: \
  (build-cli-multiarch version) \
  (build-pbs-multiarch version local-docker-registry) \
  (build-signer-multiarch version local-docker-registry)

# ===============================
# === Builder Implementations ===
# ===============================

# Creates a Docker buildx builder if it doesn't already exist
_create-docker-builder:
  docker buildx create --name multiarch-builder --driver docker-container --use > /dev/null 2>&1 || true

# Builds a binary for a specific crate and version
_docker-build-binary version crate: _create-docker-builder
  export PLATFORM=$(docker buildx inspect --bootstrap | awk -F': ' '/Platforms/ {print $2}' | cut -d',' -f1 | xargs | tr '/' '_'); \
  docker buildx build --rm --platform=local -f provisioning/build.Dockerfile --output "build/{{version}}/$PLATFORM" --target output --build-arg TARGET_CRATE=commit-boost-{{crate}} .

# Builds a Docker image for a specific crate and version
_docker-build-image version crate: _create-docker-builder
  docker buildx build --rm --load --build-arg BINARIES_PATH=build/{{version}} -t commit-boost/{{crate}}:{{version}} -f provisioning/{{crate}}.Dockerfile .

# Builds multiple binaries (for Linux amd64 and arm64 architectures) for a specific crate and version
_docker-build-binary-multiarch version crate: _create-docker-builder
  docker buildx build --rm --platform=linux/amd64,linux/arm64 -f provisioning/build.Dockerfile --output build/{{version}} --target output --build-arg TARGET_CRATE=commit-boost-{{crate}} .

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
  docker build -t test_builder_log . -f examples/builder_log/Dockerfile
  docker build -t test_status_api . -f examples/status_api/Dockerfile

# Cleans the build directory, removing all built binaries.
# Docker images are not removed by this command.
clean:
  rm -rf build

# Runs the suite of tests for all commit-boost crates.
test:
    cargo test --all-features
