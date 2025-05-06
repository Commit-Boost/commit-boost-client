# This will be the main build image
FROM --platform=${BUILDPLATFORM} lukemathwalker/cargo-chef:latest-rust-1.83 AS chef
ARG TARGETOS TARGETARCH BUILDPLATFORM
WORKDIR /app

# Planner stage
FROM --platform=${BUILDPLATFORM} chef AS planner
ARG TARGETOS TARGETARCH BUILDPLATFORM
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Builder stage
FROM --platform=${BUILDPLATFORM} chef AS builder 
ARG TARGETOS TARGETARCH BUILDPLATFORM
COPY --from=planner /app/recipe.json recipe.json
COPY . .

# Get the latest Protoc since the one in the Debian repo is incredibly old
RUN apt update && apt install -y unzip curl ca-certificates && \
  PROTOC_VERSION=$(curl -s "https://api.github.com/repos/protocolbuffers/protobuf/releases/latest" | grep -Po '"tag_name": "v\K[0-9.]+') && \
  if [ "$BUILDPLATFORM" = "linux/amd64" ]; then \
    PROTOC_ARCH=x86_64; \
  elif [ "$BUILDPLATFORM" = "linux/arm64" ]; then \
    PROTOC_ARCH=aarch_64; \
  else \
    echo "${BUILDPLATFORM} is not supported."; \
    exit 1; \
  fi && \
  curl -Lo protoc.zip https://github.com/protocolbuffers/protobuf/releases/latest/download/protoc-$PROTOC_VERSION-linux-$PROTOC_ARCH.zip && \
  unzip -q protoc.zip bin/protoc -d /usr && \
  unzip -q protoc.zip "include/google/*" -d /usr && \
  chmod a+x /usr/bin/protoc && \
  rm -rf protoc.zip

# Build the application
RUN if [ "$BUILDPLATFORM" = "linux/amd64" -a "$TARGETARCH" = "arm64" ]; then \
      # We're on x64, cross-compiling for arm64 - get OpenSSL and zlib for arm64, and set up the GCC vars
      rustup target add aarch64-unknown-linux-gnu && \
      #dpkg --add-architecture arm64 && \
      apt update && \
      apt install -y gcc-aarch64-linux-gnu libssl-dev:arm64 zlib1g-dev:arm64 && \
      TARGET="aarch64-unknown-linux-gnu" && \
      TARGET_FLAG="--target=${TARGET}" && \
      # export PKG_CONFIG_ALLOW_CROSS="true" && \
      # export PKG_CONFIG_LIBDIR="/usr/lib/aarch64-linux-gnu/pkgconfig" && \
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="/usr/bin/aarch64-linux-gnu-gcc" && \
      export RUSTFLAGS="-L /usr/aarch64-linux-gnu/lib -L $(dirname $(aarch64-linux-gnu-gcc -print-libgcc-file-name))" && \
      FEATURE_OPENSSL_VENDORED="--features openssl-vendored"; \
    elif [ "$BUILDPLATFORM" = "linux/arm64" -a "$TARGETARCH" = "amd64" ]; then \
      # We're on arm64, cross-compiling for x64 - get OpenSSL and zlib for x64, and set up the GCC vars
      dpkg --add-architecture amd64 && \
      apt update && \
      apt install -y gcc-x86-64-linux-gnu libssl-dev:amd64 zlib1g-dev:amd64 && \
      rustup target add x86_64-unknown-linux-gnu && \
      TARGET="x86_64-unknown-linux-gnu" && \
      TARGET_FLAG="--target=${TARGET}" && \
      export PKG_CONFIG_ALLOW_CROSS="true" && \
      export PKG_CONFIG_PATH="/usr/lib/x86_64-linux-gnu/pkgconfig"; \
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="/usr/bin/x86_64-linux-gnu-gcc"; \
      export RUSTFLAGS="-L $(dirname $(x86_64-linux-gnu-gcc -print-libgcc-file-name))"; \
    fi && \
    # Build the signer - general setup that works with or without cross-compilation
    # cargo chef cook ${TARGET_FLAG} --release --recipe-path recipe.json && \
    export GIT_HASH=$(git rev-parse HEAD) && \
    cargo build ${TARGET_FLAG} --release --bin commit-boost-signer ${FEATURE_OPENSSL_VENDORED} && \
    if [ ! -z "$TARGET" ]; then \
      # If we're cross-compiling, we need to move the binary out of the target dir
      mv target/${TARGET}/release/commit-boost-signer target/release/commit-boost-signer; \
    fi

FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y \
  openssl \
  ca-certificates \
  libssl3 \
  libssl-dev \
  curl \
  && apt-get clean autoclean \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/commit-boost-signer /usr/local/bin

RUN groupadd -g 10001 commitboost && \
  useradd -u 10001 -g commitboost -s /sbin/nologin commitboost
USER commitboost

ENTRYPOINT ["/usr/local/bin/commit-boost-signer"]



