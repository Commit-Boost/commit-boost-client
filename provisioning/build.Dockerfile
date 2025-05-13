# This will be the main build image
FROM --platform=${BUILDPLATFORM} lukemathwalker/cargo-chef:latest-rust-1.83 AS chef
ARG TARGETOS TARGETARCH BUILDPLATFORM OPENSSL_VENDORED TARGET_CRATE
WORKDIR /app

FROM --platform=${BUILDPLATFORM} chef AS planner
ARG TARGETOS TARGETARCH BUILDPLATFORM OPENSSL_VENDORED TARGET_CRATE
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM --platform=${BUILDPLATFORM} chef AS builder
ARG TARGETOS TARGETARCH BUILDPLATFORM OPENSSL_VENDORED TARGET_CRATE
RUN test -n "$TARGET_CRATE" || (echo "TARGET_CRATE must be set to the service / binary you want to build" && false)
ENV BUILD_VAR_SCRIPT=/tmp/env.sh
COPY --from=planner /app/recipe.json recipe.json

# Set up the build environment for cross-compilation if needed
RUN if [ "$BUILDPLATFORM" = "linux/amd64" -a "$TARGETARCH" = "arm64" ]; then \
      # We're on x64, cross-compiling for arm64
      rustup target add aarch64-unknown-linux-gnu && \
      apt update && \
      apt install -y gcc-aarch64-linux-gnu && \
      echo "#!/bin/sh" > ${BUILD_VAR_SCRIPT} && \
      echo "export TARGET=aarch64-unknown-linux-gnu" >> ${BUILD_VAR_SCRIPT} && \
      echo "export TARGET_FLAG=--target=aarch64-unknown-linux-gnu" >> ${BUILD_VAR_SCRIPT} && \
      echo "export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/aarch64-linux-gnu-gcc" >> ${BUILD_VAR_SCRIPT} && \
      echo "export RUSTFLAGS=\"-L /usr/aarch64-linux-gnu/lib -L $(dirname $(aarch64-linux-gnu-gcc -print-libgcc-file-name))\"" >> ${BUILD_VAR_SCRIPT} && \
      if [ "$OPENSSL_VENDORED" != "true" ]; then \
        # If we're linking to OpenSSL dynamically, we have to set it up for cross-compilation
        dpkg --add-architecture arm64 && \
        apt update && \
        apt install -y libssl-dev:arm64 zlib1g-dev:arm64 && \
        echo "export PKG_CONFIG_ALLOW_CROSS=true" >> ${BUILD_VAR_SCRIPT} && \
        echo "export PKG_CONFIG_LIBDIR=/usr/lib/aarch64-linux-gnu/pkgconfig" >> ${BUILD_VAR_SCRIPT} && \
        echo "export OPENSSL_INCLUDE_DIR=/usr/include/aarch64-linux-gnu" >> ${BUILD_VAR_SCRIPT} && \
        echo "export OPENSSL_LIB_DIR=/usr/lib/aarch64-linux-gnu" >> ${BUILD_VAR_SCRIPT}; \
      fi; \
    elif [ "$BUILDPLATFORM" = "linux/arm64" -a "$TARGETARCH" = "amd64" ]; then \
      # We're on arm64, cross-compiling for x64
      rustup target add x86_64-unknown-linux-gnu && \
      apt update && \
      apt install -y gcc-x86-64-linux-gnu && \
      echo "#!/bin/sh" > ${BUILD_VAR_SCRIPT} && \
      echo "export TARGET=x86_64-unknown-linux-gnu" >> ${BUILD_VAR_SCRIPT} && \
      echo "export TARGET_FLAG=--target=x86_64-unknown-linux-gnu" >> ${BUILD_VAR_SCRIPT} && \
      echo "export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/x86_64-linux-gnu-gcc" >> ${BUILD_VAR_SCRIPT} && \
      echo "export RUSTFLAGS=\"-L /usr/x86_64-linux-gnu/lib -L $(dirname $(x86_64-linux-gnu-gcc -print-libgcc-file-name))\"" >> ${BUILD_VAR_SCRIPT} && \
      if [ "$OPENSSL_VENDORED" != "true" ]; then \
        # If we're linking to OpenSSL dynamically, we have to set it up for cross-compilation
        dpkg --add-architecture amd64 && \
        apt update && \
        apt install -y libssl-dev:amd64 zlib1g-dev:amd64 && \
        echo "export PKG_CONFIG_ALLOW_CROSS=true" >> ${BUILD_VAR_SCRIPT} && \
        echo "export PKG_CONFIG_LIBDIR=/usr/lib/x86_64-linux-gnu/pkgconfig" >> ${BUILD_VAR_SCRIPT} && \
        echo "export OPENSSL_INCLUDE_DIR=/usr/include/x86_64-linux-gnu" >> ${BUILD_VAR_SCRIPT} && \
        echo "export OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu" >> ${BUILD_VAR_SCRIPT}; \
      fi; \
    fi

# Run cook to prep the build 
RUN if [ -f ${BUILD_VAR_SCRIPT} ]; then \
      . ${BUILD_VAR_SCRIPT} && \
      echo "Cross-compilation environment set up for ${TARGET}"; \
    else \
      echo "No cross-compilation needed"; \
    fi && \
    if [ "$OPENSSL_VENDORED" = "true" ]; then \
      echo "Using vendored OpenSSL" && \
      FEATURE_OPENSSL_VENDORED='--features openssl-vendored'; \
    else \
      echo "Using system OpenSSL"; \
    fi && \
    export GIT_HASH=$(git rev-parse HEAD) && \
    cargo chef cook ${TARGET_FLAG} --release --recipe-path recipe.json ${FEATURE_OPENSSL_VENDORED}

# Get the latest Protoc since the one in the Debian repo is incredibly old
COPY provisioning/protoc.sh provisioning/protoc.sh
RUN provisioning/protoc.sh

# Now we can copy the source files - chef cook wants to run before this step
COPY . .

# Build the application
RUN if [ -f ${BUILD_VAR_SCRIPT} ]; then \
      chmod +x ${BUILD_VAR_SCRIPT} && \
      . ${BUILD_VAR_SCRIPT} && \
      echo "Cross-compilation environment set up for ${TARGET}"; \
    else \
      echo "No cross-compilation needed"; \
    fi && \
    if [ "$OPENSSL_VENDORED" = "true" ]; then \
      echo "Using vendored OpenSSL" && \
      FEATURE_OPENSSL_VENDORED='--features openssl-vendored'; \
    else \
      echo "Using system OpenSSL"; \
    fi && \
    export GIT_HASH=$(git rev-parse HEAD) && \
    cargo build ${TARGET_FLAG} --release --bin ${TARGET_CRATE} ${FEATURE_OPENSSL_VENDORED} && \
    if [ ! -z "$TARGET" ]; then \
      # If we're cross-compiling, we need to move the binary out of the target dir
      mv target/${TARGET}/release/${TARGET_CRATE} target/release/${TARGET_CRATE}; \
    fi

# Copy the output
FROM scratch AS output
ARG TARGET_CRATE
COPY --from=builder /app/target/release/${TARGET_CRATE} /${TARGET_CRATE}
