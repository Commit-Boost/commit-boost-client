# Start from the latest Rust image for the build stage
FROM rust:latest AS builder

# Set the working directory
WORKDIR /app

# Copy the Cargo.toml and Cargo.lock files
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock

# Copy the source code
COPY ./bin ./bin
COPY ./crates ./crates
COPY ./tests ./tests
COPY ./examples ./examples

# Build the application
RUN cargo build --bin signer-module

# Use Ubuntu 22.04 for runtime to ensure OpenSSL 3.x is available
FROM ubuntu:22.04

# Install OpenSSL and necessary libraries
RUN apt-get update && apt-get install -y \
    openssl \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy the built binary from the builder stage
COPY --from=builder /app/target/debug/signer-module /usr/local/bin/signer-module

# Start the server
ENTRYPOINT ["/usr/local/bin/signer-module"]
