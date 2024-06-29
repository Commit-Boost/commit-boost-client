# Start from the latest Rust image for the build stage
FROM rust:latest AS builder

# Set the working directory
WORKDIR /usr/src/app

# Copy the Cargo.toml and Cargo.lock files
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock

# Copy the source code
COPY ./bin ./bin
COPY ./crates ./crates
COPY ./tests ./tests
COPY ./examples ./examples

# Build the application
RUN cargo build --bin commit-boost

# Use Ubuntu 22.04 for runtime to ensure OpenSSL 3.x is available
FROM ubuntu:22.04

# Install OpenSSL and necessary libraries
RUN apt-get update && apt-get install -y \
    openssl \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy the built binary from the builder stage
COPY --from=builder /usr/src/app/target/debug/commit-boost /usr/local/bin/commit-boost

# Copy the configuration file
COPY ./config.dockerized.toml /etc/commit-boost/config.toml
COPY ./keys.example.json ./keys.example.json
COPY ./metrics_jwt.txt ./metrics_jwt.txt

# Expose the necessary ports for metrics
EXPOSE 13030
EXPOSE 18551
EXPOSE 33951

# Set the entrypoint with the 'start' subcommand and the correct config path
ENTRYPOINT ["commit-boost", "start", "/etc/commit-boost/config.toml"]
