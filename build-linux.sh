#!/bin/bash

# This script will build the Commit-Boost applications and modules for local Linux development.

# =================
# === Functions ===
# =================

# Print a failure message to stderr and exit
fail() {
    MESSAGE=$1
    RED='\033[0;31m'
    RESET='\033[;0m'
    >&2 echo -e "\n${RED}**ERROR**\n$MESSAGE${RESET}\n"
    exit 1
}


# Builds the CLI binaries for Linux
# NOTE: You must install qemu first; e.g. sudo apt-get install -y qemu qemu-user-static
build_cli() {
    echo "Building CLI binaries..."
    docker buildx build --rm --platform=linux/amd64,linux/arm64 -f provisioning/build.Dockerfile --output build/$VERSION --target output --build-arg TARGET_CRATE=commit-boost-cli . || fail "Error building CLI."
    echo "done!"

    # Flatten the folder structure for easier referencing
    mv build/$VERSION/linux_amd64/commit-boost-cli build/$VERSION/commit-boost-cli-linux-amd64
    mv build/$VERSION/linux_arm64/commit-boost-cli build/$VERSION/commit-boost-cli-linux-arm64

    # Clean up the empty directories
    rmdir build/$VERSION/linux_amd64 build/$VERSION/linux_arm64
    echo "done!"
}


# Builds the PBS module binaries for Linux and the Docker image(s)
# NOTE: You must install qemu first; e.g. sudo apt-get install -y qemu qemu-user-static
build_pbs() {
    echo "Building PBS binaries..."
    docker buildx build --rm --platform=linux/amd64,linux/arm64 -f provisioning/build.Dockerfile --output build/$VERSION --target output --build-arg TARGET_CRATE=commit-boost-pbs . || fail "Error building PBS binaries."
    echo "done!"

    # Flatten the folder structure for easier referencing
    mv build/$VERSION/linux_amd64/commit-boost-pbs build/$VERSION/commit-boost-pbs-linux-amd64
    mv build/$VERSION/linux_arm64/commit-boost-pbs build/$VERSION/commit-boost-pbs-linux-arm64

    # Clean up the empty directories
    rmdir build/$VERSION/linux_amd64 build/$VERSION/linux_arm64
    
    echo "Building PBS Docker image..."
    # If uploading, make and push a manifest
    if [ "$LOCAL_UPLOAD" = true ]; then
        if [ -z "$LOCAL_DOCKER_REGISTRY" ]; then
            fail "LOCAL_DOCKER_REGISTRY must be set to upload to a local registry."
        fi
        docker buildx build --rm --platform=linux/amd64,linux/arm64 --build-arg BINARIES_PATH=build/$VERSION -t $LOCAL_DOCKER_REGISTRY/commit-boost/pbs:$VERSION -f provisioning/pbs.Dockerfile --push . || fail "Error building PBS image."
    else
        docker buildx build --rm --load --build-arg BINARIES_PATH=build/$VERSION -t commit-boost/pbs:$VERSION -f provisioning/pbs.Dockerfile . || fail "Error building PBS image."
    fi
    echo "done!"
}


# Builds the Signer module binaries for Linux and the Docker image(s)
# NOTE: You must install qemu first; e.g. sudo apt-get install -y qemu qemu-user-static
build_signer() {
    echo "Building Signer binaries..."
    docker buildx build --rm --platform=linux/amd64,linux/arm64 -f provisioning/build.Dockerfile --output build/$VERSION --target output --build-arg TARGET_CRATE=commit-boost-signer . || fail "Error building Signer binaries."
    echo "done!"

    # Flatten the folder structure for easier referencing
    mv build/$VERSION/linux_amd64/commit-boost-signer build/$VERSION/commit-boost-signer-linux-amd64
    mv build/$VERSION/linux_arm64/commit-boost-signer build/$VERSION/commit-boost-signer-linux-arm64

    # Clean up the empty directories
    rmdir build/$VERSION/linux_amd64 build/$VERSION/linux_arm64
    
    echo "Building Signer Docker image..."
    # If uploading, make and push a manifest
    if [ "$LOCAL_UPLOAD" = true ]; then
        if [ -z "$LOCAL_DOCKER_REGISTRY" ]; then
            fail "LOCAL_DOCKER_REGISTRY must be set to upload to a local registry."
        fi
        docker buildx build --rm --platform=linux/amd64,linux/arm64 --build-arg BINARIES_PATH=build/$VERSION -t $LOCAL_DOCKER_REGISTRY/commit-boost/signer:$VERSION -f provisioning/signer.Dockerfile --push . || fail "Error building Signer image."
    else
        docker buildx build --rm --load --build-arg BINARIES_PATH=build/$VERSION -t commit-boost/signer:$VERSION -f provisioning/signer.Dockerfile . || fail "Error building Signer image."
    fi
    echo "done!"
}


# Print usage
usage() {
    echo "Usage: build.sh [options] -v <version number>"
    echo "This script assumes it is in the commit-boost-client repository directory."
    echo "Options:"
    echo $'\t-a\tBuild all of the artifacts (CLI, PBS, and Signer, along with Docker images)'
    echo $'\t-c\tBuild the Commit-Boost CLI binaries'
    echo $'\t-p\tBuild the PBS module binary and its Docker container'
    echo $'\t-s\tBuild the Signer module binary and its Docker container'
    echo $'\t-o\tWhen passed with a build, upload the resulting image tags to a local Docker registry specified in $LOCAL_DOCKER_REGISTRY'
    exit 0
}


# =================
# === Main Body ===
# =================

# Parse arguments
while getopts "acpsov:" FLAG; do
    case "$FLAG" in
        a) CLI=true PBS=true SIGNER=true ;;
        c) CLI=true ;;
        p) PBS=true ;;
        s) SIGNER=true ;;
        o) LOCAL_UPLOAD=true ;;
        v) VERSION="$OPTARG" ;;
        *) usage ;;
    esac
done
if [ -z "$VERSION" ]; then
    usage
fi

# Cleanup old artifacts
rm -rf build/$VERSION/*
mkdir -p build/$VERSION

# Make a multiarch builder, ignore if it's already there
docker buildx create --name multiarch-builder --driver docker-container --use > /dev/null 2>&1
# NOTE: if using a local repo with a private CA, you will have to follow these steps to add the CA to the builder:
# https://stackoverflow.com/a/73585243

# Build the artifacts
if [ "$CLI" = true ]; then
    build_cli
fi
if [ "$PBS" = true ]; then
    build_pbs
fi
if [ "$SIGNER" = true ]; then
    build_signer
fi
