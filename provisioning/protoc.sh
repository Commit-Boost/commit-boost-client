#!/bin/sh

# This script installs the latest version of protoc (Protocol Buffers Compiler) from the official GitHub repository.

# Print a failure message to stderr and exit
fail() {
    MESSAGE=$1
    RED='\033[0;31m'
    RESET='\033[;0m'
    >&2 echo -e "\n${RED}**ERROR**\n$MESSAGE${RESET}\n"
    exit 1
}

# Get the OS
case "$(uname)" in
    Darwin*)
        PROTOC_OS="osx" ;
        TARGET_DIR="/opt/homebrew" ; # Emulating a homebrew install so we don't need elevated permissions
        # Darwin comes with unzip and curl already
        brew install jq ;;
    Linux*)
        PROTOC_OS="linux" ;
        TARGET_DIR="/usr" ; # Assumes the script is run as root or the user can do it manually
        if [ $(id -u) != "0" ]; then
            CMD_PREFIX="sudo " ;
        fi
        ${CMD_PREFIX}apt update && ${CMD_PREFIX}apt install -y unzip curl ca-certificates jq ;;
    *)
        echo "Unsupported OS: $(uname)" ;
        exit 1 ;;
esac

# Get the architecture
case "$(uname -m)" in
    x86_64)  PROTOC_ARCH="x86_64" ;;
    aarch64) PROTOC_ARCH="aarch_64" ;;
    arm64)   PROTOC_ARCH="aarch_64" ;;
    *)       echo "Unsupported architecture: [$(uname -m)]"; exit 1 ;;
esac

# Get the latest version
PROTOC_RAW_VERSION=$(curl --retry 10 --retry-delay 2 --retry-all-errors -fsL "https://api.github.com/repos/protocolbuffers/protobuf/releases/latest" | jq -r .tag_name) || fail "Failed to get the latest version of protoc"
if [ "$PROTOC_RAW_VERSION" = "null" ]; then
    fail "Failed to get the latest version of protoc"
fi
echo "Latest version of protoc: [$PROTOC_RAW_VERSION]"
PROTOC_VERSION=$(echo $PROTOC_RAW_VERSION | sed 's/^v//') || fail "Failed to parse the latest version of protoc"
if [ -z "$PROTOC_VERSION" ]; then
    fail "Latest version of protoc was empty"
fi

echo "Installing protoc: $PROTOC_VERSION-$PROTOC_OS-$PROTOC_ARCH"

# Download and install protoc
curl --retry 10 --retry-delay 2 --retry-all-errors -fsLo protoc.zip https://github.com/protocolbuffers/protobuf/releases/latest/download/protoc-$PROTOC_VERSION-$PROTOC_OS-$PROTOC_ARCH.zip || fail "Failed to download protoc"
${CMD_PREFIX}unzip -qo protoc.zip bin/protoc -d $TARGET_DIR || fail "Failed to unzip protoc"
${CMD_PREFIX}unzip -qo protoc.zip "include/google/*" -d $TARGET_DIR || fail "Failed to unzip protoc includes"
${CMD_PREFIX}chmod a+x $TARGET_DIR/bin/protoc || fail "Failed to set executable permissions for protoc"
rm -rf protoc.zip || fail "Failed to remove protoc zip file"
echo "protoc ${PROTOC_VERSION} installed successfully for ${PROTOC_OS} ${PROTOC_ARCH}"