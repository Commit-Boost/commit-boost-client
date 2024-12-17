#!/bin/bash

set -euo pipefail

# Commit-Boost needs the default pbs and signer module images to be available. For local development, build these based on the ./docker folder
# The image names match the ones in common::config

docker build -t commitboost_pbs_default . -f ./provisioning/pbs.Dockerfile
docker build -t commitboost_signer . -f ./provisioning/signer.Dockerfile
