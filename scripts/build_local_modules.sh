#!/bin/bash

set -euo pipefail

docker build -t test_da_commit . -f examples/da_commit/Dockerfile
docker build -t test_builder_log . -f examples/builder_log/Dockerfile
docker build -t test_status_api . -f examples/status_api/Dockerfile