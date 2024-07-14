#!/bin/bash

set -euo pipefail

docker build -t test_da_commit . -f examples/da_commit/Dockerfile