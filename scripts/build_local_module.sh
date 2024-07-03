#!/bin/bash

set -euo pipefail

sudo docker build -t test_da_commit . -f examples/da_commit/Dockerfile