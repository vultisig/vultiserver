#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "=== Building and starting integration test ==="

export DOCKER_DEFAULT_PLATFORM=linux/amd64
docker compose build
docker compose up --abort-on-container-exit --exit-code-from orchestrator

echo "=== Cleaning up ==="
docker compose down -v
