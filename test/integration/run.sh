#!/bin/bash
set -e

cd "$(dirname "$0")"

cleanup() {
  echo "=== Cleaning up ==="
  docker compose down -v || true
}
trap cleanup EXIT

echo "=== Building and starting integration test ==="

docker compose up --build --abort-on-container-exit --exit-code-from orchestrator
