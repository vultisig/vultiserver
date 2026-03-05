#!/bin/bash
set -e

cd "$(dirname "$0")"

cleanup() {
  echo "=== Cleaning up ==="
  docker compose down -v || true
}
trap cleanup EXIT

echo "=== Building and starting integration test ==="

docker compose build
docker compose up -d
docker compose logs -f orchestrator
