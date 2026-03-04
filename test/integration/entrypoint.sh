#!/bin/bash
set -e

mkdir -p "${VAULTS_PATH:-/data/vaults}"

sed -i "s/REDIS_HOST_PLACEHOLDER/${REDIS_HOST:-redis}/g" /app/config.yaml
sed -i "s|VAULTS_PATH_PLACEHOLDER|${VAULTS_PATH:-/data/vaults}|g" /app/config.yaml
sed -i "s/BUCKET_PLACEHOLDER/${BUCKET_NAME:-vultiserver}/g" /app/config.yaml

./worker &
WORKER_PID=$!

cleanup() {
  kill "$WORKER_PID" 2>/dev/null || true
  wait "$WORKER_PID" 2>/dev/null || true
}
trap cleanup EXIT

./api
