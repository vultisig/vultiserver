#!/bin/bash
set -e

mkdir -p "${VAULTS_PATH:-/data/vaults}"

./worker &
WORKER_PID=$!

./api

kill $WORKER_PID 2>/dev/null || true
