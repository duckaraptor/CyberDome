#!/usr/bin/env bash

set -u

# The engines run from the repo root, one level above this script
cd "$(dirname "$0")/.."

PYTHON_BIN="${PYTHON_BIN:-python3}"
PIDS=()

port_is_open() {
    "$PYTHON_BIN" - "$1" <<'PY'
import socket
import sys

with socket.socket() as sock:
    sys.exit(sock.connect_ex(("127.0.0.1", int(sys.argv[1]))) != 0)
PY
}

cleanup() {
    trap - EXIT INT TERM

    if ((${#PIDS[@]})); then
        echo
        echo "Stopping Zero Trust engines..."
        kill -TERM "${PIDS[@]}" 2>/dev/null || true
        wait "${PIDS[@]}" 2>/dev/null || true
    fi
}

for port in 8001 8002 8003; do
    if port_is_open "$port"; then
        echo "Port $port is already in use. Stop the existing engine processes first." >&2
        exit 1
    fi
done

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Starting Trust Engine..."
"$PYTHON_BIN" -u TrustEngine.py &
PIDS+=("$!")
sleep 1

echo "Starting Policy Engine..."
"$PYTHON_BIN" -u PolicyEngine.py &
PIDS+=("$!")
sleep 1

echo "Starting Access Proxy..."
"$PYTHON_BIN" -u AccessProxy.py &
PIDS+=("$!")

echo "All engines started. Press Ctrl+C to stop them."

while true; do
    for pid in "${PIDS[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "An engine process stopped unexpectedly." >&2
            exit 1
        fi
    done
    sleep 1
done