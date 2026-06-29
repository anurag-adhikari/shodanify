#!/bin/bash
# Run Shodanify (Rust backend)
# Usage: ./run.sh [--release] [--python]
set -e

cd "$(dirname "$0")"

if [[ "$1" == "--python" ]]; then
    echo "Starting Python backend..."
    exec python3 app.py
fi

if [[ ! -f "target/release/shodanify" ]]; then
    echo "Building release binary..."
    cargo build --release
fi

echo "Starting Rust backend..."
exec ./target/release/shodanify
