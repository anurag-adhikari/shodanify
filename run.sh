#!/bin/bash
# Run Shodanify (Rust backend)
# Usage: ./run.sh [--release]
set -e

cd "$(dirname "$0")"

if [[ ! -f "target/release/shodanify" ]]; then
    echo "Building release binary..."
    cargo build --release
fi

echo "Starting Rust backend..."
exec ./target/release/shodanify
