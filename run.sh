#!/bin/bash
# Build (release) and run Shodanify.
#   ./run.sh            build if needed, then run
#   ./run.sh --rebuild  force a fresh release build first
#   PORT=9000 ./run.sh  override config via env vars (see README)
set -e

cd "$(dirname "$0")"

BIN="target/release/shodanify"

if [[ "$1" == "--rebuild" || ! -x "$BIN" ]]; then
    echo "==> Building release binary..."
    cargo build --release
fi

echo "==> Starting Shodanify  (http://${HOST:-127.0.0.1}:${PORT:-8080})"
exec "$BIN"
