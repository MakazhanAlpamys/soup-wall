#!/usr/bin/env bash
set -euo pipefail

# Ensure local isolated TMPDIR to prevent macOS symlink guard failures (/var -> /private/var)
TMP_DIR="$(pwd)/target/local-review/tmp"
mkdir -p "$TMP_DIR"
export TMPDIR="$TMP_DIR"

echo "=== Running soup-wall workspace tests with TMPDIR=$TMPDIR ==="
cargo test --locked --workspace "$@"
