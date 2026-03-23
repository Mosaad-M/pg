#!/bin/bash
# Build a Mojo file and run the resulting binary.
# Usage: ./build_and_run.sh <file.mojo> [args...]
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOJO_FILE="$1"
shift

BASENAME="$(basename "$MOJO_FILE" .mojo)"
BUILD_DIR="$SCRIPT_DIR/.build"
mkdir -p "$BUILD_DIR"

# Select mcpu flag based on architecture
if [ "$(uname -m)" = "arm64" ] || [ "$(uname -m)" = "aarch64" ]; then
    MCPU_FLAG="--mcpu apple-m1"
else
    MCPU_FLAG="--mcpu x86-64-v2"
fi

# Build (no -Xlinker flags needed — pure Mojo, no C shim)
mojo build "$MOJO_FILE" -o "$BUILD_DIR/$BASENAME" $MCPU_FLAG -I "$SCRIPT_DIR"

# Run the built binary
"$BUILD_DIR/$BASENAME" "$@"
