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

# Use mojo-pkg flags if available (CI), else local include only
if [ -f "$SCRIPT_DIR/.mojo_flags" ]; then
    FLAGS=$(cat "$SCRIPT_DIR/.mojo_flags")
else
    FLAGS="-I $SCRIPT_DIR"
fi

# Select mcpu flag based on architecture
if [ "$(uname -m)" = "arm64" ] || [ "$(uname -m)" = "aarch64" ]; then
    MCPU_FLAG="--mcpu apple-m1"
else
    MCPU_FLAG="--mcpu x86-64-v2"
fi

# Build (no -Xlinker flags needed — pure Mojo, no C shim)
mojo build "$MOJO_FILE" -o "$BUILD_DIR/$BASENAME" $MCPU_FLAG -I "$SCRIPT_DIR" $FLAGS

# Run the built binary
"$BUILD_DIR/$BASENAME" "$@"
