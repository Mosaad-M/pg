#!/bin/bash
# Build a Mojo file with PostgreSQL wrapper support and run the resulting binary.
# Usage: ./build_and_run.sh <file.mojo> [args...]
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOJO_FILE="$1"
shift

BASENAME="$(basename "$MOJO_FILE" .mojo)"
BUILD_DIR="$SCRIPT_DIR/.build"
mkdir -p "$BUILD_DIR"

# Build with explicit -Xlinker flags (PATH-based c++ wrapper no longer works in 0.26+)
mojo build "$MOJO_FILE" -o "$BUILD_DIR/$BASENAME" \
    -Xlinker -L"$SCRIPT_DIR" \
    -Xlinker -lpg_wrapper \
    -Xlinker -rpath \
    -Xlinker "$SCRIPT_DIR"

# Run the built binary
"$BUILD_DIR/$BASENAME" "$@"
