#!/bin/bash
# Build all FTC binaries for Linux
# Usage: ./build-linux.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$SCRIPT_DIR/dist/linux"

echo "=== Building FTC Binaries for Linux ==="
echo "Output: $DIST_DIR"

mkdir -p "$DIST_DIR"

# Build ftc-node
echo ""
echo ">>> Building ftc-node..."
cd "$SCRIPT_DIR/ftc-node"
rm -rf build
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cp ftc-node "$DIST_DIR/"
echo "    ftc-node: OK"

# Build ftc-wallet
echo ""
echo ">>> Building ftc-wallet..."
cd "$SCRIPT_DIR/ftc-wallet"
rm -rf build
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cp ftc-wallet "$DIST_DIR/"
echo "    ftc-wallet: OK"

# Build ftc-miner
echo ""
echo ">>> Building ftc-miner..."
cd "$SCRIPT_DIR/ftc-miner-v2"
rm -rf build
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc) 2>/dev/null || echo "    (GPU miner may fail without OpenCL)"
if [ -f ftc-miner ]; then
    cp ftc-miner "$DIST_DIR/"
    echo "    ftc-miner: OK"
else
    echo "    ftc-miner: SKIPPED (no OpenCL)"
fi

echo ""
echo "=== Build Complete ==="
ls -la "$DIST_DIR/"
