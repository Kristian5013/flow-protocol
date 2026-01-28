#!/bin/bash
#
# FTC Node Package Script for Linux
#
# Creates a distributable tar.gz package containing:
#   - ftc-node binary
#   - install.sh script
#   - Icon file
#   - README
#
# Usage: ./package.sh
#

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
VERSION="1.0.0"
ARCH=$(uname -m)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PACKAGE_NAME="ftc-node-${VERSION}-linux-${ARCH}"
PACKAGE_DIR="$SCRIPT_DIR/$PACKAGE_NAME"
OUTPUT_FILE="$PROJECT_DIR/../release/${PACKAGE_NAME}.tar.gz"

echo -e "${GREEN}Creating FTC Node package: ${PACKAGE_NAME}${NC}"
echo ""

# Check if binary exists
if [ ! -f "$SCRIPT_DIR/ftc-node" ]; then
    echo -e "${RED}Error: ftc-node binary not found.${NC}"
    echo "Please run ./build.sh first."
    exit 1
fi

# Clean previous
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"

# Copy files
echo "Copying files..."
cp "$SCRIPT_DIR/ftc-node" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/install.sh" "$PACKAGE_DIR/"
chmod +x "$PACKAGE_DIR/install.sh"
chmod +x "$PACKAGE_DIR/ftc-node"

# Copy icon if exists
if [ -f "$SCRIPT_DIR/ftc-node.png" ]; then
    cp "$SCRIPT_DIR/ftc-node.png" "$PACKAGE_DIR/"
fi

# Create README
cat > "$PACKAGE_DIR/README.txt" << EOF
FTC Node - Flow Token Chain
============================
Version: ${VERSION}
Platform: Linux ${ARCH}

Installation
------------
1. Extract this archive
2. Run the installer:

   # System-wide install (requires root):
   sudo ./install.sh

   # User install (no root required):
   ./install.sh --user

3. Start the node:

   # System install:
   sudo systemctl start ftc-node

   # User install:
   systemctl --user start ftc-node

API Usage
---------
The node runs an HTTP API on port 17319.

Check status:
  curl http://localhost:17319/status

Get blockchain info:
  curl http://localhost:17319/block/0

Uninstall
---------
  sudo ./install.sh --uninstall
  # or for user install:
  ./install.sh --user --uninstall

For more information:
  ./install.sh --help

Genesis: Kristian Pilatovich 20091227 - First Real P2P
EOF

# Create release directory
mkdir -p "$(dirname "$OUTPUT_FILE")"

# Create tarball
echo "Creating tarball..."
cd "$SCRIPT_DIR"
tar -czvf "$OUTPUT_FILE" "$PACKAGE_NAME"

# Cleanup
rm -rf "$PACKAGE_DIR"

# Show result
echo ""
echo -e "${GREEN}Package created successfully!${NC}"
echo ""
ls -lh "$OUTPUT_FILE"
echo ""
echo "To install on a Linux system:"
echo "  tar -xzf ${PACKAGE_NAME}.tar.gz"
echo "  cd ${PACKAGE_NAME}"
echo "  sudo ./install.sh"
