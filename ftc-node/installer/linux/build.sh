#!/bin/bash
#
# FTC Node Build Script for Linux
#
# This script builds ftc-node and creates a distributable package.
#
# Requirements:
#   - CMake 3.16+
#   - GCC/Clang with C++17 support
#   - Git
#
# Usage: ./build.sh [--release|--debug]
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
VERSION="1.0.0"
BUILD_TYPE="Release"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build_linux"
OUTPUT_DIR="$SCRIPT_DIR"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --release)
            BUILD_TYPE="Release"
            shift
            ;;
        --debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        -h|--help)
            echo "FTC Node Build Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --release    Build release version (default)"
            echo "  --debug      Build debug version"
            echo "  -h, --help   Show this help"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${GREEN}Building FTC Node v${VERSION} (${BUILD_TYPE})${NC}"
echo ""

# Check dependencies
echo "Checking dependencies..."

if ! command -v cmake &> /dev/null; then
    echo -e "${RED}Error: cmake not found. Please install cmake.${NC}"
    exit 1
fi

if ! command -v g++ &> /dev/null && ! command -v clang++ &> /dev/null; then
    echo -e "${RED}Error: No C++ compiler found. Please install g++ or clang++.${NC}"
    exit 1
fi

echo "  cmake: $(cmake --version | head -n1)"
if command -v g++ &> /dev/null; then
    echo "  g++: $(g++ --version | head -n1)"
fi

# Create build directory
echo ""
echo "Creating build directory..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure
echo "Configuring..."
cmake "$PROJECT_DIR" \
    -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
    -DCMAKE_CXX_FLAGS="-O2 -march=x86-64 -mtune=generic"

# Build
echo ""
echo "Building..."
cmake --build . --config $BUILD_TYPE -j$(nproc)

# Check result
if [ ! -f "$BUILD_DIR/ftc-node" ]; then
    echo -e "${RED}Error: Build failed - ftc-node not found${NC}"
    exit 1
fi

# Copy to output
echo ""
echo "Copying files to installer directory..."
cp "$BUILD_DIR/ftc-node" "$OUTPUT_DIR/ftc-node"
chmod +x "$OUTPUT_DIR/ftc-node"

# Copy icon
if [ -f "$PROJECT_DIR/assets/ftc-node-256.png" ]; then
    cp "$PROJECT_DIR/assets/ftc-node-256.png" "$OUTPUT_DIR/ftc-node.png"
fi

# Strip binary (release only)
if [ "$BUILD_TYPE" = "Release" ]; then
    echo "Stripping binary..."
    strip "$OUTPUT_DIR/ftc-node"
fi

# Show result
echo ""
echo -e "${GREEN}Build complete!${NC}"
echo ""
ls -lh "$OUTPUT_DIR/ftc-node"
echo ""
echo "Files ready in: $OUTPUT_DIR"
echo ""
echo "To create distribution package, run:"
echo "  ./package.sh"
