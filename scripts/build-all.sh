#!/bin/bash
# FTC Build Script for Linux
# Requires: GCC/Clang, CMake, OpenSSL, OpenCL SDK

set -e

echo "========================================"
echo "FTC Build Script (Linux)"
echo "========================================"
echo

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_TYPE="Release"
CLEAN_BUILD=0
INSTALL_DEPS=0
JOBS=$(nproc 2>/dev/null || echo 4)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug|-d)
            BUILD_TYPE="Debug"
            shift
            ;;
        --clean|-c)
            CLEAN_BUILD=1
            shift
            ;;
        --install-deps)
            INSTALL_DEPS=1
            shift
            ;;
        -j*)
            JOBS="${1#-j}"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --debug, -d       Build in debug mode"
            echo "  --clean, -c       Clean build directories first"
            echo "  --install-deps    Install dependencies (requires sudo)"
            echo "  -jN               Use N parallel jobs (default: nproc)"
            echo "  --help, -h        Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "Build type: $BUILD_TYPE"
echo "Root directory: $ROOT_DIR"
echo "Parallel jobs: $JOBS"
echo

# Install dependencies if requested
if [ $INSTALL_DEPS -eq 1 ]; then
    echo "Installing dependencies..."
    if command -v apt-get &>/dev/null; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            cmake \
            libssl-dev \
            libleveldb-dev \
            libuv1-dev \
            ocl-icd-opencl-dev \
            opencl-headers \
            nvidia-opencl-dev 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        # Fedora/RHEL
        sudo dnf install -y \
            gcc-c++ \
            cmake \
            openssl-devel \
            leveldb-devel \
            libuv-devel \
            ocl-icd-devel \
            opencl-headers
    elif command -v pacman &>/dev/null; then
        # Arch Linux
        sudo pacman -Sy --noconfirm \
            base-devel \
            cmake \
            openssl \
            leveldb \
            libuv \
            ocl-icd \
            opencl-headers
    else
        echo "Warning: Unknown package manager. Please install dependencies manually:"
        echo "  - CMake"
        echo "  - OpenSSL development files"
        echo "  - LevelDB development files"
        echo "  - libuv development files"
        echo "  - OpenCL development files"
    fi
    echo
fi

# Check for CMake
if ! command -v cmake &>/dev/null; then
    echo "ERROR: CMake not found! Please install CMake."
    echo "  Ubuntu/Debian: sudo apt-get install cmake"
    echo "  Fedora: sudo dnf install cmake"
    echo "  Arch: sudo pacman -S cmake"
    exit 1
fi

# Check for compiler
if ! command -v g++ &>/dev/null && ! command -v clang++ &>/dev/null; then
    echo "ERROR: No C++ compiler found! Please install GCC or Clang."
    exit 1
fi

# Clean if requested
if [ $CLEAN_BUILD -eq 1 ]; then
    echo "Cleaning build directories..."
    rm -rf "$ROOT_DIR/ftc-node/build"
    rm -rf "$ROOT_DIR/ftc-miner-v2/build"
    rm -rf "$ROOT_DIR/ftc-wallet/build"
    rm -rf "$ROOT_DIR/ftc-keygen/build"
    echo
fi

# Create output directory
mkdir -p "$ROOT_DIR/bin"

# Function to build a component
build_component() {
    local name=$1
    local dir=$2

    echo "========================================"
    echo "Building $name..."
    echo "========================================"

    mkdir -p "$dir/build"
    cd "$dir/build"

    cmake .. -DCMAKE_BUILD_TYPE=$BUILD_TYPE
    cmake --build . --config $BUILD_TYPE -- -j$JOBS

    # Copy binary to bin directory
    local exe=$(find . -maxdepth 2 -type f -executable -name "$name*" 2>/dev/null | head -1)
    if [ -n "$exe" ]; then
        cp -f "$exe" "$ROOT_DIR/bin/"
        echo "$name built successfully!"
    else
        # Try without extension for Release builds
        exe=$(find . -maxdepth 2 -type f -executable ! -name "*.o" ! -name "*.cmake" 2>/dev/null | head -1)
        if [ -n "$exe" ]; then
            cp -f "$exe" "$ROOT_DIR/bin/"
            echo "$name built successfully!"
        fi
    fi

    cd "$ROOT_DIR"
    echo
}

# Build all components
build_component "ftc-node" "$ROOT_DIR/ftc-node"
build_component "ftc-miner" "$ROOT_DIR/ftc-miner-v2"
build_component "ftc-wallet" "$ROOT_DIR/ftc-wallet"
build_component "ftc-keygen" "$ROOT_DIR/ftc-keygen"

echo "========================================"
echo "BUILD COMPLETE!"
echo "========================================"
echo
echo "Binaries are located in: $ROOT_DIR/bin/"
echo
ls -la "$ROOT_DIR/bin/" 2>/dev/null || echo "No binaries found"
echo
echo "Run with:"
echo "  ./ftc-node          - Start the blockchain node"
echo "  ./ftc-miner         - Start GPU mining"
echo "  ./ftc-wallet        - Wallet operations"
echo "  ./ftc-keygen        - Generate new wallet keys"
echo
echo "Quick start:"
echo "  1. Generate a wallet: ./ftc-keygen"
echo "  2. Start the node:    ./ftc-node"
echo "  3. Start mining:      ./ftc-miner -o 127.0.0.1:17319 -u YOUR_WALLET_ADDRESS"
