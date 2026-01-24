#!/bin/bash
# FTC Build Script for Linux
# Kristian Pilatovich 20091227 - First Real P2P

set -e

echo "========================================"
echo "  FTC Build Script for Linux"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check dependencies
check_dep() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}Error: $1 not found. Please install it.${NC}"
        exit 1
    fi
}

check_dep cmake
check_dep g++
check_dep make

# Create dist directory
mkdir -p dist

# Build ftc-node
echo -e "${YELLOW}Building ftc-node...${NC}"
cd ftc-node
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cp ftc-node ../../dist/
cd ../..
echo -e "${GREEN}ftc-node built!${NC}"

# Build ftc-wallet
echo -e "${YELLOW}Building ftc-wallet...${NC}"
cd ftc-wallet
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cp ftc-wallet ../../dist/
cd ../..
echo -e "${GREEN}ftc-wallet built!${NC}"

# Build ftc-miner (requires OpenCL)
echo -e "${YELLOW}Building ftc-miner...${NC}"
if [ -d "/usr/include/CL" ] || [ -d "/opt/cuda/include" ]; then
    cd ftc-miner-v2
    mkdir -p build && cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(nproc)
    cp ftc-miner ../../dist/
    cd ../..
    echo -e "${GREEN}ftc-miner built!${NC}"
else
    echo -e "${RED}OpenCL not found. Skipping ftc-miner.${NC}"
    echo "Install: apt install ocl-icd-opencl-dev (or NVIDIA/AMD drivers)"
fi

# Build ftc-full
echo -e "${YELLOW}Building ftc-full...${NC}"
cd ftc-full
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cp ftc-full ../../dist/
cd ../..
echo -e "${GREEN}ftc-full built!${NC}"

echo ""
echo "========================================"
echo -e "${GREEN}Build complete!${NC}"
echo "========================================"
echo ""
echo "Binaries are in ./dist/"
ls -la dist/
echo ""
echo "Usage:"
echo "  ./dist/ftc-full -a ftc1q..."
echo "  ./dist/ftc-node"
echo "  ./dist/ftc-miner -a ftc1q..."
echo "  ./dist/ftc-wallet new"
