# FTC Build Scripts

## Windows

### Prerequisites
- Visual Studio 2019/2022 with C++ desktop development
- CMake 3.16+
- OpenCL SDK (NVIDIA CUDA Toolkit or AMD APP SDK)

### Build
```batch
scripts\build-all.bat
```

Options:
- `--debug` or `-d` - Build in debug mode
- `--clean` - Clean build directories first

### Output
Binaries are placed in `bin\` directory.

---

## Linux

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt-get install build-essential cmake libssl-dev libleveldb-dev libuv1-dev ocl-icd-opencl-dev opencl-headers

# Fedora
sudo dnf install gcc-c++ cmake openssl-devel leveldb-devel libuv-devel ocl-icd-devel opencl-headers

# Arch Linux
sudo pacman -S base-devel cmake openssl leveldb libuv ocl-icd opencl-headers
```

### Build
```bash
# Using shell script
chmod +x scripts/build-all.sh
./scripts/build-all.sh

# Or using Makefile
make

# Install dependencies automatically
./scripts/build-all.sh --install-deps
```

Options:
- `--debug` or `-d` - Build in debug mode
- `--clean` or `-c` - Clean build directories first
- `--install-deps` - Install dependencies (requires sudo)
- `-jN` - Use N parallel jobs

### Output
Binaries are placed in `bin/` directory.

---

## Quick Start

### 1. Generate a wallet
```bash
./bin/ftc-keygen
# Save the private key securely!
```

### 2. Start the node
```bash
./bin/ftc-node
```

### 3. Start mining
```bash
./bin/ftc-miner -o 127.0.0.1:17319 -u YOUR_WALLET_ADDRESS
```

### 4. Check balance
```bash
./bin/ftc-wallet balance YOUR_WALLET_ADDRESS
```

---

## Cross-Compilation

### Linux from Windows (using WSL)
```bash
wsl ./scripts/build-all.sh
```

### Windows from Linux (using MinGW)
```bash
# Install MinGW
sudo apt-get install mingw-w64

# Build
cmake -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64.cmake ..
make
```
