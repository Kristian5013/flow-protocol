#!/bin/bash
# FTC Node Setup Script
# Run as root on a fresh Ubuntu 24.04 instance
set -euo pipefail

echo "=== FTC Node Setup ==="

# Install build dependencies
apt-get update
apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    git \
    curl

# Create ftc user
if ! id -u ftc &>/dev/null; then
    useradd -r -m -s /bin/bash ftc
    echo "Created ftc user"
fi

# Create directories
mkdir -p /opt/ftc
mkdir -p /var/lib/ftc
mkdir -p /etc/ftc

# Copy config
cp /tmp/ftc-deploy/deploy/ftc.conf /etc/ftc/ftc.conf

# Build from source
echo "=== Building FTC ==="
cd /tmp/ftc-deploy
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF
cmake --build . -j$(nproc)

# Install binary
cp ftcd /opt/ftc/ftcd
chmod +x /opt/ftc/ftcd

# Set ownership
chown -R ftc:ftc /var/lib/ftc
chown -R ftc:ftc /opt/ftc
chown -R ftc:ftc /etc/ftc

# Install systemd service
cp /tmp/ftc-deploy/deploy/ftcd.service /etc/systemd/system/ftcd.service
systemctl daemon-reload
systemctl enable ftcd

echo "=== Setup complete ==="
echo "Start the node with: systemctl start ftcd"
echo "View logs with: journalctl -u ftcd -f"
echo "Or: tail -f /var/lib/ftc/debug.log"
