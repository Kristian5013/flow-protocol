#!/bin/bash
# FTC Node Update Script
# Updates binary without losing blockchain data
# Run as root
set -euo pipefail

echo "=== FTC Node Update ==="

# Stop the running node gracefully
if systemctl is-active --quiet ftcd; then
    echo "Stopping ftcd..."
    systemctl stop ftcd
    sleep 5
    echo "ftcd stopped"
else
    echo "ftcd is not running"
fi

# Backup current binary
if [ -f /opt/ftc/ftcd ]; then
    cp /opt/ftc/ftcd /opt/ftc/ftcd.bak
    echo "Backed up current binary to ftcd.bak"
fi

# Build new binary
echo "=== Building new version ==="
cd /tmp/ftc-deploy
git pull 2>/dev/null || echo "Not a git repo, using local source"
rm -rf build
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF
cmake --build . -j$(nproc)

# Install new binary
cp ftcd /opt/ftc/ftcd
chmod +x /opt/ftc/ftcd
chown ftc:ftc /opt/ftc/ftcd

# Start the node
echo "Starting ftcd..."
systemctl start ftcd
sleep 3

# Verify it's running
if systemctl is-active --quiet ftcd; then
    echo "=== Update complete ==="
    echo "ftcd is running"
    # Remove backup after successful start
    rm -f /opt/ftc/ftcd.bak
else
    echo "=== Update FAILED ==="
    echo "Restoring previous binary..."
    cp /opt/ftc/ftcd.bak /opt/ftc/ftcd
    systemctl start ftcd
    echo "Restored previous version"
    exit 1
fi
