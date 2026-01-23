#!/bin/bash
# FTC Node Installation Script for Linux
# Kristian Pilatovich 20091227 - First Real P2P

set -e

echo "================================"
echo "  FTC Node Installation"
echo "  First Real P2P"
echo "================================"
echo

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo ./install-linux.sh"
    exit 1
fi

# Create ftc user if not exists
if ! id -u ftc >/dev/null 2>&1; then
    echo "[+] Creating ftc user..."
    useradd -r -m -d /var/lib/ftc -s /bin/false ftc
fi

# Create directories
echo "[+] Creating directories..."
mkdir -p /var/lib/ftc
mkdir -p /var/log/ftc
chown -R ftc:ftc /var/lib/ftc
chown -R ftc:ftc /var/log/ftc
chmod 750 /var/lib/ftc

# Copy binary
echo "[+] Installing ftc-node..."
cp ftc-node /usr/local/bin/
chmod 755 /usr/local/bin/ftc-node

# Install systemd service
echo "[+] Installing systemd service..."
cp ftc-node.service /etc/systemd/system/
systemctl daemon-reload

# Enable service
echo "[+] Enabling service..."
systemctl enable ftc-node

echo
echo "================================"
echo "  Installation Complete!"
echo "================================"
echo
echo "Commands:"
echo "  sudo systemctl start ftc-node    # Start node"
echo "  sudo systemctl stop ftc-node     # Stop node"
echo "  sudo systemctl status ftc-node   # Check status"
echo "  journalctl -u ftc-node -f        # View logs"
echo
echo "Data directory: /var/lib/ftc"
echo "API endpoint:   http://[::1]:17319/status"
echo
echo "Add peers to: /var/lib/ftc/peers.dat"
echo
