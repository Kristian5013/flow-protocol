#!/bin/bash
#
# FTC Node Installer for Linux
# Flow Token Chain - Cryptocurrency Full Node
#
# Usage: sudo ./install.sh [OPTIONS]
#
# Options:
#   --user          Install for current user only (no sudo required)
#   --no-service    Don't install systemd service
#   --no-autostart  Don't enable autostart
#   --uninstall     Remove FTC Node
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Version
VERSION="1.0.0"

# Default options
USER_INSTALL=false
NO_SERVICE=false
NO_AUTOSTART=false
UNINSTALL=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --user)
            USER_INSTALL=true
            shift
            ;;
        --no-service)
            NO_SERVICE=true
            shift
            ;;
        --no-autostart)
            NO_AUTOSTART=true
            shift
            ;;
        --uninstall)
            UNINSTALL=true
            shift
            ;;
        -h|--help)
            echo "FTC Node Installer v${VERSION}"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --user          Install for current user only (no sudo required)"
            echo "  --no-service    Don't install systemd service"
            echo "  --no-autostart  Don't enable autostart"
            echo "  --uninstall     Remove FTC Node"
            echo "  -h, --help      Show this help"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Determine install paths
if [ "$USER_INSTALL" = true ]; then
    BIN_DIR="$HOME/.local/bin"
    DATA_DIR="$HOME/.ftc"
    SERVICE_DIR="$HOME/.config/systemd/user"
    DESKTOP_DIR="$HOME/.local/share/applications"
    ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"
    SYSTEMCTL_USER="--user"
else
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: Root privileges required. Use sudo or --user flag.${NC}"
        exit 1
    fi
    BIN_DIR="/usr/local/bin"
    DATA_DIR="/var/lib/ftc"
    SERVICE_DIR="/etc/systemd/system"
    DESKTOP_DIR="/usr/share/applications"
    ICON_DIR="/usr/share/icons/hicolor/256x256/apps"
    SYSTEMCTL_USER=""
fi

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "  ______ _______ _____   _   _           _      "
    echo " |  ____|__   __/ ____| | \ | |         | |     "
    echo " | |__     | | | |      |  \| | ___   __| | ___ "
    echo " |  __|    | | | |      | . \` |/ _ \ / _\` |/ _ \\"
    echo " | |       | | | |____  | |\  | (_) | (_| |  __/"
    echo " |_|       |_|  \_____| |_| \_|\___/ \__,_|\___|"
    echo -e "${NC}"
    echo -e "${GREEN}Flow Token Chain - Cryptocurrency Full Node${NC}"
    echo -e "Version ${VERSION}"
    echo ""
}

# Uninstall function
do_uninstall() {
    echo -e "${YELLOW}Uninstalling FTC Node...${NC}"

    # Stop service if running
    if systemctl $SYSTEMCTL_USER is-active --quiet ftc-node 2>/dev/null; then
        echo "  Stopping ftc-node service..."
        systemctl $SYSTEMCTL_USER stop ftc-node
    fi

    # Disable service
    if systemctl $SYSTEMCTL_USER is-enabled --quiet ftc-node 2>/dev/null; then
        echo "  Disabling ftc-node service..."
        systemctl $SYSTEMCTL_USER disable ftc-node
    fi

    # Remove files
    echo "  Removing files..."
    rm -f "$BIN_DIR/ftc-node"
    rm -f "$SERVICE_DIR/ftc-node.service"
    rm -f "$DESKTOP_DIR/ftc-node.desktop"
    rm -f "$ICON_DIR/ftc-node.png"

    # Reload systemd
    systemctl $SYSTEMCTL_USER daemon-reload 2>/dev/null || true

    echo -e "${GREEN}FTC Node has been uninstalled.${NC}"
    echo ""
    echo "Note: Data directory was preserved at: $DATA_DIR"
    echo "To remove all data: rm -rf $DATA_DIR"
}

# Install function
do_install() {
    echo -e "${YELLOW}Installing FTC Node...${NC}"

    # Check if binary exists
    if [ ! -f "$SCRIPT_DIR/ftc-node" ]; then
        echo -e "${RED}Error: ftc-node binary not found in $SCRIPT_DIR${NC}"
        echo "Please ensure ftc-node binary is in the same directory as this script."
        exit 1
    fi

    # Create directories
    echo "  Creating directories..."
    mkdir -p "$BIN_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$DESKTOP_DIR"
    mkdir -p "$ICON_DIR"

    # Copy binary
    echo "  Installing ftc-node binary..."
    cp "$SCRIPT_DIR/ftc-node" "$BIN_DIR/ftc-node"
    chmod +x "$BIN_DIR/ftc-node"

    # Copy icon if exists
    if [ -f "$SCRIPT_DIR/ftc-node.png" ]; then
        echo "  Installing icon..."
        cp "$SCRIPT_DIR/ftc-node.png" "$ICON_DIR/ftc-node.png"
    fi

    # Create desktop entry
    echo "  Creating desktop entry..."
    cat > "$DESKTOP_DIR/ftc-node.desktop" << EOF
[Desktop Entry]
Name=FTC Node
Comment=Flow Token Chain Cryptocurrency Node
Exec=$BIN_DIR/ftc-node
Icon=ftc-node
Terminal=false
Type=Application
Categories=Network;P2P;Finance;
Keywords=cryptocurrency;blockchain;bitcoin;ftc;
StartupNotify=false
EOF

    # Install systemd service
    if [ "$NO_SERVICE" = false ]; then
        echo "  Installing systemd service..."
        mkdir -p "$SERVICE_DIR"

        if [ "$USER_INSTALL" = true ]; then
            cat > "$SERVICE_DIR/ftc-node.service" << EOF
[Unit]
Description=FTC Node - Flow Token Chain
Documentation=https://github.com/anthropics/ftc-node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_DIR/ftc-node
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
EOF
        else
            cat > "$SERVICE_DIR/ftc-node.service" << EOF
[Unit]
Description=FTC Node - Flow Token Chain
Documentation=https://github.com/anthropics/ftc-node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ftc
Group=ftc
ExecStart=$BIN_DIR/ftc-node
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
            # Create ftc user for system install
            if ! id -u ftc >/dev/null 2>&1; then
                echo "  Creating ftc user..."
                useradd --system --no-create-home --shell /usr/sbin/nologin ftc
            fi
            chown -R ftc:ftc "$DATA_DIR"
        fi

        # Reload systemd
        systemctl $SYSTEMCTL_USER daemon-reload

        # Enable autostart
        if [ "$NO_AUTOSTART" = false ]; then
            echo "  Enabling autostart..."
            systemctl $SYSTEMCTL_USER enable ftc-node
        fi
    fi

    # Update icon cache
    if command -v gtk-update-icon-cache &> /dev/null; then
        gtk-update-icon-cache -f -t "$(dirname "$ICON_DIR")" 2>/dev/null || true
    fi

    echo ""
    echo -e "${GREEN}FTC Node has been installed successfully!${NC}"
    echo ""
    echo "Installation details:"
    echo "  Binary:   $BIN_DIR/ftc-node"
    echo "  Data:     $DATA_DIR"
    if [ "$NO_SERVICE" = false ]; then
        echo "  Service:  $SERVICE_DIR/ftc-node.service"
    fi
    echo ""
    echo "Usage:"
    echo "  Start node:    systemctl $SYSTEMCTL_USER start ftc-node"
    echo "  Stop node:     systemctl $SYSTEMCTL_USER stop ftc-node"
    echo "  View status:   systemctl $SYSTEMCTL_USER status ftc-node"
    echo "  View logs:     journalctl $SYSTEMCTL_USER -u ftc-node -f"
    echo ""
    echo "API endpoint: http://localhost:17319"
    echo "  curl http://localhost:17319/status"
    echo ""

    # Add to PATH reminder for user install
    if [ "$USER_INSTALL" = true ]; then
        if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
            echo -e "${YELLOW}Note: Add $BIN_DIR to your PATH:${NC}"
            echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
            echo ""
        fi
    fi
}

# Main
print_banner

if [ "$UNINSTALL" = true ]; then
    do_uninstall
else
    do_install
fi
