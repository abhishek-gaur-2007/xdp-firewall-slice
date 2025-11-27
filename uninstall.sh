#!/bin/bash

# Slice-XDP Firewall Uninstallation Script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Slice-XDP Firewall Uninstaller ===${NC}\n"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Please run: sudo ./uninstall.sh"
    exit 1
fi

# Stop service if running
if systemctl is-active --quiet slice-xdp; then
    echo "Stopping slice-xdp service..."
    systemctl stop slice-xdp
    echo -e "${GREEN}✓ Service stopped${NC}"
fi

# Disable service if enabled
if systemctl is-enabled --quiet slice-xdp 2>/dev/null; then
    echo "Disabling slice-xdp service..."
    systemctl disable slice-xdp
    echo -e "${GREEN}✓ Service disabled${NC}"
fi

# Remove service file
if [ -f /etc/systemd/system/slice-xdp.service ]; then
    rm -f /etc/systemd/system/slice-xdp.service
    systemctl daemon-reload
    echo -e "${GREEN}✓ Service file removed${NC}"
fi

# Remove binary and object file
if [ -f /usr/local/bin/slice-xdp ]; then
    rm -f /usr/local/bin/slice-xdp
    echo -e "${GREEN}✓ Binary removed${NC}"
fi

if [ -d /usr/local/lib/slice-xdp ]; then
    rm -rf /usr/local/lib/slice-xdp
    echo -e "${GREEN}✓ XDP object removed${NC}"
fi

echo -e "\n${GREEN}✓ Uninstallation complete${NC}"

# Ask about config and logs
echo ""
read -p "Do you want to remove config files and logs? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /etc/slice-xdp
    rm -rf /var/log/slice-xdp
    echo -e "${GREEN}✓ Config files and logs removed${NC}"
else
    echo -e "${YELLOW}⚠ Kept config files in /etc/slice-xdp${NC}"
    echo -e "${YELLOW}⚠ Kept logs in /var/log/slice-xdp${NC}"
fi

echo -e "\n${GREEN}Slice-XDP has been uninstalled${NC}"

