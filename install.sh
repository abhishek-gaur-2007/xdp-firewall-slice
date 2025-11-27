#!/bin/bash

# Slice-XDP Firewall Installation Script
# This script automates the installation process for any Linux system

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Slice-XDP Firewall Installer ===${NC}\n"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Please run: sudo ./install.sh"
    exit 1
fi

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/arch-release ]; then
        DISTRO="arch"
    else
        DISTRO="unknown"
    fi
    echo -e "${BLUE}Detected: $DISTRO${NC}\n"
}

# Install dependencies based on distro
install_dependencies() {
    echo "Installing dependencies..."
    
    case $DISTRO in
        ubuntu|debian)
            apt update
            apt install -y \
                clang \
                llvm \
                golang-go \
                libbpf-dev \
                linux-headers-$(uname -r) \
                linux-headers-generic \
                build-essential \
                pkg-config \
                || {
                    echo -e "${YELLOW}Warning: Some packages may not have installed${NC}"
                    echo "Attempting to continue..."
                }
            ;;
        rhel|centos|fedora)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y clang llvm golang libbpf-devel kernel-devel kernel-headers make gcc
            else
                yum install -y clang llvm golang libbpf-devel kernel-devel kernel-headers make gcc
            fi
            ;;
        arch|manjaro)
            pacman -S --noconfirm clang llvm go libbpf linux-headers base-devel || true
            ;;
        *)
            echo -e "${YELLOW}Warning: Unknown distribution. Please install manually:${NC}"
            echo "  - clang and llvm"
            echo "  - golang"
            echo "  - libbpf development files"
            echo "  - kernel headers for $(uname -r)"
            echo "  - build-essential / base-devel"
            echo ""
            read -p "Press Enter to continue if dependencies are installed, or Ctrl+C to exit..."
            ;;
    esac
}

# Verify critical dependencies
verify_dependencies() {
    echo -e "\nVerifying dependencies..."
    
    local missing=0
    
    if ! command -v clang >/dev/null 2>&1; then
        echo -e "${RED}✗ clang not found${NC}"
        missing=1
    else
        echo -e "${GREEN}✓ clang found: $(clang --version | head -1)${NC}"
    fi
    
    if ! command -v go >/dev/null 2>&1; then
        echo -e "${RED}✗ go not found${NC}"
        missing=1
    else
        echo -e "${GREEN}✓ go found: $(go version)${NC}"
    fi
    
    # Check for kernel headers
    if [ -d "/usr/src/linux-headers-$(uname -r)" ]; then
        echo -e "${GREEN}✓ kernel headers found for $(uname -r)${NC}"
    else
        echo -e "${YELLOW}⚠ kernel headers not found for $(uname -r)${NC}"
        echo -e "${YELLOW}⚠ Attempting to use generic headers...${NC}"
    fi
    
    # Check for libbpf
    if pkg-config --exists libbpf 2>/dev/null || [ -f /usr/include/bpf/bpf.h ]; then
        echo -e "${GREEN}✓ libbpf found${NC}"
    else
        echo -e "${YELLOW}⚠ libbpf may not be installed${NC}"
    fi
    
    if [ $missing -eq 1 ]; then
        echo -e "\n${RED}Error: Critical dependencies missing${NC}"
        echo "Please install them manually and try again."
        exit 1
    fi
    
    echo -e "${GREEN}✓ All critical dependencies verified${NC}\n"
}

# Build the project
build_project() {
    echo "Building Slice-XDP..."
    
    # Clean first
    make clean 2>/dev/null || true
    
    # Attempt build
    if make; then
        echo -e "${GREEN}✓ Build successful${NC}\n"
    else
        echo -e "${RED}Error: Build failed${NC}"
        echo -e "\n${YELLOW}Troubleshooting:${NC}"
        echo "1. Ensure kernel headers are installed: sudo apt install linux-headers-\$(uname -r)"
        echo "2. Ensure libbpf-dev is installed: sudo apt install libbpf-dev"
        echo "3. Check the error messages above for specific issues"
        echo "4. See BUILD_TROUBLESHOOTING.md for more help"
        exit 1
    fi
    
    # Verify build outputs
    if [ ! -f "xdp_firewall.o" ]; then
        echo -e "${RED}Error: XDP object file not created${NC}"
        exit 1
    fi
    
    if [ ! -f "start" ]; then
        echo -e "${RED}Error: Go binary not created${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Build artifacts verified${NC}\n"
}

# Main installation
main() {
    detect_distro
    install_dependencies
    verify_dependencies
    build_project

    # Install to system
    echo "Installing to system..."
    
    # Create directories
    mkdir -p /usr/local/lib/slice-xdp
    mkdir -p /etc/slice-xdp
    mkdir -p /var/log/slice-xdp
    
    # Install binaries
    install -m 0755 start /usr/local/bin/slice-xdp
    install -m 0644 xdp_firewall.o /usr/local/lib/slice-xdp/xdp_firewall.o
    
    # Install config files (don't overwrite existing)
    if [ ! -f /etc/slice-xdp/config.toml ]; then
        install -m 0644 config.toml /etc/slice-xdp/config.toml
        echo -e "${GREEN}✓ Installed config.toml${NC}"
    else
        echo -e "${YELLOW}⚠ Config file already exists, skipping${NC}"
    fi
    
    if [ ! -f /etc/slice-xdp/whitelist.txt ]; then
        install -m 0644 whitelist.txt /etc/slice-xdp/whitelist.txt
        echo -e "${GREEN}✓ Installed whitelist.txt${NC}"
    else
        echo -e "${YELLOW}⚠ Whitelist file already exists, skipping${NC}"
    fi
    
    if [ ! -f /etc/slice-xdp/blacklist.txt ]; then
        install -m 0644 blacklist.txt /etc/slice-xdp/blacklist.txt
        echo -e "${GREEN}✓ Installed blacklist.txt${NC}"
    else
        echo -e "${YELLOW}⚠ Blacklist file already exists, skipping${NC}"
    fi
    
    echo -e "\n${GREEN}✓ Installation complete${NC}\n"
    
    # Ask about systemd service
    read -p "Do you want to install the systemd service? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Get network interface
        echo -e "\nAvailable network interfaces:"
        ip -brief link show | grep -v "lo" | awk '{print "  - " $1}'
        echo
        read -p "Enter the interface to protect (e.g., eth0): " INTERFACE
        
        if [ -z "$INTERFACE" ]; then
            echo -e "${RED}Error: Interface cannot be empty${NC}"
            exit 1
        fi
        
        # Ask for XDP mode
        read -p "XDP mode (native/generic) [native]: " MODE
        MODE=${MODE:-native}
        
        # Create service file
        sed "s/eth0/$INTERFACE/g; s/native/$MODE/g" slice-xdp.service > /etc/systemd/system/slice-xdp.service
        
        systemctl daemon-reload
        
        echo -e "\n${GREEN}✓ Systemd service installed${NC}"
        echo -e "\nTo enable and start the service:"
        echo "  sudo systemctl enable slice-xdp"
        echo "  sudo systemctl start slice-xdp"
        echo -e "\nTo check status:"
        echo "  sudo systemctl status slice-xdp"
    fi
    
    echo -e "\n${GREEN}=== Installation Summary ===${NC}"
    echo "Binary:      /usr/local/bin/slice-xdp"
    echo "XDP Object:  /usr/local/lib/slice-xdp/xdp_firewall.o"
    echo "Config:      /etc/slice-xdp/config.toml"
    echo "Whitelist:   /etc/slice-xdp/whitelist.txt"
    echo "Blacklist:   /etc/slice-xdp/blacklist.txt"
    echo "Logs:        /var/log/slice-xdp/"
    echo ""
    echo -e "${GREEN}Usage:${NC} slice-xdp -t <seconds> -i <interface> -d <native|generic>"
    echo ""
    echo -e "Edit config: ${YELLOW}sudo nano /etc/slice-xdp/config.toml${NC}"
    echo -e "View README: ${YELLOW}less README.md${NC}"
    echo -e "\n${BLUE}Quick Start:${NC}"
    echo "  1. Edit config: sudo nano /etc/slice-xdp/config.toml"
    echo "  2. Add your IP to whitelist: echo \"YOUR.IP.HERE\" | sudo tee -a /etc/slice-xdp/whitelist.txt"
    echo "  3. Run: sudo slice-xdp -i eth0 -d native"
}

# Run main installation
main

