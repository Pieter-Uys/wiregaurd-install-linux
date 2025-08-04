#!/bin/bash

# WireGuard + WGDashboard Auto-Installer Script (Latest Version)
# Compatible with Debian/Ubuntu systems
# Follows official documentation from wireguard.com and wgdashboard.dev
# Run with: sudo bash install_wireguard.sh

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
WG_DASHBOARD_DIR="/opt/WGDashboard"
WG_PORT="51820"
DASHBOARD_PORT="10086"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        echo "Usage: sudo bash $0"
        exit 1
    fi
}

# Detect OS and version
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        print_error "Cannot detect OS. This script supports Debian/Ubuntu only."
        exit 1
    fi
    
    if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
        print_error "Unsupported OS: $OS. This script supports Debian/Ubuntu only."
        exit 1
    fi
    
    print_success "Detected OS: $OS $OS_VERSION"
}

# Update package lists and install essential packages
update_and_install_essentials() {
    print_status "Updating package lists and installing essential packages..."
    
    apt-get update -y
    
    # Install essential packages following WGDashboard documentation
    apt-get install -y \
        wireguard-tools \
        net-tools \
        git \
        curl \
        iptables \
        --no-install-recommends
    
    print_success "Essential packages installed"
}

# Install WireGuard (already included in essential packages)
setup_wireguard() {
    print_status "Setting up WireGuard..."
    
    # Enable IP forwarding (following official documentation)
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    sysctl -p /etc/sysctl.conf
    
    # Create WireGuard directories with proper permissions
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard
    
    print_success "WireGuard setup completed"
}

# Install WGDashboard following official documentation
install_wgdashboard() {
    print_status "Installing WGDashboard following official documentation..."
    
    # Remove any existing installation
    rm -rf $WG_DASHBOARD_DIR
    
    # Clone WGDashboard repository (latest version)
    cd /opt
    git clone https://github.com/donaldzou/WGDashboard.git
    
    # Navigate to src directory as per documentation
    cd $WG_DASHBOARD_DIR/src
    
    # Make wgd.sh executable and install
    chmod +x ./wgd.sh
    ./wgd.sh install
    
    print_success "WGDashboard installed successfully"
}

# Setup WGDashboard systemd service
setup_wgdashboard_service() {
    print_status "Setting up WGDashboard systemd service..."
    
    # Create systemd service file for WGDashboard
    cat > /etc/systemd/system/wgdashboard.service << EOF
[Unit]
Description=WGDashboard
Documentation=https://github.com/donaldzou/WGDashboard
After=syslog.target network-online.target
Wants=network-online.target

[Service]
Type=forking
User=root
Group=root
WorkingDirectory=$WG_DASHBOARD_DIR/src
ExecStart=$WG_DASHBOARD_DIR/src/wgd.sh start
ExecStop=$WG_DASHBOARD_DIR/src/wgd.sh stop
ExecReload=$WG_DASHBOARD_DIR/src/wgd.sh restart
TimeoutSec=30
RestartSec=15s
Restart=always
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable the service
    systemctl daemon-reload
    systemctl enable wgdashboard
    
    print_success "WGDashboard systemd service created and enabled"
}

# Generate initial WireGuard server configuration
generate_server_config() {
    print_status "Generating initial WireGuard server configuration..."
    
    cd /etc/wireguard
    
    # Generate server keys
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    chmod 600 server_private.key server_public.key
    
    SERVER_PRIVATE_KEY=$(cat server_private.key)
    SERVER_PUBLIC_KEY=$(cat server_public.key)
    
    # Get the default network interface
    DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    # Create basic server configuration following best practices
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = 10.0.0.1/24
ListenPort = $WG_PORT
SaveConfig = true

# NAT rules for traffic forwarding
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE

# Peers will be added here via WGDashboard
EOF

    chmod 600 /etc/wireguard/wg0.conf
    
    # Give proper permissions to WireGuard directory (as per documentation)
    chmod -R 755 /etc/wireguard
    
    print_success "Server configuration generated"
    print_status "Server public key: $SERVER_PUBLIC_KEY"
}

# Configure firewall using UFW
configure_firewall() {
    print_status "Configuring firewall with UFW..."
    
    # Install and configure UFW
    apt-get install -y ufw
    
    # Reset UFW to default settings
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow essential services
    ufw allow ssh
    ufw allow $WG_PORT/udp comment "WireGuard"
    ufw allow $DASHBOARD_PORT/tcp comment "WGDashboard"
    
    # Enable UFW
    ufw --force enable
    
    print_success "Firewall configured successfully"
}

# Start WGDashboard
start_wgdashboard() {
    print_status "Starting WGDashboard..."
    
    cd $WG_DASHBOARD_DIR/src
    
    # Start WGDashboard using the official method
    ./wgd.sh start
    
    # Start the systemd service
    systemctl start wgdashboard
    
    # Wait for service to be ready
    sleep 5
    
    if systemctl is-active --quiet wgdashboard; then
        print_success "WGDashboard started successfully"
    else
        print_warning "WGDashboard may not have started properly. Check systemctl status wgdashboard"
    fi
}

# Get server public IP
get_public_ip() {
    PUBLIC_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || curl -s --max-time 10 ipinfo.io/ip 2>/dev/null || echo "Unable to determine")
}

# Display comprehensive final information
display_final_info() {
    get_public_ip
    
    echo ""
    echo "=============================================="
    print_success "WireGuard + WGDashboard Installation Complete!"
    echo "=============================================="
    echo ""
    
    print_status "🌐 Access Information:"
    if [[ "$PUBLIC_IP" != "Unable to determine" ]]; then
        echo "   Web Interface: http://$PUBLIC_IP:$DASHBOARD_PORT"
    fi
    echo "   Local Access:  http://localhost:$DASHBOARD_PORT"
    echo "   Default Login: admin / admin"
    echo ""
    
    print_warning "🔒 IMPORTANT SECURITY NOTES:"
    echo "   1. Change the default admin password immediately!"
    echo "   2. Consider setting up HTTPS for production use"
    echo "   3. Ensure your server firewall allows port $WG_PORT (UDP) and $DASHBOARD_PORT (TCP)"
    echo ""
    
    print_status "🔧 WireGuard Configuration:"
    echo "   • Config file: /etc/wireguard/wg0.conf"
    echo "   • Server keys: /etc/wireguard/server_*.key"
    echo "   • Start VPN:   systemctl start wg-quick@wg0"
    echo "   • Stop VPN:    systemctl stop wg-quick@wg0"
    echo "   • Enable at boot: systemctl enable wg-quick@wg0"
    echo "   • VPN Status:  wg show"
    echo ""
    
    print_status "🖥️  WGDashboard Management:"
    echo "   • Manual start:  cd $WG_DASHBOARD_DIR/src && ./wgd.sh start"
    echo "   • Manual stop:   cd $WG_DASHBOARD_DIR/src && ./wgd.sh stop"
    echo "   • Service start: systemctl start wgdashboard"
    echo "   • Service stop:  systemctl stop wgdashboard"
    echo "   • Service status: systemctl status wgdashboard"
    echo "   • View logs:     journalctl -u wgdashboard -f"
    echo ""
    
    print_status "📋 Next Steps:"
    echo "   1. Access the dashboard and change default credentials"
    echo "   2. Start WireGuard: systemctl start wg-quick@wg0"
    echo "   3. Add your first peer through the web interface"
    echo "   4. Download/scan QR code for client configuration"
    echo ""
    
    if [[ "$PUBLIC_IP" != "Unable to determine" ]]; then
        print_status "🌍 Your server's public IP: $PUBLIC_IP"
        print_status "🔗 Use this IP as the endpoint in client configurations"
    fi
    
    echo ""
    print_status "📚 Documentation:"
    echo "   • WGDashboard: https://docs.wgdashboard.dev/"
    echo "   • WireGuard:   https://www.wireguard.com/"
    echo ""
    echo "=============================================="
    print_success "Installation completed successfully! 🎉"
    echo "=============================================="
}

# Main installation function
main() {
    echo "=============================================="
    echo "  WireGuard + WGDashboard Auto-Installer"
    echo "     Following Official Documentation"
    echo "=============================================="
    echo ""
    
    print_status "Starting installation process..."
    echo ""
    
    check_root
    detect_os
    update_and_install_essentials
    setup_wireguard
    generate_server_config
    install_wgdashboard
    setup_wgdashboard_service
    configure_firewall
    start_wgdashboard
    display_final_info
    
    echo ""
    print_success "All installation steps completed successfully!"
}

# Trap errors and provide helpful information
trap 'print_error "Installation failed at line $LINENO. Check the output above for details."' ERR

# Run main function
main "$@"
