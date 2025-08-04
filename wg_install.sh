#!/bin/bash

# WireGuard + WGDashboard Auto-Installer Script
# Compatible with Debian/Ubuntu systems
# Run with: sudo bash wg_install.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
WG_DASHBOARD_DIR="/opt/WGDashboard"
WG_PORT="51820"
DASHBOARD_PORT="10086"

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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        echo "Usage: sudo bash $0"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
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

update_and_install_essentials() {
    print_status "Updating package lists and installing essential packages..."
    
    apt-get update -y
    
    apt-get install -y \
        wireguard-tools \
        net-tools \
        git \
        curl \
        iptables \
        python3 \
        python3-pip \
        python3-venv \
        --no-install-recommends
    
    print_success "Essential packages installed"
}

setup_wireguard() {
    print_status "Setting up WireGuard..."
    
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    sysctl -p /etc/sysctl.conf
    
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard
    
    print_success "WireGuard setup completed"
}

install_wgdashboard() {
    print_status "Installing WGDashboard..."
    
    rm -rf $WG_DASHBOARD_DIR
    
    cd /opt
    git clone https://github.com/donaldzou/WGDashboard.git
    
    cd $WG_DASHBOARD_DIR/src
    
    chmod +x ./wgd.sh
    ./wgd.sh install
    
    print_success "WGDashboard installed successfully"
}

setup_wgdashboard_service() {
    print_status "Setting up WGDashboard systemd service..."
    
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

    systemctl daemon-reload
    systemctl enable wgdashboard
    
    print_success "WGDashboard systemd service created and enabled"
}

generate_server_config() {
    print_status "Generating initial WireGuard server configuration..."
    
    cd /etc/wireguard
    
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    chmod 600 server_private.key server_public.key
    
    SERVER_PRIVATE_KEY=$(cat server_private.key)
    SERVER_PUBLIC_KEY=$(cat server_public.key)
    
    DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = 10.0.0.1/24
ListenPort = $WG_PORT
SaveConfig = true

PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE
EOF

    chmod 600 /etc/wireguard/wg0.conf
    chmod -R 755 /etc/wireguard
    
    print_success "Server configuration generated"
    print_status "Server public key: $SERVER_PUBLIC_KEY"
}

configure_firewall() {
    print_status "Configuring firewall with UFW..."
    
    apt-get install -y ufw
    
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    ufw allow ssh
    ufw allow $WG_PORT/udp comment "WireGuard"
    ufw allow $DASHBOARD_PORT/tcp comment "WGDashboard"
    
    ufw --force enable
    
    print_success "Firewall configured successfully"
}

# Check if sudo is available
check_sudo() {
    if command -v sudo >/dev/null 2>&1; then
        SUDO_CMD="sudo"
        print_status "sudo is available, will use it for WGDashboard"
    else
        SUDO_CMD=""
        print_status "sudo not available, running as root (no sudo needed)"
    fi
}

start_services() {
    print_status "Starting and enabling services..."
    
    # Check sudo availability
    check_sudo
    
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    if systemctl is-active --quiet wg-quick@wg0; then
        print_success "WireGuard VPN started and enabled for auto-start"
    else
        print_warning "WireGuard VPN may not have started properly. Check systemctl status wg-quick@wg0"
    fi
    
    cd $WG_DASHBOARD_DIR/src
    
    # Start WGDashboard with or without sudo based on availability
    if [[ -n "$SUDO_CMD" ]]; then
        $SUDO_CMD ./wgd.sh start
    else
        ./wgd.sh start
    fi
    
    systemctl start wgdashboard
    
    sleep 5
    
    if systemctl is-active --quiet wgdashboard; then
        print_success "WGDashboard started successfully"
    else
        print_warning "WGDashboard may not have started properly. Check systemctl status wgdashboard"
    fi
}

get_public_ip() {
    PUBLIC_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || curl -s --max-time 10 ipinfo.io/ip 2>/dev/null || echo "Unable to determine")
}

display_final_info() {
    get_public_ip
    
    echo ""
    echo "=============================================="
    print_success "WireGuard + WGDashboard Installation Complete!"
    echo "=============================================="
    echo ""
    
    print_status "Access Information:"
    if [[ "$PUBLIC_IP" != "Unable to determine" ]]; then
        echo "   Web Interface: http://$PUBLIC_IP:$DASHBOARD_PORT"
    fi
    echo "   Local Access:  http://localhost:$DASHBOARD_PORT"
    echo "   Default Login: admin / admin"
    echo ""
    
    print_warning "IMPORTANT SECURITY NOTES:"
    echo "   1. Change the default admin password immediately!"
    echo "   2. Consider setting up HTTPS for production use"
    echo "   3. Ensure your server firewall allows port $WG_PORT (UDP) and $DASHBOARD_PORT (TCP)"
    echo ""
    
    print_status "WireGuard Configuration:"
    echo "   Config file: /etc/wireguard/wg0.conf"
    echo "   Server keys: /etc/wireguard/server_*.key"
    echo "   VPN Status:  wg show"
    echo "   Auto-start:  ENABLED"
    echo ""
    
    print_status "WGDashboard Management:"
    echo "   Manual start:  cd $WG_DASHBOARD_DIR/src && ./wgd.sh start"
    echo "   Manual stop:   cd $WG_DASHBOARD_DIR/src && ./wgd.sh stop"
    echo "   Service start: systemctl start wgdashboard"
    echo "   Service stop:  systemctl stop wgdashboard"
    echo "   Service status: systemctl status wgdashboard"
    echo "   Auto-start:  ENABLED"
    echo ""
    
    print_status "Next Steps:"
    echo "   1. Access the dashboard and change default credentials"
    echo "   2. WireGuard is already running and will auto-start on boot"
    echo "   3. Add your first peer through the web interface"
    echo "   4. Download/scan QR code for client configuration"
    echo ""
    
    if [[ "$PUBLIC_IP" != "Unable to determine" ]]; then
        print_status "Your server's public IP: $PUBLIC_IP"
        print_status "Use this IP as the endpoint in client configurations"
    fi
    
    echo ""
    print_status "Documentation:"
    echo "   WGDashboard: https://docs.wgdashboard.dev/"
    echo "   WireGuard:   https://www.wireguard.com/"
    echo ""
    echo "=============================================="
    print_success "Installation completed successfully!"
    echo "=============================================="
}

main() {
    echo "=============================================="
    echo "  WireGuard + WGDashboard Auto-Installer"
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
    start_services
    display_final_info
    
    echo ""
    print_success "All installation steps completed successfully!"
}

trap 'print_error "Installation failed at line $LINENO. Check the output above for details."' ERR

main "$@" 