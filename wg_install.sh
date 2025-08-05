#!/bin/bash

# WireGuard + WGDashboard Auto-Installer Script
# Secure by default - Dashboard local access only
# Compatible with Debian/Ubuntu systems
# Version: 1.0
# Run with: bash <(curl -s https://raw.githubusercontent.com/yourusername/wg-installer/main/install.sh)

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
WG_DIR="/etc/wireguard"
WG_DASHBOARD_DIR="/opt/WGDashboard"
WG_PORT="${WG_PORT:-51820}"
DASHBOARD_PORT="${DASHBOARD_PORT:-10086}"
WG_INTERFACE="wg0"
WG_SUBNET="10.0.0.0/24"
WG_SERVER_IP="10.0.0.1"

# Script info
SCRIPT_VERSION="1.0"
LOG_FILE="/var/log/wg-installer.log"

# Logging setup
exec 2> >(tee -a "$LOG_FILE" >&2)

msg() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[✗]${NC} $1" | tee -a "$LOG_FILE"
}

header() {
    echo ""
    echo "====================================="
    echo " WireGuard + Dashboard Installer"
    echo " Version: $SCRIPT_VERSION"
    echo "====================================="
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect OS"
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        error "This script supports Debian/Ubuntu only"
        exit 1
    fi
    
    success "Detected: $PRETTY_NAME"
}

check_virt() {
    if command -v systemd-detect-virt &> /dev/null; then
        VIRT=$(systemd-detect-virt)
        if [[ "$VIRT" != "none" ]]; then
            msg "Virtualization: $VIRT"
            if [[ "$VIRT" == "lxc" || "$VIRT" == "openvz" ]]; then
                warn "Container detected - kernel module must be loaded on host"
                read -p "Continue? (y/N): " -n 1 -r
                echo
                [[ $REPLY =~ ^[Yy]$ ]] || exit 1
            fi
        fi
    fi
}

backup_existing() {
    if [[ -d "$WG_DIR" ]] || [[ -d "$WG_DASHBOARD_DIR" ]]; then
        BACKUP_DIR="/root/wg-backup-$(date +%Y%m%d-%H%M%S)"
        msg "Backing up existing configuration to $BACKUP_DIR"
        mkdir -p "$BACKUP_DIR"
        [[ -d "$WG_DIR" ]] && cp -r "$WG_DIR" "$BACKUP_DIR/" 2>/dev/null || true
        [[ -d "$WG_DASHBOARD_DIR/db" ]] && cp -r "$WG_DASHBOARD_DIR/db" "$BACKUP_DIR/" 2>/dev/null || true
        success "Backup completed"
    fi
}

install_packages() {
    msg "Installing required packages..."
    
    apt-get update -qq
    
    PACKAGES=(
        wireguard
        wireguard-tools
        python3
        python3-pip
        python3-venv
        git
        curl
        iptables
        net-tools
        qrencode
    )
    
    for pkg in "${PACKAGES[@]}"; do
        apt-get install -y "$pkg" --no-install-recommends &>/dev/null || warn "Failed to install $pkg"
    done
    
    success "Packages installed"
}

setup_sysctl() {
    msg "Configuring kernel parameters..."
    
    cat > /etc/sysctl.d/99-wireguard.conf << EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    
    sysctl --system &>/dev/null
    success "Kernel parameters configured"
}

get_public_ip() {
    for url in "https://ipinfo.io/ip" "https://ifconfig.me" "https://api.ipify.org"; do
        PUBLIC_IP=$(curl -s --max-time 3 "$url" 2>/dev/null | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n1)
        [[ -n "$PUBLIC_IP" ]] && break
    done
    echo "${PUBLIC_IP:-Unable to determine}"
}

get_interface() {
    # Get default network interface
    IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [[ -z "$IFACE" ]]; then
        IFACE=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n1 | xargs)
    fi
    echo "${IFACE:-eth0}"
}

setup_wireguard() {
    msg "Setting up WireGuard..."
    
    # Create directory
    mkdir -p "$WG_DIR"
    chmod 700 "$WG_DIR"
    cd "$WG_DIR"
    
    # Generate keys
    if [[ ! -f server_private.key ]]; then
        wg genkey | tee server_private.key | wg pubkey > server_public.key
        chmod 600 server_*.key
    fi
    
    SERVER_PRIVATE_KEY=$(cat server_private.key)
    SERVER_PUBLIC_KEY=$(cat server_public.key)
    INTERFACE=$(get_interface)
    
    # Create config
    cat > "${WG_INTERFACE}.conf" << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = ${WG_SERVER_IP}/24
ListenPort = $WG_PORT
SaveConfig = false

PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE
EOF
    
    chmod 600 "${WG_INTERFACE}.conf"
    
    # Enable and start
    systemctl enable "wg-quick@${WG_INTERFACE}" &>/dev/null
    systemctl restart "wg-quick@${WG_INTERFACE}"
    
    success "WireGuard configured (Public key: $SERVER_PUBLIC_KEY)"
}

install_dashboard() {
    msg "Installing WGDashboard..."
    
    # Stop services
    systemctl stop wgdashboard &>/dev/null || true
    
    # Remove old installation
    rm -rf "$WG_DASHBOARD_DIR"
    
    # Clone repository
    git clone -q https://github.com/donaldzou/WGDashboard.git "$WG_DASHBOARD_DIR"
    cd "$WG_DASHBOARD_DIR"
    
    # Setup Python environment
    python3 -m venv venv
    source venv/bin/activate
    pip install -q --upgrade pip
    
    # Install dashboard
    cd src
    [[ -f requirements.txt ]] && pip install -q -r requirements.txt
    chmod +x wgd.sh
    ./wgd.sh install &>/dev/null
    
    # Configure dashboard - LOCAL ACCESS ONLY
    cat > wg-dashboard.ini << EOF
[Server]
app_ip = 127.0.0.1
app_port = $DASHBOARD_PORT
auth_req = true
version = v4.0
dashboard_refresh_interval = 60000
dashboard_sort = status
dashboard_theme = dark

[Peers]
peer_global_dns = 1.1.1.1
peer_endpoint_allowed_ip = 0.0.0.0/0
peer_display_mode = grid
remote_endpoint = $(get_public_ip)
peer_mtu = 1420
peer_keepalive = 21
EOF
    
    deactivate
    success "Dashboard installed (local access only)"
}

create_service() {
    msg "Creating systemd service..."
    
    cat > /etc/systemd/system/wgdashboard.service << EOF
[Unit]
Description=WGDashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$WG_DASHBOARD_DIR/src
Environment="PATH=$WG_DASHBOARD_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$WG_DASHBOARD_DIR/venv/bin/python3 $WG_DASHBOARD_DIR/src/dashboard.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable wgdashboard &>/dev/null
    systemctl restart wgdashboard
    
    success "Dashboard service created"
}

setup_firewall() {
    msg "Configuring firewall..."
    
    # Install UFW if not present
    if ! command -v ufw &> /dev/null; then
        apt-get install -y ufw &>/dev/null
    fi
    
    # Configure UFW
    ufw --force disable &>/dev/null
    ufw --force reset &>/dev/null
    
    ufw default deny incoming &>/dev/null
    ufw default allow outgoing &>/dev/null
    
    # Essential ports only
    ufw allow 22/tcp comment "SSH" &>/dev/null
    ufw allow "$WG_PORT/udp" comment "WireGuard" &>/dev/null
    # Dashboard port NOT opened - local access only
    
    ufw --force enable &>/dev/null
    
    success "Firewall configured (WireGuard: $WG_PORT/udp)"
}

create_tools() {
    msg "Creating management tools..."
    
    # SSH tunnel helper
    cat > /usr/local/bin/wg-dashboard << 'EOF'
#!/bin/bash
# Quick SSH tunnel for dashboard access

PORT="${1:-10086}"
SERVER="$2"

if [[ -z "$SERVER" ]]; then
    echo "Usage: wg-dashboard [port] <server>"
    echo "Example: wg-dashboard 10086 192.168.1.100"
    echo ""
    echo "This creates an SSH tunnel to access the dashboard"
    echo "After connecting, browse to: http://localhost:8080"
    exit 1
fi

echo "Creating SSH tunnel to $SERVER..."
echo "Dashboard will be available at: http://localhost:8080"
echo "Press Ctrl+C to close tunnel"
ssh -N -L 8080:localhost:$PORT root@$SERVER
EOF
    
    # Management script
    cat > /usr/local/bin/wg-manage << 'EOF'
#!/bin/bash

case "$1" in
    status)
        echo "=== WireGuard ==="
        systemctl status wg-quick@wg0 --no-pager --lines=0
        echo ""
        echo "=== Dashboard ==="
        systemctl status wgdashboard --no-pager --lines=0
        echo ""
        echo "=== Peers ==="
        wg show
        ;;
    restart)
        systemctl restart wg-quick@wg0
        systemctl restart wgdashboard
        echo "Services restarted"
        ;;
    logs)
        journalctl -u wgdashboard -u wg-quick@wg0 -n 30 --no-pager
        ;;
    backup)
        backup="/root/wg-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
        tar -czf "$backup" /etc/wireguard 2>/dev/null
        echo "Backup saved: $backup"
        ;;
    *)
        echo "Usage: wg-manage {status|restart|logs|backup}"
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/wg-dashboard /usr/local/bin/wg-manage
    success "Management tools created"
}

show_summary() {
    PUBLIC_IP=$(get_public_ip)
    
    echo ""
    echo "====================================="
    echo " Installation Complete!"
    echo "====================================="
    echo ""
    echo "WireGuard VPN:"
    echo "  Port: $WG_PORT/udp"
    echo "  Subnet: $WG_SUBNET"
    echo "  Config: $WG_DIR/${WG_INTERFACE}.conf"
    [[ "$PUBLIC_IP" != "Unable to determine" ]] && echo "  Endpoint: $PUBLIC_IP:$WG_PORT"
    echo ""
    echo "Dashboard Access (LOCAL ONLY):"
    echo "  URL: http://localhost:$DASHBOARD_PORT"
    echo "  User: admin"
    echo "  Pass: admin (change immediately!)"
    echo ""
    echo "Remote Dashboard Access:"
    echo "  Use SSH tunnel: wg-dashboard $DASHBOARD_PORT <server-ip>"
    echo "  Then browse to: http://localhost:8080"
    echo ""
    echo "Management Commands:"
    echo "  wg-manage status  - Check services"
    echo "  wg-manage restart - Restart services"
    echo "  wg-manage logs    - View logs"
    echo "  wg-manage backup  - Backup config"
    echo ""
    echo "Next Steps:"
    echo "  1. SSH tunnel to access dashboard"
    echo "  2. Change admin password"
    echo "  3. Add VPN clients"
    echo ""
    success "Setup complete! Dashboard is secure (local access only)"
}

cleanup_on_error() {
    error "Installation failed! Check $LOG_FILE for details"
    [[ -n "${BACKUP_DIR:-}" ]] && msg "Restore from: $BACKUP_DIR"
    exit 1
}

main() {
    trap cleanup_on_error ERR
    
    header
    check_root
    check_os
    check_virt
    backup_existing
    install_packages
    setup_sysctl
    setup_wireguard
    install_dashboard
    create_service
    setup_firewall
    create_tools
    show_summary
}

# Run installation
main "$@"
