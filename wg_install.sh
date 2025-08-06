#!/bin/bash

# WireGuard + WGDashboard Auto-Installer Script
# Secure by default with option for network access
# Compatible with Debian/Ubuntu systems (LXC containers and bare metal)
# Version: 3.0
# Run with: bash <(curl -s https://raw.githubusercontent.com/yourusername/wg-installer/main/install.sh)

set -uo pipefail  # Removed 'e' to handle errors manually

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
WG_DIR="/etc/wireguard"
WG_DASHBOARD_DIR="/opt/WGDashboard"
WG_PORT="${WG_PORT:-51820}"
DASHBOARD_PORT="${DASHBOARD_PORT:-10086}"
WG_INTERFACE="wg0"
WG_SUBNET="10.0.0.0/24"
WG_SERVER_IP="10.0.0.1"

# Dashboard access mode (will be set by user choice)
DASHBOARD_IP="127.0.0.1"  # Default to local only

# Script info
SCRIPT_VERSION="3.0"
LOG_FILE="/var/log/wg-installer.log"

# Environment detection
IS_CONTAINER=false
CONTAINER_TYPE="none"

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
        VIRT=$(systemd-detect-virt 2>/dev/null || echo "none")
        if [[ "$VIRT" != "none" ]]; then
            msg "Virtualization: $VIRT"
            
            case "$VIRT" in
                lxc|openvz)
                    IS_CONTAINER=true
                    CONTAINER_TYPE="$VIRT"
                    warn "Container detected - some features require host configuration"
                    msg "Checking WireGuard kernel module on host..."
                    
                    # Check if WireGuard module is available
                    if ! lsmod 2>/dev/null | grep -q wireguard && ! modinfo wireguard &>/dev/null 2>&1; then
                        echo ""
                        warn "WireGuard kernel module not detected!"
                        echo ""
                        echo "For LXC/Proxmox containers, run this on the HOST:"
                        echo "  apt install wireguard-dkms"
                        echo "  modprobe wireguard"
                        echo "  echo 'wireguard' >> /etc/modules-load.d/modules.conf"
                        echo ""
                        read -p "Has WireGuard been loaded on the host? (y/N): " -n 1 -r
                        echo
                        [[ $REPLY =~ ^[Yy]$ ]] || exit 1
                    else
                        success "WireGuard kernel module detected"
                    fi
                    ;;
                kvm|qemu|vmware|virtualbox|xen)
                    msg "Virtual machine detected - full functionality available"
                    ;;
            esac
        else
            msg "Running on bare metal"
        fi
    fi
}

ask_dashboard_access() {
    echo ""
    echo -e "${CYAN}Dashboard Access Configuration${NC}"
    echo "================================="
    echo ""
    echo "How do you want to access the WGDashboard?"
    echo ""
    echo "1) Local only (Most Secure - Requires SSH tunnel)"
    echo "   - Dashboard only accessible from localhost"
    echo "   - Remote access via SSH tunnel"
    echo "   - Recommended for production"
    echo ""
    echo "2) Local Network (Less Secure - Direct access from LAN)"
    echo "   - Dashboard accessible from your local network"
    echo "   - Direct access from any device on your network"
    echo "   - Convenient for home/lab use"
    echo ""
    
    while true; do
        read -p "Select option [1-2] (default: 1): " choice
        choice=${choice:-1}
        
        case $choice in
            1)
                DASHBOARD_IP="127.0.0.1"
                success "Dashboard will be LOCAL ONLY (secure)"
                msg "You'll need SSH tunnel for remote access"
                break
                ;;
            2)
                DASHBOARD_IP="0.0.0.0"
                warn "Dashboard will be accessible from your network"
                msg "Make sure to change the default password immediately!"
                break
                ;;
            *)
                error "Invalid option. Please select 1 or 2"
                ;;
        esac
    done
    echo ""
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
    
    # Update package lists
    if ! apt-get update -qq 2>/dev/null; then
        warn "Package update had warnings, continuing..."
    fi
    
    # Essential packages
    PACKAGES=(
        wireguard-tools  # Changed from 'wireguard' to 'wireguard-tools' for containers
        python3
        python3-pip
        python3-venv
        git
        curl
        iptables
        net-tools
        qrencode
        openresolv
    )
    
    # Add wireguard package only for non-containers
    if [[ "$IS_CONTAINER" == "false" ]]; then
        PACKAGES+=("wireguard")
    fi
    
    # Install packages
    for pkg in "${PACKAGES[@]}"; do
        if apt-get install -y "$pkg" --no-install-recommends &>/dev/null 2>&1; then
            msg "Installed: $pkg"
        else
            warn "Failed to install $pkg (may not be needed)"
        fi
    done
    
    success "Packages installed"
}

setup_sysctl() {
    msg "Configuring kernel parameters..."
    
    # Create sysctl config file
    cat > /etc/sysctl.d/99-wireguard.conf << EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.proxy_arp = 1
EOF
    
    # Try to apply sysctl settings
    if [[ "$IS_CONTAINER" == "true" ]]; then
        warn "Container detected - kernel parameters must be set on host"
        msg "Checking current IP forwarding status..."
        
        # Check if IP forwarding is enabled
        if [[ -f /proc/sys/net/ipv4/ip_forward ]]; then
            ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
            if [[ "$ip_forward" == "1" ]]; then
                success "IP forwarding is enabled on host"
            else
                warn "IP forwarding appears disabled"
                echo ""
                echo "Add this to the HOST's /etc/sysctl.conf:"
                echo "  net.ipv4.ip_forward = 1"
                echo "  net.ipv6.conf.all.forwarding = 1"
                echo ""
                echo "Then run on HOST: sysctl -p"
                echo ""
                read -p "Continue anyway? (y/N): " -n 1 -r
                echo
                [[ $REPLY =~ ^[Yy]$ ]] || exit 1
            fi
        fi
    else
        # Bare metal or VM - apply settings normally
        if sysctl --system &>/dev/null 2>&1; then
            success "Kernel parameters configured"
        else
            warn "Some kernel parameters could not be set"
        fi
    fi
}

get_public_ip() {
    local ip=""
    for url in "https://ipinfo.io/ip" "https://ifconfig.me" "https://api.ipify.org"; do
        ip=$(curl -s --max-time 3 "$url" 2>/dev/null | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n1)
        [[ -n "$ip" ]] && break
    done
    echo "${ip:-Unable to determine}"
}

get_local_ip() {
    # Get the local IP address
    local ip=""
    ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    if [[ -z "$ip" ]]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    echo "${ip:-Unable to determine}"
}

get_interface() {
    local iface=""
    
    # Method 1: Get default route interface
    iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -n1)
    
    # Method 2: Get first non-lo interface
    if [[ -z "$iface" ]]; then
        iface=$(ip link show 2>/dev/null | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n1 | xargs)
    fi
    
    # Method 3: Fallback for containers
    if [[ -z "$iface" ]]; then
        iface=$(ip link show 2>/dev/null | grep -E "^[0-9]:" | grep -v "lo:" | head -n1 | cut -d: -f2 | xargs)
    fi
    
    # Final fallback
    echo "${iface:-eth0}"
}

setup_wireguard() {
    msg "Setting up WireGuard..."
    
    # Create directory
    mkdir -p "$WG_DIR"
    chmod 700 "$WG_DIR"
    cd "$WG_DIR"
    
    # Check if we can use wg command
    if ! command -v wg &> /dev/null; then
        error "WireGuard tools not installed properly"
        exit 1
    fi
    
    # Generate keys if they don't exist
    if [[ ! -f server_private.key ]]; then
        msg "Generating server keys..."
        wg genkey | tee server_private.key | wg pubkey > server_public.key
        chmod 600 server_*.key
    fi
    
    SERVER_PRIVATE_KEY=$(cat server_private.key)
    SERVER_PUBLIC_KEY=$(cat server_public.key)
    INTERFACE=$(get_interface)
    
    msg "Using network interface: $INTERFACE"
    
    # Create config with container-friendly iptables rules
    cat > "${WG_INTERFACE}.conf" << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = ${WG_SERVER_IP}/24
ListenPort = $WG_PORT
SaveConfig = false

# PostUp/PostDown rules that work in containers
PostUp = iptables -I FORWARD -i %i -j ACCEPT
PostUp = iptables -I FORWARD -o %i -j ACCEPT
PostUp = iptables -t nat -I POSTROUTING -o $INTERFACE -j MASQUERADE
PostUp = ip6tables -I FORWARD -i %i -j ACCEPT 2>/dev/null || true
PostUp = ip6tables -I FORWARD -o %i -j ACCEPT 2>/dev/null || true
PostUp = ip6tables -t nat -I POSTROUTING -o $INTERFACE -j MASQUERADE 2>/dev/null || true

PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE
PostDown = ip6tables -D FORWARD -i %i -j ACCEPT 2>/dev/null || true
PostDown = ip6tables -D FORWARD -o %i -j ACCEPT 2>/dev/null || true
PostDown = ip6tables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE 2>/dev/null || true
EOF
    
    chmod 600 "${WG_INTERFACE}.conf"
    
    # Enable and start WireGuard
    msg "Starting WireGuard service..."
    
    # For containers, we might need to use wg-quick directly
    if [[ "$IS_CONTAINER" == "true" ]]; then
        # Stop any existing interface
        wg-quick down "${WG_INTERFACE}" 2>/dev/null || true
        
        # Start the interface
        if wg-quick up "${WG_INTERFACE}" 2>/dev/null; then
            success "WireGuard started successfully"
        else
            warn "WireGuard start had warnings - checking status..."
            if wg show "${WG_INTERFACE}" &>/dev/null; then
                success "WireGuard is running despite warnings"
            else
                error "Failed to start WireGuard"
                error "Check kernel module on host and network configuration"
                exit 1
            fi
        fi
    fi
    
    # Setup systemd service
    systemctl enable "wg-quick@${WG_INTERFACE}" 2>/dev/null || true
    systemctl restart "wg-quick@${WG_INTERFACE}" 2>/dev/null || true
    
    success "WireGuard configured"
    msg "Server public key: $SERVER_PUBLIC_KEY"
}

install_dashboard() {
    msg "Installing WGDashboard..."
    
    # Stop services if they exist
    systemctl stop wgdashboard 2>/dev/null || true
    
    # Remove old installation
    rm -rf "$WG_DASHBOARD_DIR"
    
    # Clone repository
    if ! git clone -q https://github.com/donaldzou/WGDashboard.git "$WG_DASHBOARD_DIR" 2>/dev/null; then
        error "Failed to clone WGDashboard repository"
        exit 1
    fi
    
    cd "$WG_DASHBOARD_DIR"
    
    # Setup Python environment
    msg "Setting up Python virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip quietly
    pip install -q --upgrade pip 2>/dev/null || warn "pip upgrade had warnings"
    
    # Install dashboard
    cd src
    
    # Install requirements if file exists
    if [[ -f requirements.txt ]]; then
        pip install -q -r requirements.txt 2>/dev/null || warn "Some Python packages had warnings"
    fi
    
    # Make scripts executable
    chmod +x wgd.sh
    
    # Install dashboard
    ./wgd.sh install >/dev/null 2>&1 || warn "Dashboard install had warnings"
    
    # Configure dashboard based on user choice
    cat > wg-dashboard.ini << EOF
[Server]
app_ip = $DASHBOARD_IP
app_port = $DASHBOARD_PORT
auth_req = true
version = v4.0
dashboard_refresh_interval = 60000
dashboard_sort = status
dashboard_theme = dark
wg_conf_path = $WG_DIR

[Peers]
peer_global_dns = 1.1.1.1
peer_endpoint_allowed_ip = 0.0.0.0/0
peer_display_mode = grid
remote_endpoint = $(get_public_ip)
peer_mtu = 1420
peer_keepalive = 21
EOF
    
    deactivate
    
    if [[ "$DASHBOARD_IP" == "127.0.0.1" ]]; then
        success "Dashboard installed (local access only)"
    else
        success "Dashboard installed (network accessible)"
    fi
}

create_service() {
    msg "Creating systemd service..."
    
    # Create a more robust service file
    cat > /etc/systemd/system/wgdashboard.service << EOF
[Unit]
Description=WGDashboard
After=network.target
Wants=wg-quick@${WG_INTERFACE}.service

[Service]
Type=simple
User=root
WorkingDirectory=$WG_DASHBOARD_DIR/src
Environment="PATH=$WG_DASHBOARD_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStartPre=/bin/sleep 5
ExecStart=$WG_DASHBOARD_DIR/venv/bin/python3 $WG_DASHBOARD_DIR/src/dashboard.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable wgdashboard 2>/dev/null || warn "Service enable had warnings"
    systemctl restart wgdashboard
    
    # Wait a moment for service to start
    sleep 3
    
    # Check if service started
    if systemctl is-active --quiet wgdashboard; then
        success "Dashboard service created and running"
    else
        warn "Dashboard service may not be running - check with: systemctl status wgdashboard"
    fi
}

setup_firewall() {
    msg "Configuring firewall..."
    
    # Check if we're in a container that might not support UFW
    if [[ "$IS_CONTAINER" == "true" ]]; then
        warn "Container detected - firewall should be configured on host"
        msg "Ensure these ports are open on the host:"
        echo "  - $WG_PORT/udp (WireGuard)"
        echo "  - 22/tcp (SSH)"
        if [[ "$DASHBOARD_IP" == "0.0.0.0" ]]; then
            echo "  - $DASHBOARD_PORT/tcp (Dashboard - if you want external access)"
        fi
        echo ""
        
        # Try basic iptables rules for container
        iptables -I INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
        if [[ "$DASHBOARD_IP" == "0.0.0.0" ]]; then
            iptables -I INPUT -p tcp --dport "$DASHBOARD_PORT" -j ACCEPT 2>/dev/null || true
        fi
    else
        # Install UFW if not present
        if ! command -v ufw &> /dev/null; then
            apt-get install -y ufw &>/dev/null
        fi
        
        # Configure UFW
        ufw --force disable &>/dev/null
        ufw --force reset &>/dev/null
        
        ufw default deny incoming &>/dev/null
        ufw default allow outgoing &>/dev/null
        
        # Essential ports
        ufw allow 22/tcp comment "SSH" &>/dev/null
        ufw allow "$WG_PORT/udp" comment "WireGuard" &>/dev/null
        
        # Dashboard port if network access is enabled
        if [[ "$DASHBOARD_IP" == "0.0.0.0" ]]; then
            ufw allow "$DASHBOARD_PORT/tcp" comment "WGDashboard" &>/dev/null
            warn "Dashboard port $DASHBOARD_PORT/tcp opened in firewall"
        fi
        
        ufw --force enable &>/dev/null
        
        success "Firewall configured"
    fi
}

create_tools() {
    msg "Creating management tools..."
    
    # SSH tunnel helper
    cat > /usr/local/bin/wg-tunnel << 'EOF'
#!/bin/bash
# Quick SSH tunnel for dashboard access

PORT="${1:-10086}"
SERVER="$2"

if [[ -z "$SERVER" ]]; then
    echo "Usage: wg-tunnel [port] <server>"
    echo "Example: wg-tunnel 10086 192.168.1.100"
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

WG_INTERFACE="wg0"
WG_DASHBOARD_DIR="/opt/WGDashboard"
DASHBOARD_PORT="10086"

case "$1" in
    status)
        echo "=== WireGuard ==="
        if systemctl is-active --quiet "wg-quick@${WG_INTERFACE}"; then
            echo "Status: Active"
            wg show
        else
            echo "Status: Inactive"
            echo "Try: wg-quick up ${WG_INTERFACE}"
        fi
        echo ""
        echo "=== Dashboard ==="
        systemctl status wgdashboard --no-pager --lines=3
        
        # Show dashboard access info
        echo ""
        echo "=== Dashboard Access ==="
        if grep -q "app_ip = 127.0.0.1" "$WG_DASHBOARD_DIR/src/wg-dashboard.ini" 2>/dev/null; then
            echo "Mode: Local only (SSH tunnel required)"
            echo "Use: wg-tunnel $DASHBOARD_PORT <server-ip>"
        else
            echo "Mode: Network accessible"
            local_ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
            [[ -n "$local_ip" ]] && echo "URL: http://$local_ip:$DASHBOARD_PORT"
        fi
        ;;
    restart)
        systemctl restart "wg-quick@${WG_INTERFACE}" 2>/dev/null || wg-quick down "${WG_INTERFACE}" && wg-quick up "${WG_INTERFACE}"
        systemctl restart wgdashboard
        echo "Services restarted"
        ;;
    logs)
        journalctl -u wgdashboard -u "wg-quick@${WG_INTERFACE}" -n 30 --no-pager
        ;;
    backup)
        backup="/root/wg-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
        tar -czf "$backup" /etc/wireguard "$WG_DASHBOARD_DIR/src/wg-dashboard.ini" 2>/dev/null
        echo "Backup saved: $backup"
        ;;
    *)
        echo "Usage: wg-manage {status|restart|logs|backup}"
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/wg-tunnel /usr/local/bin/wg-manage
    success "Management tools created"
}

show_summary() {
    PUBLIC_IP=$(get_public_ip)
    LOCAL_IP=$(get_local_ip)
    
    echo ""
    echo "====================================="
    success "Installation Complete!"
    echo "====================================="
    echo ""
    
    if [[ "$IS_CONTAINER" == "true" ]]; then
        warn "Running in container ($CONTAINER_TYPE)"
        echo "Some features depend on host configuration"
        echo ""
    fi
    
    echo "WireGuard VPN:"
    echo "  Port: $WG_PORT/udp"
    echo "  Subnet: $WG_SUBNET"
    echo "  Config: $WG_DIR/${WG_INTERFACE}.conf"
    [[ "$PUBLIC_IP" != "Unable to determine" ]] && echo "  Endpoint: $PUBLIC_IP:$WG_PORT"
    echo ""
    
    echo "Dashboard Access:"
    if [[ "$DASHBOARD_IP" == "127.0.0.1" ]]; then
        echo "  Mode: LOCAL ONLY (Secure)"
        echo "  Local URL: http://localhost:$DASHBOARD_PORT"
        echo ""
        echo "  Remote Access via SSH Tunnel:"
        echo "    From your computer run:"
        echo "    ssh -L 8080:localhost:$DASHBOARD_PORT root@$LOCAL_IP"
        echo "    Then browse to: http://localhost:8080"
    else
        echo "  Mode: NETWORK ACCESSIBLE"
        echo "  Local URL: http://localhost:$DASHBOARD_PORT"
        [[ "$LOCAL_IP" != "Unable to determine" ]] && echo "  Network URL: http://$LOCAL_IP:$DASHBOARD_PORT"
        [[ "$PUBLIC_IP" != "Unable to determine" ]] && echo "  External URL: http://$PUBLIC_IP:$DASHBOARD_PORT (if port forwarded)"
        echo ""
        warn "Dashboard is accessible from your network!"
        warn "CHANGE THE DEFAULT PASSWORD IMMEDIATELY!"
    fi
    echo ""
    echo "  Default Login:"
    echo "    User: admin"
    echo "    Pass: admin"
    echo ""
    
    echo "Management Commands:"
    echo "  wg-manage status  - Check services"
    echo "  wg-manage restart - Restart services"
    echo "  wg-manage logs    - View logs"
    echo "  wg-manage backup  - Backup config"
    if [[ "$DASHBOARD_IP" == "127.0.0.1" ]]; then
        echo "  wg-tunnel $DASHBOARD_PORT <server-ip> - Create SSH tunnel"
    fi
    echo ""
    
    if [[ "$IS_CONTAINER" == "true" ]]; then
        echo "Container Notes:"
        echo "  - Ensure WireGuard module is loaded on host"
        echo "  - IP forwarding must be enabled on host"
        echo "  - Firewall rules should be set on host"
        echo ""
    fi
    
    echo "Next Steps:"
    if [[ "$DASHBOARD_IP" == "127.0.0.1" ]]; then
        echo "  1. SSH tunnel to access dashboard"
    else
        echo "  1. Access dashboard at http://$LOCAL_IP:$DASHBOARD_PORT"
    fi
    echo "  2. Change admin password IMMEDIATELY"
    echo "  3. Add VPN clients"
    echo ""
    
    if [[ "$DASHBOARD_IP" == "127.0.0.1" ]]; then
        success "Setup complete! Dashboard is secure (local access only)"
    else
        success "Setup complete! Dashboard is network accessible"
        warn "Remember to change the default password!"
    fi
    
    # Final service check
    echo ""
    msg "Checking services..."
    if wg show "${WG_INTERFACE}" &>/dev/null; then
        success "WireGuard is running"
    else
        warn "WireGuard may need manual start: wg-quick up ${WG_INTERFACE}"
    fi
    
    if systemctl is-active --quiet wgdashboard; then
        success "Dashboard is running"
    else
        warn "Dashboard may need manual start: systemctl start wgdashboard"
    fi
}

cleanup_on_error() {
    error "Installation failed! Check $LOG_FILE for details"
    [[ -n "${BACKUP_DIR:-}" ]] && msg "Restore from: $BACKUP_DIR"
    exit 1
}

main() {
    # Remove strict error handling for better container compatibility
    # trap cleanup_on_error ERR
    
    header
    check_root
    check_os
    check_virt
    ask_dashboard_access  # Ask user how they want to access dashboard
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
