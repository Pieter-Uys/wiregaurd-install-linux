# WireGuard + WGDashboard Auto-Installer

A comprehensive, one-click installation script for setting up WireGuard VPN server with WGDashboard web interface on Debian/Ubuntu systems. Features universal compatibility for both minimal and full Debian installations with intelligent sudo handling and automatic IP detection.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu-blue.svg)](https://www.debian.org/)

## 🚀 Features

- **One-Click Installation**: Complete setup with a single command
- **Universal Compatibility**: Works on both minimal Debian (no sudo) and full installations
- **Automatic IP Detection**: Detects and displays server public IP for client configuration
- **Latest Versions**: Always installs the most recent stable versions
- **Official Documentation Compliance**: Follows best practices from [WireGuard](https://www.wireguard.com/install/) and [WGDashboard](https://wgdashboard.dev/) official docs
- **Comprehensive Setup**: Includes firewall configuration, systemd services, and security hardening
- **Web Management Interface**: Easy-to-use dashboard for managing VPN clients
- **Automatic Key Generation**: Generates server keys and initial configuration
- **IP Forwarding**: Properly configured for VPN traffic routing
- **Error Handling**: Robust error checking and helpful status messages
- **Sudo Handling**: Intelligent sudo detection and handling for root/non-root scenarios

## 📋 Requirements

### Supported Operating Systems
- **Ubuntu**: 20.04 LTS, 22.04 LTS, 24.04 LTS, 24.10
- **Debian**: 11.x, 12.x

### System Requirements
- **Root Access**: Script must be run with sudo privileges
- **Internet Connection**: Required for downloading packages and repositories
- **Minimum RAM**: 512MB (1GB+ recommended)
- **Disk Space**: At least 1GB free space
- **Architecture**: x86_64 (amd64)

### Network Requirements
- **Port 51820/UDP**: WireGuard VPN traffic
- **Port 10086/TCP**: WGDashboard web interface
- **Port 22/TCP**: SSH access (recommended to keep open)

## 🛠️ Installation

### Quick Install (Recommended)

```bash
# Download and run the installer
wget -O wg_install.sh "https://raw.githubusercontent.com/[your-username]/wireguard-installer/main/wg_install.sh"
chmod +x wg_install.sh
sudo bash wg_install.sh
```

### Manual Installation

```bash
# Download the script
wget https://raw.githubusercontent.com/[your-username]/wireguard-installer/main/wg_install.sh

# Make it executable
chmod +x wg_install.sh

# Run with sudo
sudo bash wg_install.sh
```

### Git Clone Method

```bash
# Clone the repository
git clone https://github.com/[your-username]/wireguard-installer.git
cd wireguard-installer

# Run the installer
sudo bash wg_install.sh
```

## 📦 What Gets Installed

### Core Components
- **WireGuard**: Latest stable version from official repositories
- **WGDashboard**: Latest version from official GitHub repository
- **Dependencies**: Python 3, Git, Net-tools, iptables, curl

### System Configuration
- **IP Forwarding**: Enabled for VPN traffic routing
- **Firewall Rules**: UFW configured with appropriate port access
- **Systemd Services**: Auto-start services for WGDashboard
- **Directory Structure**: Proper permissions for `/etc/wireguard`

### Generated Files
- `/etc/wireguard/wg0.conf` - Main WireGuard configuration
- `/etc/wireguard/server_private.key` - Server private key
- `/etc/wireguard/server_public.key` - Server public key
- `/opt/WGDashboard/` - Dashboard installation directory

## 🌐 Post-Installation

### Access the Dashboard

1. **Open your web browser** and navigate to:
   ```
   http://your-server-ip:10086
   ```
   Or locally:
   ```
   http://localhost:10086
   ```

2. **Login with default credentials**:
   - Username: `admin`
   - Password: `admin`

3. **⚠️ IMMEDIATELY change the default password** for security!

**Note**: The script will display your server's public IP during installation for client configuration purposes.

### Start WireGuard VPN

```bash
# Start the VPN service
sudo systemctl start wg-quick@wg0

# Enable auto-start on boot
sudo systemctl enable wg-quick@wg0

# Check VPN status
sudo wg show
```

### Add Your First Client

1. Access the WGDashboard web interface
2. Click "Add Peer" or "+" button
3. Configure the peer settings (name, allowed IPs, etc.)
4. Download the configuration file or scan the QR code
5. Import the configuration into your WireGuard client

## 🔧 Management Commands

### WireGuard Commands
```bash
# Start/Stop WireGuard
sudo systemctl start wg-quick@wg0
sudo systemctl stop wg-quick@wg0

# View connection status
sudo wg show

# View detailed configuration
sudo wg showconf wg0
```

### WGDashboard Commands
```bash
# Manual control (uses wrapper script for sudo compatibility)
cd /opt/WGDashboard/src
./wgd_wrapper.sh start
./wgd_wrapper.sh stop
./wgd_wrapper.sh restart

# Systemd service control
sudo systemctl start wgdashboard
sudo systemctl stop wgdashboard
sudo systemctl status wgdashboard

# View logs
sudo journalctl -u wgdashboard -f
```

### Firewall Management
```bash
# Check firewall status
sudo ufw status

# Allow additional ports if needed
sudo ufw allow [port]/[protocol]

# Reset firewall (use with caution)
sudo ufw --force reset
```

## 🔒 Security Considerations

### Immediate Security Steps
1. **Change default dashboard password**
2. **Enable SSH key authentication** (disable password auth)
3. **Update your system regularly**
4. **Monitor access logs**

### Recommended Security Enhancements
- Set up **fail2ban** for intrusion prevention
- Configure **automatic security updates**
- Use **non-standard SSH port**
- Implement **two-factor authentication** where possible
- Regular **backup of configurations**

### Firewall Ports
The script automatically configures these ports:
- `22/TCP` - SSH access
- `51820/UDP` - WireGuard VPN
- `10086/TCP` - WGDashboard web interface

## 🐛 Troubleshooting

### Common Issues

**Dashboard not accessible:**
```bash
# Check if service is running
sudo systemctl status wgdashboard

# Check firewall
sudo ufw status

# Restart dashboard
sudo systemctl restart wgdashboard
```

**WireGuard not starting:**
```bash
# Check configuration syntax
sudo wg-quick up wg0

# View system logs
sudo journalctl -u wg-quick@wg0
```

**No internet through VPN:**
```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward

# Should return 1, if not:
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Log Locations
- **WGDashboard logs**: `sudo journalctl -u wgdashboard`
- **WireGuard logs**: `sudo journalctl -u wg-quick@wg0`
- **System logs**: `/var/log/syslog`

## 📖 Documentation

### Official Documentation
- [WireGuard Official Site](https://www.wireguard.com/)
- [WGDashboard Documentation](https://docs.wgdashboard.dev/)
- [WireGuard Quick Start](https://www.wireguard.com/quickstart/)

### Client Setup Guides
- [WireGuard Windows Client](https://www.wireguard.com/install/)
- [WireGuard Android Client](https://play.google.com/store/apps/details?id=com.wireguard.android)
- [WireGuard iOS Client](https://apps.apple.com/us/app/wireguard/id1441195209)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### How to Contribute
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Bug Reports
Please use the [GitHub Issues](https://github.com/[your-username]/wireguard-installer/issues) page to report bugs.

## ⚠️ Disclaimer

This script is provided as-is for educational and convenience purposes. Always review scripts before running them with sudo privileges. The authors are not responsible for any damage or security issues that may arise from using this script.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [WireGuard](https://www.wireguard.com/) team for creating an amazing VPN solution
- [Donald Zou](https://github.com/donaldzou) for developing WGDashboard
- The open-source community for continuous improvements and feedback

## 📊 Statistics

- **Installation Time**: ~2-5 minutes (depending on system)
- **Script Size**: ~9.7KB
- **Tested Systems**: Ubuntu 20.04+, Debian 11+
- **Dependencies**: Automatically handled

---

**⭐ If this script helped you, please consider giving it a star!**

For support, please [open an issue](https://github.com/[your-username]/wireguard-installer/issues) or check the [discussions](https://github.com/[your-username]/wireguard-installer/discussions) page.
