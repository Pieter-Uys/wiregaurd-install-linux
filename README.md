# WireGuard + WGDashboard Secure Auto-Installer

A security-focused, one-click installation script for WireGuard VPN with WGDashboard on Debian/Ubuntu systems. Following best practices by default - dashboard is local-only, never exposed to the internet.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu-blue.svg)](https://www.debian.org/)
[![Security](https://img.shields.io/badge/Security-First-red.svg)](https://github.com/yourusername/wireguard-installer)

## 🔒 Security First Design

This installer follows security best practices by default:
- **Dashboard is LOCAL ACCESS ONLY** - Never exposed to the internet
- **SSH tunneling** for secure remote dashboard access
- **Minimal attack surface** - Only WireGuard port is public
- **No dangerous options** - Can't accidentally expose the dashboard
- **Secure by default** - No configuration needed for security

## 🚀 Features

- **One-Command Installation**: Complete secure setup with a single command
- **Security by Default**: Dashboard bound to localhost only (127.0.0.1)
- **SSH Tunnel Helper**: Built-in tool for secure remote dashboard access
- **Automatic Configuration**: Detects network settings automatically
- **Management Tools**: Simple commands for status, logs, and backups
- **Latest Versions**: Always installs the most recent stable versions
- **Minimal Interaction**: Clean, opinionated installation like Proxmox scripts
- **Comprehensive Setup**: Firewall, systemd services, and kernel parameters
- **Backup System**: Automatic backup of existing configurations

## 📋 Requirements

### Supported Operating Systems
- **Ubuntu**: 20.04 LTS, 22.04 LTS, 24.04 LTS
- **Debian**: 11.x, 12.x

### System Requirements
- **Root Access**: Script must be run as root or with sudo
- **Internet Connection**: Required for downloading packages
- **RAM**: 512MB minimum (1GB+ recommended)
- **Disk Space**: At least 1GB free
- **Architecture**: x86_64 (amd64) or arm64

### Network Requirements
- **Port 51820/UDP**: WireGuard VPN traffic (PUBLIC)
- **Port 22/TCP**: SSH access (for tunnel and management)
- ~~Port 10086/TCP~~ Dashboard port is LOCAL ONLY - not exposed

## 🛠️ Installation

### Quick Install (Recommended)

```bash
# One-line secure installation
bash <(curl -s https://raw.githubusercontent.com/yourusername/wireguard-installer/main/install.sh)
```

### Download and Review

```bash
# Download the script
wget https://raw.githubusercontent.com/yourusername/wireguard-installer/main/install.sh

# Review the script (always recommended!)
less install.sh

# Run the installer
sudo bash install.sh
```

### Custom Ports

```bash
# Use custom WireGuard port
export WG_PORT=51821
sudo bash install.sh
```

## 🔐 Architecture

```
Internet ──► WireGuard:51820 ✓ (VPN Protocol - Encrypted)
         ──X Dashboard:10086 ✗ (Blocked - Local Only)

Admin ──SSH──► Server ──► Dashboard ✓ (Secure Access)
```

## 📦 What Gets Installed

### Core Components
- **WireGuard**: Kernel module and tools from official repositories
- **WGDashboard**: Latest version with Python virtual environment
- **Security Tools**: UFW firewall, configured for minimal exposure
- **Management Scripts**: Helper tools for easy administration

### Configuration Files
- `/etc/wireguard/wg0.conf` - WireGuard configuration
- `/etc/wireguard/server_*.key` - Server keys (auto-generated)
- `/opt/WGDashboard/` - Dashboard installation (local-only)
- `/usr/local/bin/wg-manage` - Management utility
- `/usr/local/bin/wg-dashboard` - SSH tunnel helper

## 🌐 Post-Installation Access

### Accessing the Dashboard

Since the dashboard is secured (local-only), you have two options:

#### Option 1: SSH Tunnel (Recommended for Remote Access)

```bash
# From your local computer:
ssh -L 8080:localhost:10086 root@your-server-ip

# Then browse to:
http://localhost:8080
```

Or use the included helper:
```bash
# From your local computer:
wg-dashboard 10086 your-server-ip

# Browser automatically opens to:
http://localhost:8080
```

#### Option 2: Local Console Access

If you have direct console access to the server:
```bash
# On the server itself:
curl http://localhost:10086
# Or use a local browser if GUI is available
```

### Default Credentials

- **Username**: `admin`
- **Password**: `admin`
- **⚠️ CHANGE IMMEDIATELY** after first login!

## 🔧 Management Commands

### Quick Management Tool

```bash
# Check status of all services
wg-manage status

# Restart WireGuard and Dashboard
wg-manage restart

# View recent logs
wg-manage logs

# Create configuration backup
wg-manage backup
```

### Manual Service Control

```bash
# WireGuard service
sudo systemctl status wg-quick@wg0
sudo systemctl restart wg-quick@wg0

# Dashboard service
sudo systemctl status wgdashboard
sudo systemctl restart wgdashboard

# View active VPN connections
sudo wg show
```

### SSH Tunnel for Dashboard

```bash
# Create SSH tunnel (from your computer)
wg-dashboard 10086 <server-ip>

# Custom local port
ssh -L 9090:localhost:10086 root@server-ip
```

## 🛡️ Security Features

### Default Security Measures

✅ **Dashboard Local Only**: Bound to 127.0.0.1, inaccessible from internet  
✅ **Minimal Firewall**: Only WireGuard and SSH ports open  
✅ **No Public Web Interface**: Dashboard requires SSH tunnel  
✅ **Automatic Backups**: Existing configs backed up before changes  
✅ **Secure Defaults**: No options to weaken security  

### Why Local-Only Dashboard?

1. **No Web Vulnerabilities**: Dashboard can't be attacked from internet
2. **No Brute Force Risk**: Login page not exposed to public
3. **No Zero-Days**: Web interface bugs can't be exploited remotely
4. **SSH Protection**: Access requires SSH keys/credentials first
5. **Defense in Depth**: Multiple layers of security

### Additional Security Steps

After installation, consider:

1. **SSH Key Authentication**:
   ```bash
   ssh-copy-id root@your-server
   # Then disable password auth in /etc/ssh/sshd_config
   ```

2. **Change Default Password**:
   - First thing after installation!
   - Use a strong, unique password

3. **Regular Updates**:
   ```bash
   apt update && apt upgrade
   ```

4. **Monitor Logs**:
   ```bash
   wg-manage logs
   journalctl -u sshd
   ```

## 🐛 Troubleshooting

### Dashboard Not Accessible

```bash
# Check if service is running
sudo systemctl status wgdashboard

# Check if bound to localhost
ss -tuln | grep 10086
# Should show 127.0.0.1:10086 NOT 0.0.0.0:10086

# Restart service
sudo systemctl restart wgdashboard
```

### SSH Tunnel Not Working

```bash
# Test SSH connection first
ssh root@your-server-ip

# Check if dashboard is running locally
ssh root@your-server-ip "curl -I http://localhost:10086"

# Verbose SSH tunnel for debugging
ssh -v -N -L 8080:localhost:10086 root@your-server-ip
```

### WireGuard Issues

```bash
# Check WireGuard status
sudo wg show

# Check if module is loaded
lsmod | grep wireguard

# View configuration
sudo cat /etc/wireguard/wg0.conf

# Check logs
sudo journalctl -u wg-quick@wg0
```

### Client Can't Connect

1. **Check server firewall**:
   ```bash
   sudo ufw status
   # Should show 51820/udp ALLOW
   ```

2. **Verify IP forwarding**:
   ```bash
   sysctl net.ipv4.ip_forward
   # Should return 1
   ```

3. **Check client configuration**:
   - Correct server public IP
   - Correct server public key
   - Correct port (51820 by default)

## 📊 Performance & Resources

- **Installation Time**: ~2-3 minutes
- **RAM Usage**: ~50MB (WireGuard) + ~100MB (Dashboard)
- **CPU Usage**: Minimal (<5% on average)
- **Disk Space**: ~200MB total
- **Network Overhead**: <5% for WireGuard protocol

## 🤝 Contributing

Contributions are welcome! Please focus on:
- Security improvements
- Bug fixes
- Documentation updates
- Platform compatibility

### Development

```bash
# Clone repository
git clone https://github.com/yourusername/wireguard-installer.git
cd wireguard-installer

# Create feature branch
git checkout -b feature/your-feature

# Test thoroughly
sudo bash install.sh

# Submit PR
```

## 📖 Documentation & Resources

### Official Documentation
- [WireGuard Documentation](https://www.wireguard.com/)
- [WGDashboard Wiki](https://github.com/donaldzou/WGDashboard/wiki)

### Client Setup Guides
- [Windows Client](https://www.wireguard.com/install/)
- [macOS Client](https://apps.apple.com/us/app/wireguard/id1451685025)
- [iOS Client](https://apps.apple.com/us/app/wireguard/id1441195209)
- [Android Client](https://play.google.com/store/apps/details?id=com.wireguard.android)
- [Linux Client](https://www.wireguard.com/install/)

### Security Resources
- [WireGuard Whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
- [SSH Tunneling Guide](https://www.ssh.com/academy/ssh/tunneling)

## ⚠️ Disclaimer

This script is provided as-is for secure VPN deployment. While we prioritize security, always:
- Review scripts before running with sudo
- Keep your system updated
- Monitor access logs
- Use strong passwords
- Enable SSH key authentication

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Credits

- [WireGuard](https://www.wireguard.com/) by Jason A. Donenfeld
- [WGDashboard](https://github.com/donaldzou) by Donald Zou
- Inspired by [Proxmox VE Helper Scripts](https://tteck.github.io/Proxmox/)

## 📈 Stats & Compatibility

| OS | Version | Status | Tested |
|---|---|---|---|
| Ubuntu | 24.04 LTS | ✅ Supported | ✓ |
| Ubuntu | 22.04 LTS | ✅ Supported | ✓ |
| Ubuntu | 20.04 LTS | ✅ Supported | ✓ |
| Debian | 12 (Bookworm) | ✅ Supported | ✓ |
| Debian | 11 (Bullseye) | ✅ Supported | ✓ |

---

**🔒 Security First** | **🚀 Fast Setup** | **🛡️ Best Practices**

If this script helped you, please ⭐ star the repository!

For support: [Open an Issue](https://github.com/yourusername/wireguard-installer/issues) | [Discussions](https://github.com/yourusername/wireguard-installer/discussions)
