# AdGuard Home Infrastructure - Setup Guide

This comprehensive guide will walk you through setting up AdGuard Home Infrastructure on your Australian home network.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Hardware Requirements](#hardware-requirements)
3. [Network Planning](#network-planning)
4. [Installation Methods](#installation-methods)
5. [Configuration](#configuration)
6. [Post-Installation Setup](#post-installation-setup)
7. [Network Integration](#network-integration)
8. [Verification & Testing](#verification--testing)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **Operating System** | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| **RAM** | 2GB | 4GB |
| **Storage** | 20GB available | 50GB available |
| **CPU** | 2 cores | 4 cores |
| **Network** | 100 Mbps | 1 Gbps |

### Required Knowledge

- Basic Linux command line usage
- Network configuration fundamentals
- Understanding of DNS concepts
- Basic Docker concepts (helpful but not required)

### Access Requirements

- **Administrative access** to your target server
- **SSH access** for remote installation
- **Router admin access** for DNS configuration
- **Internet connectivity** for downloading components

## Hardware Requirements

### Recommended Hardware

#### Budget Option ($200-400 AUD)
- **Raspberry Pi 4 (4GB/8GB)** or equivalent SBC
- **High-quality microSD card** (64GB Class 10 or better)
- **Reliable power supply** with backup battery (optional)

#### Home Server Option ($500-1000 AUD)
- **Intel NUC** or similar compact PC
- **8GB RAM minimum**
- **256GB SSD** for OS and data
- **Gigabit Ethernet**

#### Repurposed PC Option ($0-200 AUD)
- **Any x86_64 PC** with 4GB+ RAM
- **SSD recommended** for better performance
- **Wired network connection preferred**

### Network Infrastructure

#### Essential Network Setup
```
Internet → Modem → Router → AdGuard Server (192.168.1.100)
                      ↓
                 All network devices
```

#### Network Requirements
- **Static IP assignment** for AdGuard server
- **Port access** to router configuration
- **DHCP configuration** access for DNS settings

## Network Planning

### IP Address Planning

#### Default Configuration
- **AdGuard Server**: 192.168.1.100/24
- **Gateway/Router**: 192.168.1.1
- **Network Range**: 192.168.1.0/24
- **DNS Services**: 53/tcp, 53/udp

#### Custom Network Planning
If your network uses different IP ranges, update these values in `.env`:

```bash
# For 10.0.0.0/24 networks
STATIC_IP=10.0.0.100
GATEWAY=10.0.0.1
NETMASK=255.255.255.0

# For 172.16.1.0/24 networks
STATIC_IP=172.16.1.100
GATEWAY=172.16.1.1
NETMASK=255.255.255.0
```

### Port Planning

#### Required Ports
| Port | Protocol | Service | Access |
|------|----------|---------|---------|
| 53 | TCP/UDP | DNS | All devices |
| 2222 | TCP | SSH | Admin only |
| 3000 | TCP | AdGuard Web | LAN only |
| 3001 | TCP | Grafana | LAN only |
| 9090 | TCP | Prometheus | LAN only |

#### Security Considerations
- **SSH on port 2222** instead of default 22
- **Web interfaces restricted** to local network
- **Monitoring ports isolated** from internet

## Installation Methods

### Method 1: Automated Installation (Recommended)

#### Step 1: Download Release
```bash
# Download latest stable release
wget https://github.com/your-repo/adguard-home-infrastructure/releases/latest/download/adguard-home-infrastructure-latest.tar.gz

# Extract archive
tar -xzf adguard-home-infrastructure-latest.tar.gz
cd adguard-home-infrastructure-*
```

#### Step 2: Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env  # See configuration section below
```

#### Step 3: Run Installation
```bash
# Execute automated installation
sudo make install

# Monitor installation progress
tail -f /opt/logs/adguard-install.log
```

### Method 2: Cloud-Init Deployment

#### Step 1: Prepare Cloud-Init Configuration
```bash
# Edit cloud-init configuration
nano provisioning/cloud-init/cloud-init.yaml

# Update SSH public key
# Replace: ssh-rsa YOUR_PUBLIC_KEY_HERE
```

#### Step 2: Deploy with Cloud-Init
```bash
# For cloud providers (AWS, DigitalOcean, etc.)
# Upload cloud-init.yaml during instance creation

# For bare metal with cloud-init support
sudo cloud-init -f provisioning/cloud-init/cloud-init.yaml
```

### Method 3: Manual Installation

#### Step 1: System Preparation
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install prerequisites
sudo apt install -y git curl wget docker.io docker-compose

# Add user to docker group
sudo usermod -aG docker $USER
```

#### Step 2: Clone Repository
```bash
# Clone source code
git clone https://github.com/your-repo/adguard-home-infrastructure.git
cd adguard-home-infrastructure
```

#### Step 3: Manual Configuration
```bash
# Run individual setup steps
sudo scripts/setup/install.sh

# Or run components individually
sudo configs/firewall/ufw-rules.sh
cd docker && docker-compose up -d
```

## Configuration

### Essential Configuration (.env)

#### Network Configuration
```bash
# Static IP Configuration
STATIC_IP=192.168.1.100
GATEWAY=192.168.1.1
NETMASK=255.255.255.0
NETWORK_INTERFACE=eth0

# Domain Configuration
HOSTNAME=adguard-dns
DOMAIN=home.local
```

#### DNS Configuration (Australian Optimized)
```bash
# Primary DNS Servers (Australian PoPs)
DNS_UPSTREAM_1=1.1.1.1          # Cloudflare Sydney
DNS_UPSTREAM_2=9.9.9.9          # Quad9 Australia-friendly
DNS_UPSTREAM_3=8.8.8.8          # Google Sydney

# DNS-over-HTTPS Upstreams
DNS_UPSTREAM_DOH_1=https://1.1.1.1/dns-query
DNS_UPSTREAM_DOH_2=https://dns.quad9.net/dns-query
DNS_UPSTREAM_DOH_3=https://dns.google/dns-query

# Timezone
TZ=Australia/Sydney
```

#### Security Configuration
```bash
# SSH Security
SSH_PORT=2222
SSH_USER=adguard

# Service Credentials
ADGUARD_USERNAME=admin
ADGUARD_PASSWORD=your_very_secure_password_here

# Monitoring Credentials
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=another_secure_password_here
GRAFANA_SECRET_KEY=a_long_random_secret_key

# Contact Information
ADMIN_EMAIL=your-email@example.com
```

#### Advanced Configuration
```bash
# Backup Configuration
BACKUP_LOCATION=/opt/backups
BACKUP_RETENTION_DAYS=30
BACKUP_ENCRYPTION_KEY=generate_with_openssl_rand

# Alert Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Optional: Telegram Alerts
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Optional: Slack Alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
```

### Security Configuration

#### SSH Key Setup
```bash
# Generate SSH key pair (if you don't have one)
ssh-keygen -t rsa -b 4096 -C "your-email@example.com"

# Copy public key to server
ssh-copy-id -p 2222 adguard@192.168.1.100
```

#### Password Generation
```bash
# Generate secure passwords
openssl rand -base64 32  # For ADGUARD_PASSWORD
openssl rand -base64 32  # For GRAFANA_ADMIN_PASSWORD
openssl rand -base64 64  # For GRAFANA_SECRET_KEY
openssl rand -base64 32  # For BACKUP_ENCRYPTION_KEY
```

### AdGuard-Specific Configuration

#### Custom Blocklists
Add Australian-specific blocklists in `docker/configs/adguard/AdGuardHome.yaml`:

```yaml
filters:
  # Default lists already included

  # Add Australian-specific lists
  - enabled: true
    url: https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/sections/cookies.txt
    name: Cookie Notices (AU Compliant)
    id: 100

  # Add local custom rules
user_rules:
  # Australian banking whitelists
  - '@@||commbank.com.au^'
  - '@@||westpac.com.au^'
  - '@@||anz.com^'
  - '@@||nab.com.au^'

  # Australian government services
  - '@@||mygovid.gov.au^'
  - '@@||centrelink.gov.au^'
  - '@@||ato.gov.au^'
```

## Post-Installation Setup

### Initial Service Configuration

#### Step 1: AdGuard Home Setup
```bash
# Access AdGuard web interface
# URL: http://192.168.1.100:3000

# Follow the setup wizard:
# 1. Choose admin interface port (keep 3000)
# 2. Choose DNS port (keep 53)
# 3. Create admin account
# 4. Configure DNS servers (already optimized)
```

#### Step 2: Grafana Dashboard Setup
```bash
# Access Grafana
# URL: http://192.168.1.100:3001
# Login: admin / [your_grafana_password]

# Import pre-configured dashboards:
# - Go to + → Import
# - Use dashboard IDs: 13802, 1860, 893
# - Configure data sources to point to Prometheus
```

#### Step 3: Monitoring Configuration
```bash
# Verify Prometheus targets
# URL: http://192.168.1.100:9090/targets

# All targets should show "UP" status:
# - prometheus (localhost:9090)
# - adguard-exporter (adguard-exporter:9617)
# - node-exporter (node-exporter:9100)
# - adguard-home (adguard:3000)
```

### Security Hardening

#### Step 1: SSH Configuration
```bash
# Test SSH access on new port
ssh -p 2222 adguard@192.168.1.100

# Disable password authentication (already done in cloud-init)
sudo nano /etc/ssh/sshd_config
# Verify: PasswordAuthentication no

# Restart SSH service
sudo systemctl restart ssh
```

#### Step 2: Firewall Verification
```bash
# Check UFW status
sudo ufw status verbose

# Expected output should show:
# - Port 2222/tcp (SSH)
# - Port 53/tcp,udp (DNS)
# - Port 3000/tcp (AdGuard Web - LAN only)
# - Monitoring ports restricted to LAN
```

#### Step 3: Fail2ban Configuration
```bash
# Check fail2ban status
sudo fail2ban-client status

# Check AdGuard-specific jails
sudo fail2ban-client status adguard-auth
sudo fail2ban-client status sshd-adguard
```

### Backup Configuration

#### Step 1: Verify Backup Setup
```bash
# Run manual backup test
sudo /opt/scripts/backup/backup.sh

# Check backup location
ls -la /opt/backups/

# Verify backup integrity
ls -la /opt/backups/*.sha256
```

#### Step 2: Schedule Verification
```bash
# Check cron jobs
sudo crontab -l

# Expected entries:
# - Daily backup at 3 AM
# - Security monitoring every 15 minutes
# - Weekly updates on Sunday
```

## Network Integration

### Router Configuration

#### Step 1: DNS Server Configuration
```
Router Web Interface → DHCP Settings → DNS Settings

Primary DNS Server: 192.168.1.100
Secondary DNS Server: 1.1.1.1 (fallback)

Apply and restart router
```

#### Step 2: DHCP Lease Configuration
```
DHCP Reservations:
- MAC Address: [AdGuard server MAC]
- IP Address: 192.168.1.100
- Hostname: adguard-dns
```

#### Step 3: Port Forwarding (Optional)
```
For remote access (advanced users only):
- SSH: External port 2222 → 192.168.1.100:2222
- AdGuard Web: Do NOT expose to internet
```

### Device Configuration

#### Automatic Configuration (Recommended)
Most devices will automatically receive the new DNS settings from DHCP.

#### Manual Configuration (If needed)
```
For devices requiring manual DNS:
Primary DNS: 192.168.1.100
Secondary DNS: 1.1.1.1

Examples:
- Gaming consoles
- IoT devices
- Servers with static IPs
```

### ISP-Specific Considerations

#### Telstra
```bash
# Add Telstra-specific DNS fallbacks
echo "208.67.222.222" >> /etc/resolv.conf  # OpenDNS
echo "208.67.220.220" >> /etc/resolv.conf  # OpenDNS
```

#### Optus
```bash
# Optus networks may benefit from additional upstream
DNS_UPSTREAM_4=203.12.160.35  # Optus DNS
```

#### TPG/iiNet
```bash
# Add TPG-specific configurations
DNS_UPSTREAM_4=203.12.160.35  # TPG DNS
```

## Verification & Testing

### DNS Functionality Tests

#### Step 1: Basic DNS Resolution
```bash
# Test from AdGuard server
dig @localhost google.com
dig @localhost facebook.com
dig @localhost youtube.com

# Test from client device
nslookup google.com
nslookup cloudflare.com
```

#### Step 2: DNS Blocking Tests
```bash
# Test ad blocking (should return 0.0.0.0 or no result)
dig @192.168.1.100 doubleclick.net
dig @192.168.1.100 googleadservices.com
dig @192.168.1.100 googlesyndication.com

# Test malware blocking
dig @192.168.1.100 malware.wicar.org
```

#### Step 3: Performance Tests
```bash
# Test query speed
time dig @192.168.1.100 google.com
time dig @192.168.1.100 facebook.com

# Compare with upstream
time dig @1.1.1.1 google.com
time dig @8.8.8.8 google.com
```

### Service Health Tests

#### Step 1: Container Status
```bash
# Check all containers are running
docker-compose ps

# Expected status: "Up" for all services
```

#### Step 2: Web Interface Tests
```bash
# Test AdGuard web interface
curl -I http://192.168.1.100:3000/

# Test Grafana interface
curl -I http://192.168.1.100:3001/

# Test Prometheus interface
curl -I http://192.168.1.100:9090/
```

#### Step 3: Monitoring Tests
```bash
# Check Prometheus metrics
curl http://192.168.1.100:9617/metrics | grep adguard

# Check system metrics
curl http://192.168.1.100:9100/metrics | grep node_
```

### Network Integration Tests

#### Step 1: Client Device Tests
```bash
# From a client device, test:

# 1. DNS resolution works
nslookup google.com

# 2. Websites load normally
curl -I https://www.google.com.au

# 3. Ads are blocked
# Visit a website with ads and verify blocking
```

#### Step 2: Performance Verification
```bash
# Speed test from client
speedtest-cli

# DNS resolution speed
time nslookup google.com
time nslookup facebook.com
```

### Security Verification

#### Step 1: Firewall Tests
```bash
# From external network (mobile data):

# SSH should work on custom port
ssh -p 2222 adguard@[your-public-ip]

# Web interfaces should NOT be accessible
curl http://[your-public-ip]:3000/  # Should fail
curl http://[your-public-ip]:3001/  # Should fail
```

#### Step 2: Intrusion Detection Tests
```bash
# Generate some test failed logins
ssh -p 2222 wronguser@192.168.1.100  # Should fail

# Check fail2ban response
sudo fail2ban-client status sshd-adguard
```

## Troubleshooting

### Common Issues

#### Issue: DNS Resolution Not Working
```bash
# Check AdGuard service status
docker-compose ps adguard

# Check AdGuard logs
docker-compose logs adguard

# Verify DNS port binding
sudo netstat -tulpn | grep :53

# Test direct DNS query
dig @127.0.0.1 google.com
```

#### Issue: Web Interface Not Accessible
```bash
# Check container status
docker-compose ps

# Check firewall rules
sudo ufw status

# Verify port binding
sudo netstat -tulpn | grep :3000

# Check container logs
docker-compose logs adguard
```

#### Issue: Slow DNS Resolution
```bash
# Check upstream DNS servers
dig @1.1.1.1 google.com
dig @9.9.9.9 google.com

# Monitor AdGuard query log
tail -f /opt/adguard/logs/querylog.json

# Check system resources
top
df -h
```

#### Issue: Monitoring Not Working
```bash
# Check Prometheus targets
curl http://localhost:9090/api/v1/targets

# Verify exporters
curl http://localhost:9617/metrics  # AdGuard exporter
curl http://localhost:9100/metrics  # Node exporter

# Check container networking
docker network ls
docker network inspect adguard-net
```

### Recovery Procedures

#### Complete Service Recovery
```bash
# Stop all services
cd /opt/adguard-infrastructure/docker
docker-compose down

# Restart all services
docker-compose up -d

# Verify health
make health
```

#### Configuration Recovery
```bash
# Restore from backup
/opt/scripts/backup/restore.sh

# Or restore specific component
docker-compose down adguard
# Restore AdGuard configuration
docker-compose up -d adguard
```

#### Network Recovery
```bash
# Reset network configuration
sudo netplan apply

# Restart networking
sudo systemctl restart networking

# Verify connectivity
ping 8.8.8.8
ping google.com
```

### Advanced Troubleshooting

#### Container Debugging
```bash
# Enter container for debugging
docker exec -it adguard-home /bin/sh

# Check container networking
docker exec adguard-home netstat -tulpn

# View container environment
docker exec adguard-home env
```

#### Log Analysis
```bash
# Centralized log viewing
journalctl -u docker -f

# Service-specific logs
docker-compose logs -f adguard
docker-compose logs -f prometheus
docker-compose logs -f grafana
```

#### Performance Analysis
```bash
# Container resource usage
docker stats

# System performance
htop
iotop
nethogs
```

### Getting Help

#### Log Collection
```bash
# Collect diagnostic information
/opt/scripts/monitoring/comprehensive-monitor.sh

# Generate support bundle
tar -czf adguard-support-$(date +%Y%m%d).tar.gz \
  /opt/logs/ \
  /opt/adguard-infrastructure/.env \
  /var/log/syslog \
  /var/log/auth.log
```

#### Community Support
- GitHub Issues: Report bugs and get community help
- Wiki Documentation: Additional guides and examples
- Discussion Forums: Community Q&A

#### Professional Support
For enterprise deployments or custom configurations, contact our professional support team.

---

This completes the comprehensive setup guide. For additional help, see the [Troubleshooting Guide](troubleshooting.md) or contact support.