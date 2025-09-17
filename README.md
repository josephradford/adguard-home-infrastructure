# AdGuard Home Infrastructure as Code

[![CI](https://github.com/your-repo/adguard-home-infrastructure/workflows/CI/badge.svg)](https://github.com/your-repo/adguard-home-infrastructure/actions)
[![Security Scan](https://github.com/your-repo/adguard-home-infrastructure/workflows/Security%20Scanning/badge.svg)](https://github.com/your-repo/adguard-home-infrastructure/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A complete Infrastructure as Code solution for AdGuard Home DNS filtering with comprehensive monitoring, security hardening, and operational excellence. Specifically optimized for Australian home networks with Sydney PoP DNS servers.

## 🚀 Features

### Core Infrastructure
- **AdGuard Home** DNS filtering with 15+ curated blocklists
- **Complete monitoring stack** (Prometheus, Grafana, Alertmanager)
- **Security hardening** with UFW firewall and Fail2ban protection
- **Automated backups** with encryption and retention management
- **Cloud-init provisioning** for Ubuntu 24.04 LTS
- **Container security** with non-root users and read-only filesystems

### Australian Network Optimization 🇦🇺
- **Cloudflare Sydney PoP** (1.1.1.1) as primary DNS upstream
- **Quad9 Australia-friendly** (9.9.9.9) as secondary DNS
- **Google Sydney PoP** (8.8.8.8) as tertiary DNS
- **Australia/Sydney timezone** configuration
- **Local network optimization** for 192.168.1.0/24 networks

### Security & Compliance
- **SSH hardening** with custom port and key-only authentication
- **Firewall configuration** with minimal required ports
- **Fail2ban protection** against brute force attacks
- **Automated security updates** and vulnerability scanning
- **File integrity monitoring** with AIDE
- **Container security** with dropped privileges and capabilities

### Operational Excellence
- **One-command installation** with `make install`
- **Comprehensive health monitoring** and alerting
- **Automated backup and recovery** procedures
- **CI/CD pipeline** with security scanning and automated testing
- **Complete documentation** and troubleshooting guides
- **Multi-channel alerting** (Email, Slack, Telegram)

## 📋 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Ubuntu 24.04 LTS | Ubuntu 24.04 LTS |
| **RAM** | 2GB | 4GB |
| **Storage** | 20GB | 50GB |
| **Network** | Dynamic IP | Static IP (192.168.1.100) |
| **Dependencies** | None | Docker & docker-compose (auto-installed) |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AdGuard Infrastructure                    │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   AdGuard   │  │ Prometheus  │  │   Grafana   │         │
│  │    Home     │  │  (Metrics)  │  │(Dashboard) │         │
│  │   :53/:3000 │  │    :9090    │  │    :3001    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │    Node     │  │ Alertmanager│  │  AdGuard    │         │
│  │  Exporter   │  │ (Alerts)    │  │  Exporter   │         │
│  │    :9100    │  │    :9093    │  │    :9617    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│                      Security Layer                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │     UFW     │  │  Fail2ban   │  │    AIDE     │         │
│  │  Firewall   │  │ Protection  │  │  Integrity  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│                     Network Layer                           │
│    Internet → Router → AdGuard (192.168.1.100) → Devices  │
│              DNS: 1.1.1.1 (Sydney) → Blocked/Allowed      │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Option 1: Automated Installation (Recommended)

```bash
# Download latest release
wget https://github.com/your-repo/adguard-home-infrastructure/releases/latest/download/adguard-home-infrastructure-latest.tar.gz

# Extract and install
tar -xzf adguard-home-infrastructure-latest.tar.gz
cd adguard-home-infrastructure-*
cp .env.example .env

# Edit configuration (required)
nano .env  # Configure your network settings

# Install everything
sudo make install
```

### Option 2: Development Installation

```bash
# Clone repository
git clone https://github.com/your-repo/adguard-home-infrastructure.git
cd adguard-home-infrastructure

# Configure environment
cp .env.example .env
nano .env  # Configure your settings

# Install
sudo make install
```

### Option 3: Cloud-Init Deployment

```bash
# Use the cloud-init configuration for automated server provisioning
# Upload provisioning/cloud-init/cloud-init.yaml to your cloud provider
# or USB drive for automatic installation
```

## ⚙️ Configuration

### Essential Configuration (.env)

```bash
# Network Configuration
STATIC_IP=192.168.1.100
GATEWAY=192.168.1.1
NETMASK=255.255.255.0

# DNS Configuration (Australian Optimized)
DNS_UPSTREAM_1=1.1.1.1  # Cloudflare Sydney
DNS_UPSTREAM_2=9.9.9.9  # Quad9 Australia
DNS_UPSTREAM_3=8.8.8.8  # Google Sydney
TZ=Australia/Sydney

# Security Configuration
SSH_PORT=2222
SSH_USER=adguard
ADMIN_EMAIL=your-email@example.com

# Service Credentials
ADGUARD_USERNAME=admin
ADGUARD_PASSWORD=your_secure_password
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=your_secure_password
```

### Network Setup

Configure your router to use the AdGuard server as the primary DNS:
- **Primary DNS**: 192.168.1.100
- **Secondary DNS**: 1.1.1.1 (fallback)

## 🎯 Management Commands

| Command | Description |
|---------|-------------|
| `make install` | Complete infrastructure installation |
| `make health` | Check system health and service status |
| `make backup` | Create encrypted backup of all data |
| `make restore` | Restore from latest backup |
| `make update` | Update system packages and containers |
| `make restart` | Restart all services |
| `make logs` | View service logs |
| `make test` | Run validation tests |
| `make security-scan` | Run security audit |
| `make clean` | Clean up temporary files and old images |

## 📊 Access Points

After installation, access your services:

| Service | URL | Purpose |
|---------|-----|---------|
| **AdGuard Home** | http://192.168.1.100:3000 | DNS filtering management |
| **Grafana** | http://192.168.1.100:3001 | Monitoring dashboards |
| **Prometheus** | http://192.168.1.100:9090 | Metrics and alerts |
| **Alertmanager** | http://192.168.1.100:9093 | Alert management |

## 🔒 Security Features

### Network Security
- **Custom SSH port** (2222) with key-only authentication
- **UFW firewall** with minimal required ports
- **Fail2ban protection** against brute force attacks
- **Rate limiting** for DNS queries and web interfaces

### Container Security
- **Non-root containers** with dropped privileges
- **Read-only filesystems** where possible
- **Security profiles** and capability restrictions
- **Resource limits** to prevent abuse

### Monitoring & Alerting
- **24/7 monitoring** of all services and system resources
- **Multi-channel alerts** (Email, Slack, Telegram)
- **Security event detection** and automated response
- **Performance monitoring** with Australian latency optimization

### Data Protection
- **Encrypted backups** with configurable retention
- **Query log privacy** with Australian compliance considerations
- **Secure configuration management**
- **Automated security updates**

## 📈 Monitoring & Dashboards

### Pre-configured Grafana Dashboards
- **AdGuard Overview**: DNS queries, blocks, top domains
- **System Resources**: CPU, memory, disk, network
- **Security Dashboard**: Failed logins, blocked IPs, threats
- **Network Performance**: DNS latency, upstream health
- **Australian DNS Analytics**: Geographic query analysis

### Alerting Rules
- **Service Health**: Container failures, DNS outages
- **Security Events**: Brute force attempts, malware queries
- **Performance**: High latency, resource exhaustion
- **Australian-specific**: Upstream Sydney PoP health

## 🔧 Maintenance

### Automated Operations
- **Daily backups** at 3 AM AEDT with 30-day retention
- **Weekly security scans** and vulnerability assessments
- **Container updates** with automated rollback on failure
- **Log rotation** and cleanup

### Manual Operations
```bash
# View real-time service status
make health

# Create immediate backup
make backup

# Update all components
make update

# Restart specific service
docker-compose restart adguard

# View detailed logs
make logs service=adguard
```

## 🌏 Australian Compliance & Optimization

### DNS Privacy
- **DNS-over-HTTPS** for upstream queries
- **Query anonymization** options
- **Log retention** configurable for privacy compliance
- **Australian data sovereignty** considerations

### Network Performance
- **Sydney PoP priority** for minimal latency
- **Australian CDN optimization** for content delivery
- **Local timezone handling** for logs and schedules
- **ISP-optimized configurations** for major Australian providers

## 🧪 Testing & Validation

### Automated Testing
```bash
# Run full test suite
make test

# Test DNS functionality
make test-dns

# Security validation
make security-scan

# Performance testing
make performance-test
```

### Manual Validation
```bash
# Test DNS resolution
dig @192.168.1.100 google.com

# Test DNS blocking
dig @192.168.1.100 doubleclick.net  # Should return 0.0.0.0

# Check service health
curl http://192.168.1.100:3000/
curl http://192.168.1.100:9090/-/healthy
```

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Setup Guide](docs/setup.md) | Detailed installation instructions |
| [Security Guide](docs/security.md) | Security hardening and compliance |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and solutions |
| [API Documentation](docs/api.md) | Service API references |
| [Contributing](CONTRIBUTING.md) | Development and contribution guide |

## 🔄 CI/CD Pipeline

### Automated Workflows
- **Continuous Integration**: Code quality, security scanning, testing
- **Security Scanning**: Container vulnerabilities, dependency checks
- **Automated Releases**: Version management, artifact creation
- **Deployment Pipeline**: Automated deployment with rollback

### Quality Gates
- **Code Quality**: ShellCheck, YAML linting, configuration validation
- **Security**: Trivy scanning, secret detection, compliance checks
- **Functionality**: DNS testing, service health, performance validation

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/your-repo/adguard-home-infrastructure.git
cd adguard-home-infrastructure
make dev-setup
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Community Support
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Community Q&A and sharing
- **Wiki**: Additional documentation and examples

### Professional Support
For enterprise deployments and custom configurations, contact us at support@example.com.

## 🙏 Acknowledgments

- **AdGuard Team** for the excellent DNS filtering software
- **Prometheus Community** for monitoring tools
- **Australian DNS Providers** for reliable upstream services
- **Open Source Community** for security tools and best practices

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=your-repo/adguard-home-infrastructure&type=Date)](https://star-history.com/#your-repo/adguard-home-infrastructure&Date)

---

**Made with ❤️ for the Australian home networking community**

Current Version: v1.0.0 | Last Updated: 2024-01-15 | Maintained by: [Your Name]