# Security Guide - AdGuard Home Infrastructure

This guide covers the comprehensive security measures implemented in AdGuard Home Infrastructure, compliance considerations for Australian networks, and best practices for maintaining a secure DNS filtering environment.

## Table of Contents

1. [Security Architecture](#security-architecture)
2. [Network Security](#network-security)
3. [Container Security](#container-security)
4. [Access Control](#access-control)
5. [Monitoring & Detection](#monitoring--detection)
6. [Data Protection](#data-protection)
7. [Compliance & Privacy](#compliance--privacy)
8. [Incident Response](#incident-response)
9. [Security Maintenance](#security-maintenance)
10. [Australian Considerations](#australian-considerations)

## Security Architecture

### Defense in Depth Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                    External Threats                         │
├─────────────────────────────────────────────────────────────┤
│  1. Network Perimeter (UFW Firewall + Fail2ban)           │
├─────────────────────────────────────────────────────────────┤
│  2. Access Control (SSH Keys + MFA)                        │
├─────────────────────────────────────────────────────────────┤
│  3. Container Security (Non-root + Capabilities)           │
├─────────────────────────────────────────────────────────────┤
│  4. Application Security (TLS + Authentication)            │
├─────────────────────────────────────────────────────────────┤
│  5. Data Protection (Encryption + Backups)                 │
├─────────────────────────────────────────────────────────────┤
│  6. Monitoring & Detection (AIDE + Log Analysis)           │
├─────────────────────────────────────────────────────────────┤
│  7. Incident Response (Automated + Manual)                 │
└─────────────────────────────────────────────────────────────┘
```

### Security Principles

#### Zero Trust Architecture
- **No implicit trust** between components
- **Verify every request** regardless of source
- **Least privilege access** for all services
- **Continuous monitoring** and validation

#### Australian Privacy by Design
- **Data minimization** in DNS query logging
- **Purpose limitation** for collected data
- **Consent mechanisms** for optional features
- **Local data storage** where possible

## Network Security

### Firewall Configuration

#### UFW (Uncomplicated Firewall) Rules
```bash
# Essential services only
Port 53/tcp,udp     # DNS (public)
Port 2222/tcp       # SSH (rate limited)
Port 3000/tcp       # AdGuard Web (LAN only)

# Monitoring (LAN only)
Port 9090/tcp       # Prometheus (192.168.0.0/16)
Port 3001/tcp       # Grafana (192.168.0.0/16)
Port 9093/tcp       # Alertmanager (192.168.0.0/16)
```

#### Advanced Network Security
```bash
# DDoS Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048

# IP Spoofing Protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ICMP Redirect Protection
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
```

### SSH Hardening

#### Secure SSH Configuration
```bash
# /etc/ssh/sshd_config security settings
Port 2222                          # Non-standard port
Protocol 2                         # SSH protocol 2 only
PermitRootLogin no                  # Disable root login
PasswordAuthentication no           # Key-only authentication
PubkeyAuthentication yes            # Enable public key auth
MaxAuthTries 3                      # Limit auth attempts
ClientAliveInterval 600             # Auto-disconnect idle
ClientAliveCountMax 3               # Max idle checks
AllowUsers adguard                  # Restrict user access
```

#### SSH Key Management
```bash
# Generate secure SSH keys
ssh-keygen -t ed25519 -b 4096 -C "adguard-$(date +%Y%m%d)"

# Key rotation schedule
# - Generate new keys quarterly
# - Remove old keys after validation
# - Use different keys for different environments
```

### DNS Security

#### DNS-over-HTTPS (DoH) Configuration
```yaml
# Secure upstream DNS with DoH
upstream_dns:
  - https://1.1.1.1/dns-query        # Cloudflare Sydney
  - https://dns.quad9.net/dns-query  # Quad9 (privacy-focused)
  - https://dns.google/dns-query     # Google Sydney

# DNS Security Features
enable_dnssec: true                  # DNSSEC validation
refuse_any: true                     # Block ANY queries
ratelimit: 20                        # Rate limit queries
```

#### DNS Privacy Protection
```yaml
# Query anonymization
edns_client_subnet:
  enabled: true
  use_custom: false

# Log retention for privacy
querylog:
  interval: 2160h                    # 90 days maximum
  size_memory: 1000                  # Limit memory usage

# Blocked query handling
blocked_response_ttl: 10             # Short TTL for blocked
```

### Fail2ban Protection

#### Anti-Brute Force Configuration
```ini
# SSH Protection
[sshd-adguard]
enabled = true
port = 2222
maxretry = 3
bantime = 7200                       # 2 hours
findtime = 600                       # 10 minutes

# AdGuard Web Protection
[adguard-auth]
enabled = true
port = 3000
maxretry = 5
bantime = 3600                       # 1 hour

# DNS DoS Protection
[adguard-dos]
enabled = true
port = 53
maxretry = 100                       # High threshold for legitimate use
bantime = 1800                       # 30 minutes
```

#### Geographic Blocking (Optional)
```bash
# Block non-Australian IPs for SSH (advanced)
# Configure GeoIP blocking for enhanced security
# Note: May impact legitimate remote access
```

## Container Security

### Container Hardening

#### Security Constraints
```yaml
# Docker Compose security configuration
security_opt:
  - no-new-privileges:true           # Prevent privilege escalation

cap_drop:
  - ALL                              # Drop all capabilities

cap_add:
  - NET_BIND_SERVICE                 # Only required capabilities
  - SETGID
  - SETUID

read_only: true                      # Read-only filesystem
user: "1000:1000"                    # Non-root user
```

#### Resource Limits
```yaml
deploy:
  resources:
    limits:
      memory: 512m                   # Memory limit
      cpus: '1.0'                    # CPU limit
    reservations:
      memory: 256m                   # Guaranteed memory
      cpus: '0.5'                    # Guaranteed CPU
```

### Image Security

#### Trusted Base Images
- **AdGuard Home**: Official images only
- **Prometheus**: Official Prometheus images
- **Grafana**: Official Grafana OSS images
- **Alpine Linux**: Minimal attack surface

#### Image Scanning
```bash
# Automated vulnerability scanning
trivy image adguard/adguardhome:latest
trivy image prom/prometheus:latest
trivy image grafana/grafana-oss:latest

# CI/CD integration for continuous scanning
```

### Network Isolation

#### Container Networking
```yaml
networks:
  adguard-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16      # Isolated subnet
    driver_opts:
      com.docker.network.bridge.enable_icc: "true"
      com.docker.network.bridge.enable_ip_masquerade: "true"
```

#### Service Communication
- **Internal DNS**: Container-to-container communication
- **No external access**: Except through defined ports
- **TLS encryption**: For inter-service communication where supported

## Access Control

### Authentication Systems

#### Multi-Factor Authentication (MFA)
```bash
# SSH MFA with TOTP (optional)
# Install Google Authenticator PAM module
sudo apt install libpam-google-authenticator

# Configure in /etc/pam.d/sshd
auth required pam_google_authenticator.so
```

#### Service Authentication
```yaml
# AdGuard Home authentication
users:
  - name: admin
    password: $2a$10$bcrypt_hash    # Bcrypt hashed password

# Grafana authentication
auth:
  disable_login_form: false
  disable_signout_menu: false
```

### Authorization Framework

#### Role-Based Access Control (RBAC)
```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Administrator  │  │   Monitoring    │  │   Read-Only     │
│                 │  │   Operator      │  │   Viewer        │
├─────────────────┤  ├─────────────────┤  ├─────────────────┤
│ • Full access   │  │ • View metrics  │  │ • View status   │
│ • Configuration │  │ • Create alerts │  │ • Read logs     │
│ • User mgmt     │  │ • Acknowledge   │  │ • Basic info    │
│ • System admin  │  │ • Report issues │  │ • No changes    │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

#### Service Permissions
```bash
# File system permissions
/opt/adguard/           # adguard:adguard 750
/opt/monitoring/        # adguard:adguard 750
/opt/backups/           # adguard:adguard 700
/opt/logs/              # adguard:adguard 755
```

### API Security

#### API Authentication
```bash
# AdGuard Home API
# Use session-based authentication
# Implement rate limiting
# Validate all inputs

# Prometheus API
# Restrict to local network
# No authentication by default (network-isolated)

# Grafana API
# Token-based authentication
# Role-based permissions
```

## Monitoring & Detection

### Security Information and Event Management (SIEM)

#### Log Aggregation
```bash
# Centralized logging configuration
rsyslog → /var/log/adguard-security.log

# Log sources:
- SSH authentication attempts
- AdGuard query logs
- Container events
- System security events
- Network connection logs
```

#### Security Metrics
```yaml
# Prometheus security metrics
security_failed_logins_total         # Failed SSH attempts
security_banned_ips_total            # Fail2ban actions
dns_suspicious_queries_total         # Malware/phishing queries
container_security_violations_total  # Container security events
```

### Intrusion Detection

#### File Integrity Monitoring (AIDE)
```bash
# Critical files monitored
/etc/ssh/sshd_config                 # SSH configuration
/etc/ufw/                            # Firewall rules
/opt/adguard/conf/                   # AdGuard configuration
/etc/fail2ban/                       # Fail2ban configuration
/etc/systemd/system/                 # Service definitions

# Daily integrity checks
/usr/bin/aide --check
```

#### Network Intrusion Detection
```bash
# Monitoring suspicious patterns
- High-volume DNS queries from single IP
- Queries to known malware domains
- Unusual traffic patterns
- Port scanning attempts
- Brute force attack patterns
```

### Automated Response

#### Security Automation
```bash
# Automated responses to threats
1. Fail2ban automatic IP blocking
2. DNS query rate limiting
3. Container restart on anomalies
4. Backup triggers on security events
5. Alert escalation procedures
```

#### Incident Escalation
```yaml
# Alert severity levels
Critical: Service compromise, data breach
High: Authentication failures, system anomalies
Medium: Performance issues, configuration changes
Low: Informational events, routine maintenance
```

## Data Protection

### Encryption

#### Data at Rest
```bash
# Backup encryption
BACKUP_ENCRYPTION_KEY=AES-256        # Strong encryption key
openssl enc -aes-256-cbc -salt       # Backup encryption method

# Configuration protection
chmod 600 .env                       # Restrict environment file
chmod 600 /opt/adguard/conf/*        # Protect configuration
```

#### Data in Transit
```bash
# TLS/SSL configuration
# DNS-over-HTTPS for upstream queries
# SSH with strong ciphers
# Container-to-container encryption where possible
```

### Backup Security

#### Secure Backup Strategy
```bash
# 3-2-1 Backup rule implementation
3 copies: Local, network, offsite
2 different media types
1 offsite location (cloud/remote)

# Backup verification
sha256sum backup_file                # Integrity verification
gpg --verify backup_signature        # Authenticity verification
```

#### Backup Access Control
```bash
# Restricted backup access
/opt/backups/           700 adguard:adguard
backup_key.gpg          600 adguard:adguard

# Backup retention policy
Daily: 7 days
Weekly: 4 weeks
Monthly: 12 months
```

### Privacy Protection

#### DNS Query Privacy
```yaml
# Privacy-preserving configuration
querylog:
  enabled: true
  interval: 2160h                    # 90 days max retention
  anonymize_client_ip: true          # Optional anonymization

# Query log rotation
logrotate configuration              # Automatic cleanup
```

#### Data Minimization
```bash
# Collect only necessary data
- DNS queries (for filtering)
- Basic system metrics (for monitoring)
- Security events (for protection)

# Avoid collecting:
- Personal browsing habits
- Detailed user patterns
- Unnecessary metadata
```

## Compliance & Privacy

### Australian Privacy Principles (APPs)

#### APP 1: Open and Transparent Management
```markdown
Privacy Policy Requirements:
- Clear data collection purposes
- Data usage explanation
- Retention period disclosure
- Contact information provision
```

#### APP 3: Collection of Solicited Personal Information
```bash
# Legitimate collection purposes
DNS_COLLECTION_PURPOSE="Network security and content filtering"
LOG_COLLECTION_PURPOSE="System monitoring and threat detection"
METRICS_COLLECTION_PURPOSE="Performance optimization"
```

#### APP 11: Security of Personal Information
```bash
# Technical safeguards
- Encryption for data at rest and in transit
- Access controls and authentication
- Regular security updates
- Monitoring and incident response

# Administrative safeguards
- Staff training and awareness
- Access management procedures
- Incident response procedures
- Regular security assessments
```

### Data Sovereignty

#### Australian Data Residency
```bash
# Local data storage
LOG_STORAGE="/opt/logs"              # Local filesystem
BACKUP_LOCATION="/opt/backups"       # Local backup storage
METRICS_RETENTION="local"            # No external metrics

# Upstream DNS considerations
# Choose providers with Australian presence
# Prefer DNS-over-HTTPS for privacy
```

#### Cross-Border Data Transfer
```yaml
# Minimize offshore data transfer
upstream_dns:
  - Australian or privacy-focused providers
  - Local CDN endpoints where possible
  - Encrypted communications only
```

### GDPR Considerations (if applicable)

#### Right to Erasure
```bash
# Data deletion procedures
./scripts/privacy/delete-user-data.sh [identifier]

# Log anonymization
./scripts/privacy/anonymize-logs.sh [date_range]
```

#### Data Portability
```bash
# Export user data (if applicable)
./scripts/privacy/export-user-data.sh [identifier]
```

## Incident Response

### Incident Classification

#### Security Incident Types
```
Level 1 - Critical: Data breach, system compromise
Level 2 - High: Authentication bypass, service disruption
Level 3 - Medium: Configuration errors, performance issues
Level 4 - Low: Policy violations, minor anomalies
```

### Response Procedures

#### Immediate Response (0-1 hours)
```bash
1. Isolate affected systems
   docker compose down [service]

2. Preserve evidence
   cp /var/log/* /opt/incident-$(date +%Y%m%d)/

3. Assess impact
   ./scripts/monitoring/comprehensive-monitor.sh

4. Notify stakeholders
   # Send alerts via configured channels
```

#### Short-term Response (1-24 hours)
```bash
1. Detailed investigation
   - Log analysis
   - Timeline reconstruction
   - Impact assessment

2. Containment measures
   - Block malicious IPs
   - Disable compromised accounts
   - Apply emergency patches

3. Recovery planning
   - Service restoration steps
   - Data recovery procedures
   - Communication plan
```

#### Long-term Response (1-30 days)
```bash
1. Root cause analysis
2. Security improvements
3. Policy updates
4. Training and awareness
5. Lessons learned documentation
```

### Forensics and Evidence

#### Log Preservation
```bash
# Immutable log storage
./scripts/security/preserve-evidence.sh [incident_id]

# Chain of custody documentation
./scripts/security/custody-log.sh [evidence_id]
```

#### Recovery Procedures
```bash
# System recovery from backups
./scripts/backup/restore.sh [backup_date]

# Service recovery verification
make health
make test
```

## Security Maintenance

### Regular Security Tasks

#### Daily Tasks
```bash
# Automated (via cron)
- Security monitoring scan
- Log analysis and alerting
- Backup integrity verification
- Service health checks

# Manual verification
- Review security alerts
- Check fail2ban status
- Monitor unusual activity
```

#### Weekly Tasks
```bash
# System maintenance
- Security updates review
- Log rotation verification
- Backup testing
- Performance monitoring

# Security assessment
- Failed login analysis
- Network traffic review
- Container security check
```

#### Monthly Tasks
```bash
# Comprehensive review
- Security policy review
- Access control audit
- Incident response testing
- Security training updates

# System hardening
- Configuration review
- Vulnerability assessment
- Penetration testing (optional)
```

### Security Updates

#### Automated Updates
```bash
# System security updates
unattended-upgrades configuration
/etc/apt/apt.conf.d/50unattended-upgrades

# Container image updates
watchtower configuration
automatic security updates only
```

#### Manual Updates
```bash
# Configuration updates
git pull origin main
make update

# Security patches
./scripts/maintenance/security-update.sh
```

### Vulnerability Management

#### Vulnerability Scanning
```bash
# Container scanning
trivy image [image_name]

# System scanning
lynis audit system
```

#### Patch Management
```bash
# Security patch priority
Critical: Immediate (0-24 hours)
High: Urgent (1-7 days)
Medium: Standard (1-30 days)
Low: Planned (next maintenance window)
```

## Australian Considerations

### Regulatory Compliance

#### Telecommunications Consumer Protections Code
- **Service reliability** requirements
- **Customer notification** procedures
- **Dispute resolution** mechanisms

#### Privacy Act 1988
- **Australian Privacy Principles** compliance
- **Notifiable data breach** requirements
- **Consent mechanisms** for optional features

### Cultural and Regional Factors

#### Australian Internet Landscape
```bash
# ISP-specific considerations
- Telstra network optimizations
- NBN compatibility requirements
- Mobile data considerations
- Regional connectivity variations
```

#### Local Threat Landscape
```bash
# Australian-specific threats
- Government impersonation attacks
- Banking fraud attempts
- Telecommunications scams
- Regional malware campaigns
```

### Government and Law Enforcement

#### Assistance and Access Act 2018
```markdown
Considerations:
- Technical capability notices
- Technical assistance requests
- Technical assistance notices
- Industry assistance measures
```

#### Data Retention Obligations
```bash
# Metadata retention (if applicable)
# Note: Home users typically exempt
# Consult legal advice for business use
```

### Best Practices for Australian Deployment

#### DNS Provider Selection
```yaml
# Prioritize providers with:
- Australian presence
- Privacy commitments
- Government transparency
- Strong security practices
```

#### Network Configuration
```bash
# Australian timezone
TZ=Australia/Sydney

# Local NTP servers
au.pool.ntp.org
ntp.ubuntu.com

# Regional CDN preferences
# Use Australian PoPs where available
```

#### Support and Maintenance
```bash
# Business hours consideration
MAINTENANCE_WINDOW="02:00-04:00 AEDT"
SUPPORT_HOURS="09:00-17:00 AEDT"

# Holiday scheduling
# Consider Australian public holidays
# Plan maintenance around long weekends
```

---

This security guide provides comprehensive coverage of security measures, compliance considerations, and best practices for Australian deployment. Regular review and updates ensure continued protection against evolving threats.