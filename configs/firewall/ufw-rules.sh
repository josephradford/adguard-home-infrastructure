#!/bin/bash
# AdGuard Home Infrastructure - UFW Firewall Configuration
# Security-hardened firewall rules for Australian home network

set -euo pipefail

# Configuration
LOG_FILE="/opt/logs/firewall-config.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${LOG_FILE}"
}

info() { log "INFO" "${BLUE}$*${NC}"; }
warn() { log "WARN" "${YELLOW}$*${NC}"; }
error() { log "ERROR" "${RED}$*${NC}"; }
success() { log "SUCCESS" "${GREEN}$*${NC}"; }

# Load environment variables if available
if [[ -f "/opt/adguard/.env" ]]; then
    set -a
    source "/opt/adguard/.env"
    set +a
fi

# Default values
SSH_PORT=${SSH_PORT:-2222}
ADGUARD_WEB_PORT=${ADGUARD_WEB_PORT:-3000}
GRAFANA_PORT=${GRAFANA_PORT:-3001}
PROMETHEUS_PORT=${PROMETHEUS_PORT:-9090}

configure_ufw() {
    info "Configuring UFW firewall for AdGuard Home infrastructure..."

    # Reset UFW to defaults
    sudo ufw --force reset

    # Set default policies
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw default deny forward

    # Enable logging
    sudo ufw logging on

    info "Basic UFW policies configured"

    # === ESSENTIAL SERVICES ===

    # SSH access (custom port for security)
    sudo ufw allow "${SSH_PORT}/tcp" comment 'SSH (custom port)'
    info "SSH access allowed on port ${SSH_PORT}"

    # DNS services (TCP and UDP on port 53)
    sudo ufw allow 53/tcp comment 'DNS TCP'
    sudo ufw allow 53/udp comment 'DNS UDP'
    info "DNS services allowed on port 53"

    # DNS over TLS (DoT)
    sudo ufw allow 853/tcp comment 'DNS over TLS'
    sudo ufw allow 853/udp comment 'DNS over TLS'
    info "DNS over TLS allowed on port 853"

    # === WEB INTERFACES ===

    # AdGuard Home web interface (restricted to local network)
    sudo ufw allow from 192.168.0.0/16 to any port "${ADGUARD_WEB_PORT}" comment 'AdGuard Web (LAN only)'
    sudo ufw allow from 10.0.0.0/8 to any port "${ADGUARD_WEB_PORT}" comment 'AdGuard Web (private)'
    sudo ufw allow from 172.16.0.0/12 to any port "${ADGUARD_WEB_PORT}" comment 'AdGuard Web (private)'
    info "AdGuard web interface restricted to private networks"

    # === MONITORING SERVICES (LAN ONLY) ===

    # Prometheus (metrics collection)
    sudo ufw allow from 192.168.0.0/16 to any port "${PROMETHEUS_PORT}" comment 'Prometheus (LAN only)'
    sudo ufw allow from 10.0.0.0/8 to any port "${PROMETHEUS_PORT}" comment 'Prometheus (private)'
    info "Prometheus access restricted to private networks"

    # Grafana (dashboards)
    sudo ufw allow from 192.168.0.0/16 to any port "${GRAFANA_PORT}" comment 'Grafana (LAN only)'
    sudo ufw allow from 10.0.0.0/8 to any port "${GRAFANA_PORT}" comment 'Grafana (private)'
    info "Grafana access restricted to private networks"

    # Alertmanager
    sudo ufw allow from 192.168.0.0/16 to any port 9093 comment 'Alertmanager (LAN only)'
    info "Alertmanager access restricted to private networks"

    # Node Exporter (system metrics)
    sudo ufw allow from 192.168.0.0/16 to any port 9100 comment 'Node Exporter (LAN only)'
    info "Node Exporter access restricted to private networks"

    # AdGuard Exporter
    sudo ufw allow from 192.168.0.0/16 to any port 9617 comment 'AdGuard Exporter (LAN only)'
    info "AdGuard Exporter access restricted to private networks"

    # === LOOPBACK INTERFACE ===
    sudo ufw allow in on lo comment 'Loopback interface'
    sudo ufw allow out on lo comment 'Loopback interface'
    info "Loopback interface allowed"

    # === ICMP (for ping and traceroute) ===
    sudo ufw allow in proto icmp comment 'ICMP (ping)'
    info "ICMP (ping) allowed"

    # === DOCKER NETWORKING ===
    # Allow Docker internal networking
    sudo ufw allow in on docker0 comment 'Docker bridge'
    sudo ufw allow out on docker0 comment 'Docker bridge'
    info "Docker networking allowed"

    # === RATE LIMITING ===
    # Rate limit SSH connections (6 connections per 30 seconds)
    sudo ufw limit "${SSH_PORT}/tcp" comment 'SSH rate limiting'
    info "SSH rate limiting enabled"

    # Rate limit DNS queries from external sources
    sudo ufw limit from any to any port 53 comment 'DNS rate limiting'
    info "DNS rate limiting enabled"

    # === SECURITY RULES ===

    # Block common attack vectors
    sudo ufw deny from 0.0.0.0/8 comment 'Block invalid source'
    sudo ufw deny from 127.0.0.0/8 comment 'Block loopback from external'
    sudo ufw deny from 169.254.0.0/16 comment 'Block link-local'
    sudo ufw deny from 224.0.0.0/4 comment 'Block multicast'
    sudo ufw deny from 240.0.0.0/5 comment 'Block reserved'
    info "Security rules for invalid sources configured"

    # Block known malicious ports
    local malicious_ports=(
        "135/tcp"   # Windows RPC
        "139/tcp"   # NetBIOS
        "445/tcp"   # SMB
        "1433/tcp"  # MSSQL
        "1521/tcp"  # Oracle
        "3389/tcp"  # RDP
        "5432/tcp"  # PostgreSQL
        "3306/tcp"  # MySQL
        "6379/tcp"  # Redis
        "27017/tcp" # MongoDB
    )

    for port in "${malicious_ports[@]}"; do
        sudo ufw deny "${port}" comment "Block ${port} (security)"
    done
    info "Malicious ports blocked"

    # === AUSTRALIAN SPECIFIC RULES ===

    # Allow Australian government services (optional)
    # These can be uncommented if you need access to government services
    # sudo ufw allow out to gov.au port 443 comment 'Australian Government HTTPS'
    # sudo ufw allow out to ato.gov.au port 443 comment 'Australian Tax Office'
    # sudo ufw allow out to centrelink.gov.au port 443 comment 'Centrelink'

    # Allow major Australian ISP DNS servers as backup
    sudo ufw allow out to 1.1.1.1 port 53 comment 'Cloudflare DNS (Sydney PoP)'
    sudo ufw allow out to 1.0.0.1 port 53 comment 'Cloudflare DNS (Sydney PoP)'
    sudo ufw allow out to 8.8.8.8 port 53 comment 'Google DNS (Sydney PoP)'
    sudo ufw allow out to 8.8.4.4 port 53 comment 'Google DNS (Sydney PoP)'
    sudo ufw allow out to 9.9.9.9 port 53 comment 'Quad9 DNS'
    info "Australian-optimized DNS servers allowed"

    # === APPLICATION-SPECIFIC RULES ===

    # Allow NTP for time synchronization
    sudo ufw allow out 123/udp comment 'NTP time sync'
    info "NTP time synchronization allowed"

    # Allow HTTPS for updates and external services
    sudo ufw allow out 443/tcp comment 'HTTPS outbound'
    sudo ufw allow out 80/tcp comment 'HTTP outbound'
    info "Web traffic (HTTP/HTTPS) allowed outbound"

    # Enable UFW
    sudo ufw --force enable

    success "UFW firewall configuration completed"
}

# Configure advanced UFW settings
configure_advanced_settings() {
    info "Configuring advanced UFW settings..."

    # UFW configuration file tweaks
    local ufw_conf="/etc/ufw/ufw.conf"

    if [[ -f "$ufw_conf" ]]; then
        # Enable logging
        sudo sed -i 's/LOGLEVEL=.*/LOGLEVEL=medium/' "$ufw_conf"

        # Set default forward policy
        sudo sed -i 's/DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="DROP"/' "$ufw_conf"

        info "UFW configuration file updated"
    fi

    # Configure before rules for additional security
    local before_rules="/etc/ufw/before.rules"

    if [[ -f "$before_rules" ]]; then
        # Backup original file
        sudo cp "$before_rules" "${before_rules}.backup.$(date +%Y%m%d)"

        # Add custom rules at the beginning
        local temp_file="/tmp/ufw_before_rules"
        cat > "$temp_file" << 'EOF'
# Custom security rules for AdGuard Home infrastructure

# Drop INVALID packets
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP

# Rate limit ICMP
-A ufw-before-input -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 1 -j ACCEPT

# Block common attack patterns
-A ufw-before-input -p tcp --dport 22 -m string --string "root" --algo bm -j DROP
-A ufw-before-input -p tcp --dport 22 -m string --string "admin" --algo bm -j DROP

# SYN flood protection
-A ufw-before-input -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT

EOF

        # Append original content
        tail -n +2 "$before_rules" >> "$temp_file"

        # Replace original file
        sudo mv "$temp_file" "$before_rules"

        info "Advanced security rules added to before.rules"
    fi

    # Configure sysctl for network security
    local sysctl_conf="/etc/sysctl.d/99-ufw-security.conf"

    sudo tee "$sysctl_conf" > /dev/null << 'EOF'
# UFW Security enhancements for AdGuard Home

# IP Spoofing protection
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP ping requests
# net.ipv4.icmp_echo_ignore_all = 1

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# TCP window scaling
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 0

# Protect against time-wait assassination
net.ipv4.tcp_rfc1337 = 1
EOF

    # Apply sysctl settings
    sudo sysctl -p "$sysctl_conf" >/dev/null 2>&1

    success "Advanced UFW security settings configured"
}

# Create UFW application profiles
create_app_profiles() {
    info "Creating UFW application profiles..."

    # AdGuard Home profile
    sudo tee "/etc/ufw/applications.d/adguard-home" > /dev/null << 'EOF'
[AdGuard Home]
title=AdGuard Home DNS Server
description=AdGuard Home DNS filtering and web interface
ports=53,3000/tcp|53/udp

[AdGuard DNS]
title=AdGuard DNS Only
description=DNS service only
ports=53/tcp|53/udp

[AdGuard Web]
title=AdGuard Web Interface
description=Web management interface
ports=3000/tcp

[AdGuard DoT]
title=AdGuard DNS over TLS
description=DNS over TLS service
ports=853/tcp|853/udp
EOF

    # Monitoring stack profile
    sudo tee "/etc/ufw/applications.d/monitoring-stack" > /dev/null << 'EOF'
[Prometheus]
title=Prometheus Monitoring
description=Prometheus metrics collection
ports=9090/tcp

[Grafana]
title=Grafana Dashboard
description=Grafana visualization dashboard
ports=3001/tcp

[Alertmanager]
title=Alertmanager
description=Prometheus Alertmanager
ports=9093/tcp

[Node Exporter]
title=Node Exporter
description=System metrics exporter
ports=9100/tcp

[Monitoring Stack]
title=Complete Monitoring Stack
description=Prometheus, Grafana, and Alertmanager
ports=9090,9093,3001/tcp
EOF

    # Reload UFW application profiles
    sudo ufw app update all

    success "UFW application profiles created"
}

# Display firewall status
show_firewall_status() {
    info "Current UFW firewall status:"
    echo
    sudo ufw status verbose
    echo
    info "UFW application profiles:"
    sudo ufw app list
    echo
    success "Firewall configuration display completed"
}

# Test firewall configuration
test_firewall() {
    info "Testing firewall configuration..."

    local test_errors=0

    # Test SSH port
    if sudo ufw status | grep -q "${SSH_PORT}/tcp.*ALLOW"; then
        success "SSH port ${SSH_PORT} is properly configured"
    else
        error "SSH port ${SSH_PORT} configuration error"
        ((test_errors++))
    fi

    # Test DNS ports
    if sudo ufw status | grep -q "53/tcp.*ALLOW" && sudo ufw status | grep -q "53/udp.*ALLOW"; then
        success "DNS ports are properly configured"
    else
        error "DNS ports configuration error"
        ((test_errors++))
    fi

    # Test monitoring ports restriction
    if sudo ufw status | grep -q "${GRAFANA_PORT}/tcp.*192.168"; then
        success "Monitoring ports are properly restricted to LAN"
    else
        warn "Monitoring ports may not be properly restricted"
    fi

    # Check if UFW is active
    if sudo ufw status | grep -q "Status: active"; then
        success "UFW firewall is active"
    else
        error "UFW firewall is not active"
        ((test_errors++))
    fi

    if [[ $test_errors -eq 0 ]]; then
        success "Firewall configuration test passed"
        return 0
    else
        error "Firewall configuration test failed with $test_errors errors"
        return 1
    fi
}

# Main function
main() {
    info "Starting UFW firewall configuration for AdGuard Home infrastructure..."

    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"

    # Configure basic UFW rules
    configure_ufw

    # Configure advanced settings
    configure_advanced_settings

    # Create application profiles
    create_app_profiles

    # Test configuration
    if test_firewall; then
        success "Firewall configuration completed successfully"
    else
        error "Firewall configuration completed with errors"
        exit 1
    fi

    # Show final status
    show_firewall_status

    info "UFW firewall configuration completed"
    info "Log file: $LOG_FILE"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi