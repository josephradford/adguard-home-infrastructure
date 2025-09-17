#!/bin/bash
# AdGuard Home Infrastructure - Complete Installation Script
# Automated deployment for Australian home network DNS filtering

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_FILE="/opt/logs/adguard-install.log"
BACKUP_DIR="/opt/backups"
DATA_DIR="/opt/adguard"
MONITORING_DIR="/opt/monitoring"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${LOG_FILE}"
}

info() { log "INFO" "${BLUE}$*${NC}"; }
warn() { log "WARN" "${YELLOW}$*${NC}"; }
error() { log "ERROR" "${RED}$*${NC}"; }
success() { log "SUCCESS" "${GREEN}$*${NC}"; }

# Error handling
cleanup() {
    if [[ $? -ne 0 ]]; then
        error "Installation failed. Check logs at ${LOG_FILE}"
        error "You can retry installation by running: make install"
    fi
}
trap cleanup EXIT

# Requirements check
check_requirements() {
    info "Checking system requirements..."

    # Check if running as root or with sudo access
    if [[ $EUID -eq 0 ]]; then
        warn "Running as root. This is not recommended for security reasons."
    elif ! sudo -n true 2>/dev/null; then
        error "This script requires sudo access. Please run with sudo or add user to sudoers."
        exit 1
    fi

    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect OS. This script is designed for Ubuntu 24.04 LTS."
        exit 1
    fi

    # shellcheck source=/dev/null
    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]] || [[ "$VERSION_ID" != "24.04" ]]; then
        error "This script requires Ubuntu 24.04 LTS. Current OS: $PRETTY_NAME"
        exit 1
    fi

    # Check architecture
    if [[ "$(uname -m)" != "x86_64" ]]; then
        warn "This script is optimized for x86_64 architecture. Current: $(uname -m)"
    fi

    success "System requirements check passed"
}

# Create directories
create_directories() {
    info "Creating directory structure..."

    sudo mkdir -p "${DATA_DIR}"/{data,logs,work,conf}
    sudo mkdir -p "${MONITORING_DIR}"/{prometheus,grafana,alertmanager}
    sudo mkdir -p "${BACKUP_DIR}"
    sudo mkdir -p /opt/logs
    sudo mkdir -p /opt/scripts

    # Set ownership
    sudo chown -R "${USER}:${USER}" /opt/adguard /opt/monitoring /opt/backups /opt/logs /opt/scripts

    success "Directory structure created"
}

# Install Docker from official repository
install_docker() {
    info "Installing Docker..."

    # Remove any existing Docker installations
    sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

    # Add Docker's official GPG key
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

    # Add Docker repository
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
        $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Update package index
    sudo apt-get update

    # Install Docker Engine, CLI, containerd, and Docker Compose plugin
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    # Add user to docker group
    sudo usermod -aG docker "${USER}"

    # Start and enable Docker service
    sudo systemctl start docker
    sudo systemctl enable docker

    # Test Docker installation
    if sudo docker run --rm hello-world >/dev/null 2>&1; then
        success "Docker installed successfully"
    else
        warn "Docker installed but test failed - may require logout/login"
    fi
}

# Install system packages
install_packages() {
    info "Installing system packages..."

    # Update package index
    sudo apt-get update

    # Install basic packages first
    sudo apt-get install -y \
        curl \
        wget \
        git \
        htop \
        vim \
        unzip \
        ufw \
        fail2ban \
        certbot \
        python3-certbot-dns-cloudflare \
        rsync \
        logrotate \
        cron \
        ntp \
        unattended-upgrades \
        apt-listchanges \
        needrestart \
        rkhunter \
        chkrootkit \
        aide \
        lynis \
        tree \
        jq \
        shellcheck \
        yamllint \
        ca-certificates \
        gnupg \
        lsb-release \
        apache2-utils

    # Install Docker using official repository
    install_docker

    success "System packages installed"
}

# Configure environment
setup_environment() {
    info "Setting up environment configuration..."

    # Copy environment template if .env doesn't exist
    if [[ ! -f "${PROJECT_ROOT}/.env" ]]; then
        cp "${PROJECT_ROOT}/.env.example" "${PROJECT_ROOT}/.env"
        warn "Environment file created from template at ${PROJECT_ROOT}/.env"
        warn "Please edit this file with your specific configuration before continuing"

        # Generate secure passwords
        local adguard_password
        local grafana_password
        local grafana_secret

        adguard_password=$(openssl rand -base64 32)
        grafana_password=$(openssl rand -base64 32)
        grafana_secret=$(openssl rand -base64 32)

        # Update .env file with generated passwords
        sed -i "s/ADGUARD_PASSWORD=change_this_password/ADGUARD_PASSWORD=${adguard_password}/" "${PROJECT_ROOT}/.env"
        sed -i "s/GRAFANA_ADMIN_PASSWORD=change_this_password/GRAFANA_ADMIN_PASSWORD=${grafana_password}/" "${PROJECT_ROOT}/.env"
        sed -i "s/GRAFANA_SECRET_KEY=change_this_secret/GRAFANA_SECRET_KEY=${grafana_secret}/" "${PROJECT_ROOT}/.env"

        info "Generated secure passwords for AdGuard and Grafana"
        info "AdGuard Password: ${adguard_password}"
        info "Grafana Password: ${grafana_password}"
        warn "Save these passwords securely!"
    fi

    # Load environment variables
    if [[ -f "${PROJECT_ROOT}/.env" ]]; then
        set -a
        # shellcheck source=/dev/null
        source "${PROJECT_ROOT}/.env"
        set +a
    else
        error "Environment file not found at ${PROJECT_ROOT}/.env"
        exit 1
    fi

    success "Environment configuration loaded"
}

# Configure security
configure_security() {
    info "Configuring security hardening..."

    # Configure UFW firewall
    sudo ufw --force reset
    sudo ufw default deny incoming
    sudo ufw default allow outgoing

    # Allow essential services
    sudo ufw allow "${SSH_PORT:-2222}/tcp" comment 'SSH'
    sudo ufw allow 53/tcp comment 'DNS TCP'
    sudo ufw allow 53/udp comment 'DNS UDP'
    sudo ufw allow 3000/tcp comment 'AdGuard Web'

    # Allow monitoring from local network
    sudo ufw allow from 192.168.0.0/16 to any port 9090 comment 'Prometheus'
    sudo ufw allow from 192.168.0.0/16 to any port 3001 comment 'Grafana'
    sudo ufw allow from 192.168.0.0/16 to any port 9093 comment 'Alertmanager'

    sudo ufw --force enable

    # Configure fail2ban
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban

    # Copy fail2ban configuration
    if [[ -f "${PROJECT_ROOT}/configs/fail2ban/jail.d/adguard.conf" ]]; then
        sudo cp "${PROJECT_ROOT}/configs/fail2ban/jail.d/adguard.conf" /etc/fail2ban/jail.d/
        sudo systemctl restart fail2ban
    fi

    # Enable automatic security updates
    sudo systemctl enable unattended-upgrades
    echo 'Unattended-Upgrade::Automatic-Reboot "false";' | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades

    # Initialize AIDE
    if command -v aide >/dev/null 2>&1; then
        sudo aideinit
        sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
    fi

    success "Security hardening configured"
}

# Deploy Docker containers
deploy_containers() {
    info "Deploying Docker containers..."

    cd "${PROJECT_ROOT}/docker"

    # Create data directories with proper permissions
    mkdir -p data/{adguard/{work,conf},prometheus,grafana,alertmanager}

    # Copy configuration files
    cp -r configs/* data/

    # Generate AdGuard configuration with proper password hash
    if [[ -n "${ADGUARD_PASSWORD:-}" ]]; then
        local password_hash
        password_hash=$(htpasswd -bnBC 10 "" "${ADGUARD_PASSWORD}" | tr -d ':\n' | sed 's/^[^$]*//')
        sed -i "s|\$2a\$10\$example_hash_replace_this|${password_hash}|" data/adguard/AdGuardHome.yaml
    fi

    # Pull latest images
    docker compose pull

    # Start services
    docker compose up -d

    # Wait for services to be ready
    info "Waiting for services to start..."
    sleep 30

    # Verify services are running
    if docker compose ps | grep -q "Up"; then
        success "Docker containers deployed successfully"
    else
        error "Some containers failed to start"
        docker compose logs
        exit 1
    fi
}

# Install monitoring scripts
install_scripts() {
    info "Installing operational scripts..."

    # Copy scripts to system location
    sudo cp -r "${PROJECT_ROOT}/scripts"/* /opt/scripts/
    sudo chmod +x /opt/scripts/**/*.sh

    # Install cron jobs for monitoring and maintenance
    {
        echo "# AdGuard Home Infrastructure Maintenance"
        echo "0 2 * * * ${USER} /opt/scripts/backup/backup.sh"
        echo "*/15 * * * * ${USER} /opt/scripts/monitoring/comprehensive-monitor.sh"
        echo "0 3 * * 0 ${USER} /opt/scripts/maintenance/update.sh"
        echo "0 1 * * * root /usr/bin/aide --check"
    } | sudo tee /etc/cron.d/adguard-maintenance

    success "Operational scripts installed"
}

# Configure system optimizations
configure_system() {
    info "Applying system optimizations..."

    # Copy sysctl optimizations
    if [[ -f "${PROJECT_ROOT}/configs/sysctl/99-adguard.conf" ]]; then
        sudo cp "${PROJECT_ROOT}/configs/sysctl/99-adguard.conf" /etc/sysctl.d/
        sudo sysctl -p /etc/sysctl.d/99-adguard.conf
    fi

    # Configure log rotation
    sudo cp "${PROJECT_ROOT}/configs/logrotate/adguard" /etc/logrotate.d/

    # Configure systemd service (if provided)
    if [[ -f "${PROJECT_ROOT}/configs/systemd/adguard.service" ]]; then
        sudo cp "${PROJECT_ROOT}/configs/systemd/adguard.service" /etc/systemd/system/
        sudo systemctl daemon-reload
        sudo systemctl enable adguard.service
    fi

    success "System optimizations applied"
}

# Verify installation
verify_installation() {
    info "Verifying installation..."

    local errors=0

    # Check if containers are running
    if ! docker compose -f "${PROJECT_ROOT}/docker/docker-compose.yml" ps | grep -q "Up"; then
        error "Some Docker containers are not running"
        ((errors++))
    fi

    # Check if AdGuard is responding
    if ! curl -f -s "http://localhost:3000/" >/dev/null; then
        error "AdGuard Home web interface is not accessible"
        ((errors++))
    fi

    # Check DNS resolution
    if ! dig @localhost google.com >/dev/null 2>&1; then
        error "DNS resolution is not working"
        ((errors++))
    fi

    # Check if monitoring is working
    if ! curl -f -s "http://localhost:9090/-/healthy" >/dev/null; then
        error "Prometheus is not healthy"
        ((errors++))
    fi

    if ! curl -f -s "http://localhost:3001/api/health" >/dev/null; then
        error "Grafana is not healthy"
        ((errors++))
    fi

    if [[ $errors -eq 0 ]]; then
        success "Installation verification passed"
        return 0
    else
        error "Installation verification failed with $errors errors"
        return 1
    fi
}

# Display success information
show_completion_info() {
    info "Installation completed successfully!"
    echo
    echo "=========================================="
    echo "AdGuard Home Infrastructure is now ready!"
    echo "=========================================="
    echo
    echo "Access URLs:"
    echo "  AdGuard Home:  http://192.168.1.100:3000"
    echo "  Grafana:       http://192.168.1.100:3001"
    echo "  Prometheus:    http://192.168.1.100:9090"
    echo "  Alertmanager:  http://192.168.1.100:9093"
    echo
    echo "Credentials:"
    echo "  AdGuard Home:  admin / [check .env file]"
    echo "  Grafana:       admin / [check .env file]"
    echo
    echo "Next steps:"
    echo "  1. Access AdGuard Home and complete initial setup"
    echo "  2. Configure your router to use 192.168.1.100 as DNS server"
    echo "  3. Import Grafana dashboards for monitoring"
    echo "  4. Test DNS resolution and ad blocking"
    echo
    echo "Maintenance commands:"
    echo "  make health    - Check system health"
    echo "  make backup    - Create backup"
    echo "  make update    - Update containers"
    echo "  make logs      - View logs"
    echo
    echo "Documentation: ${PROJECT_ROOT}/docs/"
    echo "Logs: ${LOG_FILE}"
    echo
}

# Main installation function
main() {
    # Create log directory first (before any logging)
    sudo mkdir -p "$(dirname "${LOG_FILE}")"
    sudo chown "${USER}:${USER}" "$(dirname "${LOG_FILE}")"

    info "Starting AdGuard Home Infrastructure installation..."
    info "Installation log: ${LOG_FILE}"

    # Run installation steps
    check_requirements
    create_directories
    install_packages
    setup_environment
    configure_security
    deploy_containers
    install_scripts
    configure_system

    # Verify installation
    if verify_installation; then
        show_completion_info
        success "Installation completed successfully!"
    else
        error "Installation completed with errors. Please check the logs."
        exit 1
    fi
}

# Run main function
main "$@"