#!/bin/bash
# AdGuard Home Infrastructure - Backup Script
# Comprehensive backup solution with encryption and retention management

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BACKUP_DIR="${BACKUP_LOCATION:-/opt/backups}"
LOG_FILE="/opt/logs/backup.log"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

# Load environment variables
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "${PROJECT_ROOT}/.env"
    set +a
fi

# Backup configuration
BACKUP_DATE=$(date '+%Y%m%d-%H%M%S')
BACKUP_NAME="adguard-backup-${BACKUP_DATE}"
TEMP_BACKUP_DIR="/tmp/${BACKUP_NAME}"
ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-}"

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
    local exit_code=$?
    if [[ -d "$TEMP_BACKUP_DIR" ]]; then
        rm -rf "$TEMP_BACKUP_DIR"
    fi
    if [[ $exit_code -ne 0 ]]; then
        error "Backup failed with exit code $exit_code"
    fi
    exit $exit_code
}
trap cleanup EXIT

# Initialize backup
init_backup() {
    info "Initializing backup process..."

    # Create backup directories
    mkdir -p "$BACKUP_DIR" "$TEMP_BACKUP_DIR" "$(dirname "$LOG_FILE")"

    # Check available disk space
    local available_space
    available_space=$(df "$BACKUP_DIR" | awk 'NR==2 {print $4}')
    local required_space=1048576  # 1GB in KB

    if [[ "$available_space" -lt "$required_space" ]]; then
        error "Insufficient disk space for backup. Available: ${available_space}KB, Required: ${required_space}KB"
        exit 1
    fi

    success "Backup initialization completed"
}

# Backup AdGuard Home configuration and data
backup_adguard() {
    info "Backing up AdGuard Home..."

    local adguard_backup_dir="${TEMP_BACKUP_DIR}/adguard"
    mkdir -p "$adguard_backup_dir"

    # Stop AdGuard temporarily for consistent backup
    info "Stopping AdGuard Home for consistent backup..."
    if docker compose -f "${PROJECT_ROOT}/docker/docker-compose.yml" stop adguard 2>/dev/null; then
        sleep 5  # Wait for graceful shutdown
    else
        warn "Could not stop AdGuard container gracefully"
    fi

    # Backup AdGuard data
    if [[ -d "/opt/adguard" ]]; then
        cp -r /opt/adguard/* "$adguard_backup_dir/" 2>/dev/null || true
        success "AdGuard data backed up"
    else
        warn "AdGuard data directory not found"
    fi

    # Backup Docker volumes
    if docker volume ls | grep -q adguard; then
        info "Backing up Docker volumes..."
        docker run --rm \
            -v adguard-data:/data \
            -v "${adguard_backup_dir}:/backup" \
            alpine tar czf /backup/adguard-volumes.tar.gz -C /data . 2>/dev/null || true
    fi

    # Restart AdGuard
    info "Restarting AdGuard Home..."
    docker compose -f "${PROJECT_ROOT}/docker/docker-compose.yml" start adguard >/dev/null 2>&1 || true

    # Wait for service to be ready
    local retry_count=0
    while [[ $retry_count -lt 30 ]]; do
        if curl -s -f "http://localhost:${ADGUARD_WEB_PORT:-3000}/" >/dev/null 2>&1; then
            success "AdGuard Home restarted successfully"
            break
        fi
        sleep 2
        ((retry_count++))
    done

    if [[ $retry_count -ge 30 ]]; then
        warn "AdGuard Home may not have restarted properly"
    fi
}

# Backup monitoring data
backup_monitoring() {
    info "Backing up monitoring data..."

    local monitoring_backup_dir="${TEMP_BACKUP_DIR}/monitoring"
    mkdir -p "$monitoring_backup_dir"

    # Backup Prometheus data
    if [[ -d "/opt/monitoring/prometheus" ]]; then
        cp -r /opt/monitoring/prometheus "$monitoring_backup_dir/" 2>/dev/null || true
    fi

    # Backup Grafana data
    if [[ -d "/opt/monitoring/grafana" ]]; then
        cp -r /opt/monitoring/grafana "$monitoring_backup_dir/" 2>/dev/null || true
    fi

    # Backup Alertmanager data
    if [[ -d "/opt/monitoring/alertmanager" ]]; then
        cp -r /opt/monitoring/alertmanager "$monitoring_backup_dir/" 2>/dev/null || true
    fi

    # Export Grafana dashboards
    if curl -s -f "http://localhost:${GRAFANA_PORT:-3001}/api/health" >/dev/null 2>&1; then
        info "Exporting Grafana dashboards..."
        mkdir -p "${monitoring_backup_dir}/grafana-exports"

        # Get dashboard UIDs
        local dashboards
        dashboards=$(curl -s -H "Content-Type: application/json" \
            "http://admin:${GRAFANA_ADMIN_PASSWORD}@localhost:${GRAFANA_PORT:-3001}/api/search?type=dash-db" 2>/dev/null | \
            jq -r '.[].uid' 2>/dev/null || echo "")

        for uid in $dashboards; do
            if [[ -n "$uid" && "$uid" != "null" ]]; then
                curl -s -H "Content-Type: application/json" \
                    "http://admin:${GRAFANA_ADMIN_PASSWORD}@localhost:${GRAFANA_PORT:-3001}/api/dashboards/uid/${uid}" \
                    > "${monitoring_backup_dir}/grafana-exports/dashboard-${uid}.json" 2>/dev/null || true
            fi
        done
    fi

    success "Monitoring data backed up"
}

# Backup system configuration
backup_system_config() {
    info "Backing up system configuration..."

    local config_backup_dir="${TEMP_BACKUP_DIR}/system-config"
    mkdir -p "$config_backup_dir"

    # Configuration files to backup
    local config_files=(
        "/etc/ssh/sshd_config"
        "/etc/ufw"
        "/etc/fail2ban"
        "/etc/systemd/system/adguard.service"
        "/etc/cron.d/adguard-maintenance"
        "/etc/logrotate.d/adguard"
        "/etc/sysctl.d/99-adguard.conf"
        "/etc/apt/apt.conf.d/50unattended-upgrades"
    )

    for config_path in "${config_files[@]}"; do
        if [[ -e "$config_path" ]]; then
            local dest_path="${config_backup_dir}${config_path}"
            mkdir -p "$(dirname "$dest_path")"
            cp -r "$config_path" "$dest_path" 2>/dev/null || true
        fi
    done

    # Backup network configuration
    if [[ -f "/etc/netplan/01-netcfg.yaml" ]]; then
        cp "/etc/netplan/01-netcfg.yaml" "${config_backup_dir}/netplan.yaml" 2>/dev/null || true
    fi

    # Backup environment variables
    if [[ -f "${PROJECT_ROOT}/.env" ]]; then
        cp "${PROJECT_ROOT}/.env" "${config_backup_dir}/environment.env" 2>/dev/null || true
    fi

    success "System configuration backed up"
}

# Backup Docker configuration
backup_docker_config() {
    info "Backing up Docker configuration..."

    local docker_backup_dir="${TEMP_BACKUP_DIR}/docker-config"
    mkdir -p "$docker_backup_dir"

    # Backup Docker Compose files
    if [[ -d "${PROJECT_ROOT}/docker" ]]; then
        cp -r "${PROJECT_ROOT}/docker" "$docker_backup_dir/" 2>/dev/null || true
    fi

    # Backup Docker daemon configuration
    if [[ -f "/etc/docker/daemon.json" ]]; then
        cp "/etc/docker/daemon.json" "${docker_backup_dir}/daemon.json" 2>/dev/null || true
    fi

    # Export Docker images list
    docker images --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}" > "${docker_backup_dir}/images-list.txt" 2>/dev/null || true

    # Export container information
    docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" > "${docker_backup_dir}/containers-list.txt" 2>/dev/null || true

    success "Docker configuration backed up"
}

# Backup logs and reports
backup_logs() {
    info "Backing up logs and reports..."

    local logs_backup_dir="${TEMP_BACKUP_DIR}/logs"
    mkdir -p "$logs_backup_dir"

    # System logs
    local log_files=(
        "/var/log/syslog"
        "/var/log/auth.log"
        "/var/log/ufw.log"
        "/var/log/fail2ban.log"
    )

    for log_file in "${log_files[@]}"; do
        if [[ -f "$log_file" ]]; then
            cp "$log_file" "${logs_backup_dir}/$(basename "$log_file")" 2>/dev/null || true
        fi
    done

    # Application logs
    if [[ -d "/opt/logs" ]]; then
        cp -r /opt/logs/* "$logs_backup_dir/" 2>/dev/null || true
    fi

    # Reports
    if [[ -d "/opt/reports" ]]; then
        cp -r /opt/reports "${logs_backup_dir}/" 2>/dev/null || true
    fi

    success "Logs and reports backed up"
}

# Create system information snapshot
create_system_snapshot() {
    info "Creating system information snapshot..."

    local snapshot_file="${TEMP_BACKUP_DIR}/system-snapshot.txt"

    {
        echo "AdGuard Home Infrastructure - System Snapshot"
        echo "Generated: $(date)"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -a)"
        echo "Distribution: $(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown")"
        echo
        echo "=== Network Configuration ==="
        ip addr show 2>/dev/null || true
        echo
        echo "=== Docker Status ==="
        docker version 2>/dev/null || echo "Docker not available"
        docker compose version 2>/dev/null || echo "Docker Compose not available"
        echo
        echo "=== Running Containers ==="
        docker ps 2>/dev/null || echo "Cannot list containers"
        echo
        echo "=== System Resources ==="
        echo "Memory:"
        free -h 2>/dev/null || true
        echo "Disk:"
        df -h 2>/dev/null || true
        echo "Load:"
        uptime 2>/dev/null || true
        echo
        echo "=== Firewall Status ==="
        ufw status verbose 2>/dev/null || echo "UFW status unavailable"
        echo
        echo "=== Fail2ban Status ==="
        fail2ban-client status 2>/dev/null || echo "Fail2ban status unavailable"
        echo
        echo "=== Systemd Services ==="
        systemctl list-units --type=service --state=active | grep -E "(docker|adguard|ssh|ufw|fail2ban)" 2>/dev/null || true
    } > "$snapshot_file"

    success "System snapshot created"
}

# Compress and encrypt backup
create_backup_archive() {
    info "Creating backup archive..."

    local archive_file="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"

    # Create compressed archive
    tar -czf "$archive_file" -C "$(dirname "$TEMP_BACKUP_DIR")" "$(basename "$TEMP_BACKUP_DIR")"

    # Encrypt if encryption key is provided
    if [[ -n "$ENCRYPTION_KEY" ]]; then
        info "Encrypting backup..."
        openssl enc -aes-256-cbc -salt -in "$archive_file" -out "${archive_file}.enc" -k "$ENCRYPTION_KEY"
        rm "$archive_file"
        archive_file="${archive_file}.enc"
        success "Backup encrypted"
    fi

    # Calculate and store checksum
    sha256sum "$archive_file" > "${archive_file}.sha256"

    # Get backup size
    local backup_size
    backup_size=$(stat -c%s "$archive_file" 2>/dev/null | numfmt --to=iec-i --suffix=B 2>/dev/null || echo "unknown")

    success "Backup archive created: $(basename "$archive_file") (${backup_size})"
    info "Backup location: $archive_file"

    # Store backup metadata
    local metadata_file="${BACKUP_DIR}/${BACKUP_NAME}.metadata.json"
    {
        echo "{"
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"hostname\": \"$(hostname)\","
        echo "  \"backup_name\": \"$BACKUP_NAME\","
        echo "  \"archive_file\": \"$(basename "$archive_file")\","
        echo "  \"size_bytes\": $(stat -f%z "$archive_file" 2>/dev/null || stat -c%s "$archive_file"),"
        echo "  \"size_human\": \"$backup_size\","
        echo "  \"encrypted\": $(if [[ -n "$ENCRYPTION_KEY" ]]; then echo "true"; else echo "false"; fi),"
        echo "  \"checksum\": \"$(cut -d' ' -f1 "${archive_file}.sha256")\","
        echo "  \"components\": ["
        echo "    \"adguard_data\","
        echo "    \"monitoring_data\","
        echo "    \"system_config\","
        echo "    \"docker_config\","
        echo "    \"logs_reports\","
        echo "    \"system_snapshot\""
        echo "  ]"
        echo "}"
    } > "$metadata_file"
}

# Clean up old backups
cleanup_old_backups() {
    info "Cleaning up old backups (retention: ${RETENTION_DAYS} days)..."

    local deleted_count=0

    # Find and delete old backup files
    while IFS= read -r -d '' file; do
        rm -f "$file"
        ((deleted_count++))
    done < <(find "$BACKUP_DIR" -name "adguard-backup-*.tar.gz*" -type f -mtime +"${RETENTION_DAYS}" -print0 2>/dev/null)

    # Clean up metadata files
    find "$BACKUP_DIR" -name "adguard-backup-*.metadata.json" -type f -mtime +"${RETENTION_DAYS}" -delete 2>/dev/null || true

    if [[ $deleted_count -gt 0 ]]; then
        info "Deleted $deleted_count old backup files"
    else
        info "No old backups to clean up"
    fi

    # Show current backup statistics
    local total_backups
    local total_size

    total_backups=$(find "$BACKUP_DIR" -name "adguard-backup-*.tar.gz*" -type f | wc -l)
    total_size=$(find "$BACKUP_DIR" -name "adguard-backup-*.tar.gz*" -type f -exec ls -ln {} \; | awk '{sum += $5} END {print sum}' || echo "0")

    info "Current backup statistics: $total_backups backups, $(numfmt --to=iec "$total_size" 2>/dev/null || echo "$total_size bytes") total size"
}

# Verify backup integrity
verify_backup() {
    local archive_file
    if [[ -n "$ENCRYPTION_KEY" ]]; then
        archive_file="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz.enc"
    else
        archive_file="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
    fi

    info "Verifying backup integrity..."

    # Verify checksum
    if [[ -f "${archive_file}.sha256" ]]; then
        if sha256sum -c "${archive_file}.sha256" >/dev/null 2>&1; then
            success "Backup checksum verification passed"
        else
            error "Backup checksum verification failed!"
            return 1
        fi
    else
        warn "No checksum file found for verification"
    fi

    # Test archive integrity
    if [[ -n "$ENCRYPTION_KEY" ]]; then
        # Test encrypted archive
        if openssl enc -aes-256-cbc -d -in "$archive_file" -k "$ENCRYPTION_KEY" | tar -tzf - >/dev/null 2>&1; then
            success "Encrypted backup archive integrity verified"
        else
            error "Encrypted backup archive integrity check failed!"
            return 1
        fi
    else
        # Test regular archive
        if tar -tzf "$archive_file" >/dev/null 2>&1; then
            success "Backup archive integrity verified"
        else
            error "Backup archive integrity check failed!"
            return 1
        fi
    fi

    return 0
}

# Send backup notification
send_notification() {
    local status=$1
    local message=$2

    if [[ -n "${ADMIN_EMAIL:-}" ]] && command -v mail >/dev/null 2>&1; then
        local subject
        if [[ "$status" == "success" ]]; then
            subject="[AdGuard] Backup Completed Successfully"
        else
            subject="[AdGuard] Backup Failed"
        fi

        {
            echo "AdGuard Home Infrastructure Backup Report"
            echo "=========================================="
            echo
            echo "Status: $status"
            echo "Timestamp: $(date)"
            echo "Hostname: $(hostname)"
            echo "Backup Name: $BACKUP_NAME"
            echo
            echo "Message: $message"
            echo
            if [[ "$status" == "success" ]]; then
                echo "Backup Details:"
                echo "- Location: $BACKUP_DIR"
                echo "- Retention: $RETENTION_DAYS days"
                if [[ -n "$ENCRYPTION_KEY" ]]; then
                    echo "- Encryption: Enabled"
                fi
            fi
            echo
            echo "Log file: $LOG_FILE"
        } | mail -s "$subject" "$ADMIN_EMAIL"
    fi

    # Log to syslog
    logger -t "adguard-backup" "$status: $message"
}

# Main backup function
main() {
    info "Starting AdGuard Home infrastructure backup..."

    local start_time
    start_time=$(date +%s)

    # Initialize backup environment
    init_backup

    # Perform backup operations
    backup_adguard
    backup_monitoring
    backup_system_config
    backup_docker_config
    backup_logs
    create_system_snapshot

    # Create final archive
    create_backup_archive

    # Verify backup integrity
    if verify_backup; then
        success "Backup verification passed"
    else
        error "Backup verification failed"
        send_notification "failed" "Backup verification failed"
        exit 1
    fi

    # Clean up old backups
    cleanup_old_backups

    # Calculate backup duration
    local end_time duration
    end_time=$(date +%s)
    duration=$((end_time - start_time))

    success "Backup completed successfully in ${duration} seconds"
    send_notification "success" "Backup completed successfully in ${duration} seconds"

    return 0
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi