#!/bin/bash
# AdGuard Home Infrastructure - Update Script
# Automated system and container updates with safety checks

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_FILE="/opt/logs/update.log"
BACKUP_BEFORE_UPDATE=true
UPDATE_CONTAINERS=true
UPDATE_SYSTEM=true

# Load environment variables
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
    set -a
    # shellcheck source=./.env
    source "${PROJECT_ROOT}/.env"
    set +a
fi

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
    if [[ $exit_code -ne 0 ]]; then
        error "Update process failed with exit code $exit_code"
        send_notification "failed" "Update process failed"
    fi
    exit $exit_code
}
trap cleanup EXIT

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-backup)
                BACKUP_BEFORE_UPDATE=false
                shift
                ;;
            --containers-only)
                UPDATE_SYSTEM=false
                shift
                ;;
            --system-only)
                UPDATE_CONTAINERS=false
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo
                echo "Options:"
                echo "  --no-backup        Skip backup before update"
                echo "  --containers-only  Update only containers"
                echo "  --system-only      Update only system packages"
                echo "  --help, -h         Show this help message"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

# Check system health before update
check_system_health() {
    info "Checking system health before update..."

    local health_issues=0

    # Check if all containers are running
    if ! docker compose -f "${PROJECT_ROOT}/docker/docker compose.yml" ps | grep -q "Up"; then
        warn "Some containers are not running"
        ((health_issues++))
    fi

    # Check AdGuard health
    if ! curl -s -f "http://localhost:3000/" >/dev/null; then
        warn "AdGuard web interface is not accessible"
        ((health_issues++))
    fi

    # Check DNS resolution
    if ! dig @localhost google.com >/dev/null 2>&1; then
        warn "DNS resolution is not working"
        ((health_issues++))
    fi

    # Check disk space (need at least 2GB free)
    local available_space
    available_space=$(df / | awk 'NR==2 {print $4}')
    if [[ "$available_space" -lt 2097152 ]]; then  # 2GB in KB
        error "Insufficient disk space for update. Available: ${available_space}KB"
        return 1
    fi

    # Check memory usage
    local memory_usage
    memory_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    if [[ "$memory_usage" -gt 90 ]]; then
        warn "High memory usage before update: ${memory_usage}%"
    fi

    if [[ $health_issues -gt 0 ]]; then
        warn "System health check completed with $health_issues issues"
    else
        success "System health check passed"
    fi

    return 0
}

# Create backup before update
create_pre_update_backup() {
    if [[ "$BACKUP_BEFORE_UPDATE" == "true" ]]; then
        info "Creating backup before update..."

        if [[ -x "${PROJECT_ROOT}/scripts/backup/backup.sh" ]]; then
            "${PROJECT_ROOT}/scripts/backup/backup.sh"
            success "Pre-update backup completed"
        else
            error "Backup script not found or not executable"
            return 1
        fi
    else
        info "Skipping pre-update backup (--no-backup specified)"
    fi
}

# Update system packages
update_system_packages() {
    if [[ "$UPDATE_SYSTEM" != "true" ]]; then
        info "Skipping system package updates"
        return 0
    fi

    info "Updating system packages..."

    # Update package index
    sudo apt-get update

    # Check if any packages need updating
    local upgradable_packages
    upgradable_packages=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")

    if [[ "$upgradable_packages" -eq 0 ]]; then
        info "No system packages need updating"
        return 0
    fi

    info "Found $upgradable_packages packages to update"

    # Perform upgrade
    sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

    # Clean up
    sudo apt-get autoremove -y
    sudo apt-get autoclean

    # Check if reboot is required
    if [[ -f "/var/run/reboot-required" ]]; then
        warn "System reboot is required after updates"
        warn "Reboot will be scheduled for 2 AM if no other maintenance is running"

        # Schedule reboot for 2 AM
        echo "shutdown -r 02:00 'Scheduled reboot after system updates'" | sudo at now 2>/dev/null || true
    fi

    success "System packages updated successfully"
}

# Update Docker containers
update_containers() {
    if [[ "$UPDATE_CONTAINERS" != "true" ]]; then
        info "Skipping container updates"
        return 0
    fi

    info "Updating Docker containers..."

    cd "${PROJECT_ROOT}/docker"

    # Get current container images
    local current_images
    current_images=$(docker compose config | grep "image:" | awk '{print $2}' | sort -u)

    info "Current container images:"
    echo "$current_images" | while read -r image; do
        info "  $image"
    done

    # Pull latest images
    info "Pulling latest container images..."
    docker compose pull

    # Check which images were updated
    local updated_images
    updated_images=$(docker images --format "table {{.Repository}}:{{.Tag}}\t{{.CreatedAt}}" | grep "$(date '+%Y-%m-%d')" | awk '{print $1}' || echo "")

    if [[ -n "$updated_images" ]]; then
        info "Updated images found, recreating containers..."

        # Stop containers gracefully
        docker compose down --timeout 30

        # Start containers with new images
        docker compose up -d

        # Wait for services to be ready
        info "Waiting for services to start..."
        sleep 30

        # Verify services are running
        local retry_count=0
        while [[ $retry_count -lt 60 ]]; do
            if docker compose ps | grep -q "Up"; then
                break
            fi
            sleep 5
            ((retry_count++))
        done

        if [[ $retry_count -ge 60 ]]; then
            error "Services did not start properly after update"
            return 1
        fi

        # Clean up old images
        info "Cleaning up old Docker images..."
        docker image prune -f

        success "Containers updated successfully"
    else
        info "No container updates available"
    fi
}

# Update AdGuard Home configurations
update_adguard_config() {
    info "Checking AdGuard Home configuration updates..."

    # Check if there are any configuration updates in the repository
    local config_file="${PROJECT_ROOT}/docker/configs/adguard/AdGuardHome.yaml"
    local running_config="/opt/adguard/conf/AdGuardHome.yaml"

    if [[ -f "$config_file" && -f "$running_config" ]]; then
        # Compare configurations (excluding dynamic fields)
        local config_diff
        config_diff=$(diff -u "$running_config" "$config_file" | grep -v "^@@\|^+++\|^---" | grep "^[+-]" | wc -l || echo "0")

        if [[ "$config_diff" -gt 0 ]]; then
            warn "Configuration differences detected"
            info "Please review and manually update configuration if needed"
        else
            info "AdGuard configuration is up to date"
        fi
    fi
}

# Update filter lists
update_filter_lists() {
    info "Updating AdGuard filter lists..."

    # Use AdGuard API to update filters
    local api_url="http://localhost:3000/control/filtering/refresh"

    if curl -s -X POST "$api_url" >/dev/null 2>&1; then
        success "Filter lists updated successfully"
    else
        warn "Could not update filter lists via API"
    fi
}

# Update monitoring configurations
update_monitoring_configs() {
    info "Updating monitoring configurations..."

    # Check if Prometheus rules need updating
    local rules_dir="${PROJECT_ROOT}/docker/configs/prometheus/rules"
    local running_rules_dir="/opt/monitoring/prometheus/rules"

    if [[ -d "$rules_dir" && -d "$running_rules_dir" ]]; then
        # Copy updated rules
        cp -r "$rules_dir"/* "$running_rules_dir/" 2>/dev/null || true

        # Reload Prometheus configuration
        if curl -s -X POST "http://localhost:9090/-/reload" >/dev/null 2>&1; then
            info "Prometheus configuration reloaded"
        else
            warn "Could not reload Prometheus configuration"
        fi
    fi

    # Update Grafana dashboards
    local dashboards_dir="${PROJECT_ROOT}/docker/configs/grafana/dashboards"
    local running_dashboards_dir="/opt/monitoring/grafana/dashboards"

    if [[ -d "$dashboards_dir" && -d "$running_dashboards_dir" ]]; then
        cp -r "$dashboards_dir"/* "$running_dashboards_dir/" 2>/dev/null || true
        info "Grafana dashboards updated"
    fi
}

# Verify system after update
verify_system_after_update() {
    info "Verifying system health after update..."

    local verification_errors=0

    # Wait for services to stabilize
    sleep 30

    # Check container health
    local unhealthy_containers
    unhealthy_containers=$(docker ps --filter "health=unhealthy" --format "table {{.Names}}" | grep -v NAMES | wc -l || echo "0")

    if [[ "$unhealthy_containers" -gt 0 ]]; then
        error "Found $unhealthy_containers unhealthy containers"
        ((verification_errors++))
    fi

    # Check AdGuard health
    if ! curl -s -f "http://localhost:3000/" >/dev/null; then
        error "AdGuard web interface is not accessible after update"
        ((verification_errors++))
    fi

    # Check DNS resolution
    if ! dig @localhost google.com >/dev/null 2>&1; then
        error "DNS resolution is not working after update"
        ((verification_errors++))
    fi

    # Check monitoring services
    if ! curl -s -f "http://localhost:9090/-/healthy" >/dev/null; then
        error "Prometheus is not healthy after update"
        ((verification_errors++))
    fi

    if ! curl -s -f "http://localhost:3001/api/health" >/dev/null; then
        error "Grafana is not healthy after update"
        ((verification_errors++))
    fi

    # Test DNS blocking
    local test_domain="doubleclick.net"
    local dns_result
    dns_result=$(dig @localhost "$test_domain" +short | head -1 || echo "")

    if [[ "$dns_result" == "0.0.0.0" ]] || [[ -z "$dns_result" ]]; then
        success "DNS blocking is working correctly"
    else
        warn "DNS blocking may not be working correctly"
    fi

    if [[ $verification_errors -eq 0 ]]; then
        success "System verification passed after update"
        return 0
    else
        error "System verification failed with $verification_errors errors"
        return 1
    fi
}

# Update system security
update_security() {
    info "Updating security configurations..."

    # Update fail2ban rules if needed
    if systemctl is-active --quiet fail2ban; then
        sudo systemctl reload fail2ban
        info "Fail2ban configuration reloaded"
    fi

    # Update firewall rules if needed
    local ufw_status
    ufw_status=$(sudo ufw status | head -1)
    if [[ "$ufw_status" == "Status: active" ]]; then
        # Refresh UFW rules
        sudo ufw --force reload
        info "UFW firewall rules reloaded"
    fi

    # Update AIDE database
    if command -v aide >/dev/null 2>&1; then
        info "Updating AIDE database..."
        sudo aideinit
        sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
        success "AIDE database updated"
    fi

    # Run security scan
    if command -v lynis >/dev/null 2>&1; then
        info "Running security audit..."
        sudo lynis audit system --quick >/dev/null 2>&1 || true
        info "Security audit completed"
    fi
}

# Send update notification
send_notification() {
    local status=$1
    local message=$2

    if [[ -n "${ADMIN_EMAIL:-}" ]] && command -v mail >/dev/null 2>&1; then
        local subject
        if [[ "$status" == "success" ]]; then
            subject="[AdGuard] System Update Completed Successfully"
        else
            subject="[AdGuard] System Update Failed"
        fi

        {
            echo "AdGuard Home Infrastructure Update Report"
            echo "========================================="
            echo
            echo "Status: $status"
            echo "Timestamp: $(date)"
            echo "Hostname: $(hostname)"
            echo
            echo "Update Details:"
            echo "- System packages: $(if [[ "$UPDATE_SYSTEM" == "true" ]]; then echo "Updated"; else echo "Skipped"; fi)"
            echo "- Containers: $(if [[ "$UPDATE_CONTAINERS" == "true" ]]; then echo "Updated"; else echo "Skipped"; fi)"
            echo "- Pre-update backup: $(if [[ "$BACKUP_BEFORE_UPDATE" == "true" ]]; then echo "Created"; else echo "Skipped"; fi)"
            echo
            echo "Message: $message"
            echo
            echo "Log file: $LOG_FILE"
        } | mail -s "$subject" "$ADMIN_EMAIL"
    fi

    # Log to syslog
    logger -t "adguard-update" "$status: $message"
}

# Main update function
main() {
    local start_time
    start_time=$(date +%s)

    info "Starting AdGuard Home infrastructure update..."

    # Parse command line arguments
    parse_args "$@"

    # Pre-update checks
    check_system_health

    # Create backup if requested
    create_pre_update_backup

    # Perform updates
    if [[ "$UPDATE_SYSTEM" == "true" ]]; then
        update_system_packages
    fi

    if [[ "$UPDATE_CONTAINERS" == "true" ]]; then
        update_containers
        update_adguard_config
        update_filter_lists
        update_monitoring_configs
    fi

    # Update security configurations
    update_security

    # Verify system health after update
    if verify_system_after_update; then
        local end_time duration
        end_time=$(date +%s)
        duration=$((end_time - start_time))

        success "Update completed successfully in ${duration} seconds"
        send_notification "success" "All updates completed successfully in ${duration} seconds"
    else
        error "Update completed but system verification failed"
        send_notification "failed" "Update completed but system verification failed"
        exit 1
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi