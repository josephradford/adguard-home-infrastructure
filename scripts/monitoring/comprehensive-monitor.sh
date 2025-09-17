#!/bin/bash
# AdGuard Home Infrastructure - Comprehensive Security Monitoring Script
# Detects anomalies, security threats, and system issues

set -euo pipefail

# Configuration
# SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"  # Currently unused
LOG_FILE="/opt/logs/security-monitor.log"
ALERT_FILE="/opt/logs/security-alerts.log"
REPORT_DIR="/opt/reports"
TEMP_DIR="/tmp/adguard-monitor"

# Load environment variables
if [[ -f "/opt/adguard/.env" ]]; then
    set -a
    # shellcheck source=/opt/adguard/.env
    source "/opt/adguard/.env"
    set +a
fi

# Monitoring thresholds
DNS_QUERY_THRESHOLD=1000      # Queries per minute threshold
MEMORY_THRESHOLD=85           # Memory usage percentage
CPU_THRESHOLD=80              # CPU usage percentage
DISK_THRESHOLD=85             # Disk usage percentage
FAILED_LOGIN_THRESHOLD=10     # Failed login attempts

# Colors and formatting (currently unused but available for future enhancements)
# RED='\033[0;31m'
# GREEN='\033[0;32m'
# YELLOW='\033[1;33m'
# BLUE='\033[0;34m'
# NC='\033[0m'

# Logging functions
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${timestamp} [${level}] ${message}" | tee -a "${LOG_FILE}"
}

info() { log "INFO" "$*"; }
warn() { log "WARN" "$*"; }
error() { log "ERROR" "$*"; }
alert() {
    log "ALERT" "$*"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ALERT] $*" >> "${ALERT_FILE}"
}

# Initialize monitoring
init_monitoring() {
    mkdir -p "${REPORT_DIR}" "${TEMP_DIR}" "$(dirname "${LOG_FILE}")" "$(dirname "${ALERT_FILE}")"

    # Clean up temp files older than 1 hour
    find "${TEMP_DIR}" -type f -mmin +60 -delete 2>/dev/null || true
}

# Check AdGuard Home health
check_adguard_health() {
    info "Checking AdGuard Home health..."

    local adguard_status=0
    local dns_responses=0
    local web_response=0

    # Check if AdGuard container is running
    if ! docker ps | grep -q "adguard-home.*Up"; then
        alert "AdGuard Home container is not running!"
        adguard_status=1
    fi

    # Check DNS response
    if ! timeout 5 dig @localhost google.com >/dev/null 2>&1; then
        alert "AdGuard DNS is not responding!"
        dns_responses=1
    fi

    # Check web interface
    if ! timeout 5 curl -s -f "http://localhost:3000/" >/dev/null; then
        alert "AdGuard web interface is not accessible!"
        web_response=1
    fi

    # Check query processing time
    local processing_time
    processing_time=$(curl -s "http://localhost:3000/control/stats" 2>/dev/null | jq -r '.avg_processing_time // 0' 2>/dev/null || echo "0")

    if (( $(echo "$processing_time > 100" | bc -l 2>/dev/null || echo "0") )); then
        warn "High DNS processing time: ${processing_time}ms"
    fi

    return $((adguard_status + dns_responses + web_response))
}

# Monitor DNS query patterns
monitor_dns_patterns() {
    info "Monitoring DNS query patterns..."

    local current_minute
    current_minute=$(date '+%Y-%m-%d %H:%M')

    # Get current query stats from AdGuard
    local stats_json
    if ! stats_json=$(curl -s "http://localhost:3000/control/stats" 2>/dev/null); then
        warn "Could not retrieve AdGuard stats"
        return 1
    fi

    local total_queries
    local blocked_queries
    local query_rate

    total_queries=$(echo "$stats_json" | jq -r '.num_dns_queries // 0')
    blocked_queries=$(echo "$stats_json" | jq -r '.num_blocked_filtering // 0')

    # Calculate queries per minute (approximate)
    query_rate=$(echo "scale=2; $total_queries / 1440" | bc -l 2>/dev/null || echo "0")

    # Check for unusual query volume
    if (( $(echo "$query_rate > $DNS_QUERY_THRESHOLD" | bc -l 2>/dev/null || echo "0") )); then
        alert "High DNS query rate detected: ${query_rate} queries/minute"
    fi

    # Check for high block rate (possible malware activity)
    local block_percentage
    if [[ "$total_queries" -gt 0 ]]; then
        block_percentage=$(echo "scale=2; ($blocked_queries * 100) / $total_queries" | bc -l 2>/dev/null || echo "0")

        if (( $(echo "$block_percentage > 50" | bc -l 2>/dev/null || echo "0") )); then
            alert "High DNS block rate: ${block_percentage}% of queries blocked"
        fi
    fi

    # Log stats for trend analysis
    echo "${current_minute},${total_queries},${blocked_queries},${query_rate},${block_percentage}" >> "${REPORT_DIR}/dns-stats.csv"
}

# Check system resources
check_system_resources() {
    info "Checking system resources..."

    # Memory usage
    local memory_usage
    memory_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')

    if [[ "$memory_usage" -gt "$MEMORY_THRESHOLD" ]]; then
        alert "High memory usage: ${memory_usage}%"
    fi

    # CPU usage
    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2+$4}' | cut -d'%' -f1)

    if (( $(echo "$cpu_usage > $CPU_THRESHOLD" | bc -l 2>/dev/null || echo "0") )); then
        alert "High CPU usage: ${cpu_usage}%"
    fi

    # Disk usage
    local disk_usage
    disk_usage=$(df / | awk 'NR==2 {print $(NF-1)}' | sed 's/%//')

    if [[ "$disk_usage" -gt "$DISK_THRESHOLD" ]]; then
        alert "High disk usage: ${disk_usage}%"
    fi

    # Check load average
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')

    if (( $(echo "$load_avg > 2.0" | bc -l 2>/dev/null || echo "0") )); then
        warn "High system load: ${load_avg}"
    fi
}

# Monitor network security
monitor_network_security() {
    info "Monitoring network security..."

    # Check for unusual network connections
    local active_connections
    active_connections=$(netstat -tn | grep -c "ESTABLISHED" || echo "0")

    if [[ "$active_connections" -gt 100 ]]; then
        warn "High number of active connections: ${active_connections}"
    fi

    # Check for failed SSH attempts
    local failed_ssh
    failed_ssh=$(grep "Failed password" /var/log/auth.log 2>/dev/null | grep "$(date '+%b %d')" | wc -l || echo "0")

    if [[ "$failed_ssh" -gt "$FAILED_LOGIN_THRESHOLD" ]]; then
        alert "High number of failed SSH attempts today: ${failed_ssh}"
    fi

    # Check listening ports
    local unexpected_ports
    unexpected_ports=$(netstat -tlnp | grep -v ":53\|:22\|:2222\|:3000\|:3001\|:9090\|:9093\|:9100\|:9617" | grep "LISTEN" | wc -l || echo "0")

    if [[ "$unexpected_ports" -gt 0 ]]; then
        warn "Unexpected listening ports detected: ${unexpected_ports}"
        netstat -tlnp | grep "LISTEN" | grep -v ":53\|:22\|:2222\|:3000\|:3001\|:9090\|:9093\|:9100\|:9617" >> "${ALERT_FILE}"
    fi
}

# Check container security
check_container_security() {
    info "Checking container security..."

    # Check if containers are running with expected security settings
    local containers_status=0

    # Check AdGuard container
    if ! docker inspect adguard-home 2>/dev/null | jq -r '.[0].HostConfig.SecurityOpt[]' | grep -q "no-new-privileges:true"; then
        warn "AdGuard container missing security options"
        containers_status=1
    fi

    # Check for containers running as root
    local root_containers
    root_containers=$(docker ps --format "table {{.Names}}\t{{.Image}}" -q | xargs docker inspect 2>/dev/null | jq -r '.[] | select(.Config.User == "" or .Config.User == "root" or .Config.User == "0") | .Name' | sed 's|^/||' | wc -l || echo "0")

    if [[ "$root_containers" -gt 1 ]]; then  # Allow one for monitoring
        warn "Multiple containers running as root: ${root_containers}"
    fi

    # Check container resource usage
    local high_cpu_containers
    high_cpu_containers=$(docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}" | awk 'NR>1 && $2+0 > 80 {print $1}' | wc -l || echo "0")

    if [[ "$high_cpu_containers" -gt 0 ]]; then
        warn "Containers with high CPU usage detected: ${high_cpu_containers}"
    fi

    return $containers_status
}

# File integrity monitoring
check_file_integrity() {
    info "Checking file integrity..."

    # Check critical configuration files
    local critical_files=(
        "/etc/ssh/sshd_config"
        "/etc/ufw/ufw.conf"
        "/etc/fail2ban/jail.conf"
        "/opt/adguard/conf/AdGuardHome.yaml"
    )

    for file in "${critical_files[@]}"; do
        if [[ -f "$file" ]]; then
            local file_hash
            file_hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
            local stored_hash_file="${TEMP_DIR}/$(basename "$file").hash"

            if [[ -f "$stored_hash_file" ]]; then
                local stored_hash
                stored_hash=$(cat "$stored_hash_file")

                if [[ "$file_hash" != "$stored_hash" ]]; then
                    alert "File integrity violation: $file has been modified"
                fi
            fi

            echo "$file_hash" > "$stored_hash_file"
        fi
    done

    # Check for new SUID files
    local new_suid_files
    new_suid_files=$(find /usr /bin /sbin -perm -4000 -type f 2>/dev/null | wc -l || echo "0")
    local stored_suid_count_file="${TEMP_DIR}/suid_count"

    if [[ -f "$stored_suid_count_file" ]]; then
        local stored_suid_count
        stored_suid_count=$(cat "$stored_suid_count_file")

        if [[ "$new_suid_files" -gt "$stored_suid_count" ]]; then
            alert "New SUID files detected: $((new_suid_files - stored_suid_count)) new files"
        fi
    fi

    echo "$new_suid_files" > "$stored_suid_count_file"
}

# Monitor Docker daemon security
monitor_docker_security() {
    info "Monitoring Docker security..."

    # Check Docker daemon status
    if ! systemctl is-active --quiet docker; then
        alert "Docker daemon is not running!"
        return 1
    fi

    # Check for privileged containers
    local privileged_containers
    privileged_containers=$(docker ps -q | xargs docker inspect 2>/dev/null | jq -r '.[] | select(.HostConfig.Privileged == true) | .Name' | sed 's|^/||' | wc -l || echo "0")

    if [[ "$privileged_containers" -gt 0 ]]; then
        alert "Privileged containers detected: ${privileged_containers}"
    fi

    # Check for containers with dangerous capabilities
    local dangerous_caps
    dangerous_caps=$(docker ps -q | xargs docker inspect 2>/dev/null | jq -r '.[] | select(.HostConfig.CapAdd != null) | .Name + ": " + (.HostConfig.CapAdd | join(","))' | wc -l || echo "0")

    if [[ "$dangerous_caps" -gt 0 ]]; then
        warn "Containers with additional capabilities: ${dangerous_caps}"
    fi
}

# Check log anomalies
check_log_anomalies() {
    info "Checking log anomalies..."

    # Check for suspicious log entries
    local suspicious_patterns=(
        "password.*fail"
        "authentication.*fail"
        "invalid.*user"
        "brute.*force"
        "scan"
        "exploit"
        "malware"
        "virus"
    )

    for pattern in "${suspicious_patterns[@]}"; do
        local matches
        matches=$(grep -i "$pattern" /var/log/syslog /var/log/auth.log 2>/dev/null | grep "$(date '+%b %d')" | wc -l || echo "0")

        if [[ "$matches" -gt 10 ]]; then
            warn "High number of suspicious log entries for pattern '$pattern': ${matches}"
        fi
    done

    # Check AdGuard query logs for suspicious domains
    if [[ -f "/opt/adguard/data/querylog.json" ]]; then
        local suspicious_domains
        suspicious_domains=$(grep -i "malware\|phishing\|trojan\|botnet\|ransomware" /opt/adguard/data/querylog.json 2>/dev/null | wc -l || echo "0")

        if [[ "$suspicious_domains" -gt 5 ]]; then
            alert "High number of malicious domain queries: ${suspicious_domains}"
        fi
    fi
}

# Send alerts if any issues found
send_alerts() {
    if [[ -f "$ALERT_FILE" ]] && [[ -s "$ALERT_FILE" ]]; then
        local alert_count
        alert_count=$(wc -l < "$ALERT_FILE")

        if [[ "$alert_count" -gt 0 ]]; then
            info "Sending security alerts (${alert_count} alerts)..."

            # Send email alert if configured
            if command -v mail >/dev/null 2>&1 && [[ -n "${ADMIN_EMAIL:-}" ]]; then
                {
                    echo "AdGuard Home Security Alert Report"
                    echo "Generated: $(date)"
                    echo "Host: $(hostname)"
                    echo
                    echo "Recent alerts:"
                    tail -20 "$ALERT_FILE"
                } | mail -s "[AdGuard] Security Alerts - $(date '+%Y-%m-%d')" "${ADMIN_EMAIL}"
            fi

            # Send to syslog
            logger -t "adguard-monitor" "Security alerts detected: ${alert_count} alerts"

            # Rotate alert file
            mv "$ALERT_FILE" "${ALERT_FILE}.$(date '+%Y%m%d-%H%M%S')"

            # Keep only last 7 days of alert files
            find "$(dirname "$ALERT_FILE")" -name "$(basename "$ALERT_FILE").*" -mtime +7 -delete 2>/dev/null || true
        fi
    fi
}

# Generate health report
generate_health_report() {
    local report_file="${REPORT_DIR}/health-$(date '+%Y%m%d-%H%M%S').json"

    {
        echo "{"
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"hostname\": \"$(hostname)\","
        echo "  \"system\": {"
        echo "    \"uptime\": \"$(uptime | awk '{print $3,$4}')\","
        echo "    \"load_avg\": \"$(uptime | awk -F'load average:' '{print $2}')\","
        echo "    \"memory_usage\": $(free | awk 'NR==2{printf "%.0f", $3*100/$2}'),"
        echo "    \"disk_usage\": $(df / | awk 'NR==2 {print $(NF-1)}' | sed 's/%//'),"
        echo "    \"cpu_usage\": $(top -bn1 | grep "Cpu(s)" | awk '{print $2+$4}' | cut -d'%' -f1)"
        echo "  },"
        echo "  \"services\": {"
        echo "    \"adguard_running\": $(docker ps | grep -q "adguard-home.*Up" && echo "true" || echo "false"),"
        echo "    \"prometheus_running\": $(docker ps | grep -q "prometheus.*Up" && echo "true" || echo "false"),"
        echo "    \"grafana_running\": $(docker ps | grep -q "grafana.*Up" && echo "true" || echo "false")"
        echo "  },"
        echo "  \"dns\": {"
        echo "    \"queries_today\": $(curl -s "http://localhost:3000/control/stats" 2>/dev/null | jq -r '.num_dns_queries // 0'),"
        echo "    \"blocked_today\": $(curl -s "http://localhost:3000/control/stats" 2>/dev/null | jq -r '.num_blocked_filtering // 0')"
        echo "  }"
        echo "}"
    } > "$report_file"

    info "Health report saved to: $report_file"
}

# Main monitoring function
main() {
    info "Starting comprehensive security monitoring..."

    # Initialize monitoring environment
    init_monitoring

    # Run all monitoring checks
    local exit_code=0

    check_adguard_health || exit_code=$?
    monitor_dns_patterns || exit_code=$?
    check_system_resources || exit_code=$?
    monitor_network_security || exit_code=$?
    check_container_security || exit_code=$?
    check_file_integrity || exit_code=$?
    monitor_docker_security || exit_code=$?
    check_log_anomalies || exit_code=$?

    # Send alerts if any issues found
    send_alerts

    # Generate health report
    generate_health_report

    # Clean up old reports (keep 30 days)
    find "${REPORT_DIR}" -name "health-*.json" -mtime +30 -delete 2>/dev/null || true

    if [[ $exit_code -eq 0 ]]; then
        info "Monitoring completed successfully"
    else
        warn "Monitoring completed with issues (exit code: $exit_code)"
    fi

    return $exit_code
}

# Run monitoring
main "$@"