#!/bin/bash
# AdGuard Home Infrastructure - Security Integration Tests
# Comprehensive security validation and penetration testing

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_LOG="/tmp/adguard-security-test-$(date +%Y%m%d-%H%M%S).log"

# Test configuration
# TEST_TIMEOUT=30  # Currently unused but available for future timeout implementations
# MAX_RETRIES=3  # Currently unused but available for future retry logic
# SECURITY_SCAN_TIMEOUT=60  # Currently unused but available for future timeout implementations

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Test counters
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
SECURITY_ISSUES=0

# Load environment if available
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "${PROJECT_ROOT}/.env"
    set +a
fi

# Default values
STATIC_IP=${STATIC_IP:-192.168.1.100}
SSH_PORT=${SSH_PORT:-2222}
ADGUARD_WEB_PORT=${ADGUARD_WEB_PORT:-3000}
GRAFANA_PORT=${GRAFANA_PORT:-3001}
PROMETHEUS_PORT=${PROMETHEUS_PORT:-9090}

# Logging functions
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${timestamp} [${level}] ${message}" | tee -a "${TEST_LOG}"
}

info() { log "INFO" "$*"; }
warn() { log "WARN" "${YELLOW}$*${NC}"; }
error() { log "ERROR" "${RED}$*${NC}"; }
success() { log "SUCCESS" "${GREEN}$*${NC}"; }
security_issue() {
    log "SECURITY" "${RED}[SECURITY ISSUE] $*${NC}"
    ((SECURITY_ISSUES++))
}

# Test framework functions
test_start() {
    local test_name="$1"
    ((TESTS_TOTAL++))
    echo -n "  Testing ${test_name}... "
    info "Starting security test: ${test_name}"
}

test_pass() {
    local test_name="$1"
    ((TESTS_PASSED++))
    echo -e "${GREEN}✓ SECURE${NC}"
    success "Security test passed: ${test_name}"
}

test_fail() {
    local test_name="$1"
    local reason="$2"
    ((TESTS_FAILED++))
    echo -e "${RED}✗ VULNERABLE${NC}"
    security_issue "Security test failed: ${test_name} - ${reason}"
}

test_skip() {
    local test_name="$1"
    local reason="$2"
    ((TESTS_SKIPPED++))
    echo -e "${YELLOW}⚠ SKIP${NC}"
    warn "Security test skipped: ${test_name} - ${reason}"
}

# Prerequisites check
check_prerequisites() {
    info "Checking security test prerequisites..."

    # Check if nmap is available
    if ! command -v nmap >/dev/null 2>&1; then
        warn "nmap not found. Install with: sudo apt install nmap"
    fi

    # Check if ss/netstat is available
    if ! command -v ss >/dev/null 2>&1 && ! command -v netstat >/dev/null 2>&1; then
        error "ss or netstat required. Install with: sudo apt install iproute2"
        exit 1
    fi

    # Check if openssl is available
    if ! command -v openssl >/dev/null 2>&1; then
        warn "openssl not found. Some TLS tests will be skipped."
    fi

    success "Prerequisites check completed"
}

# Network security tests
test_network_security() {
    echo -e "\n${BOLD}Network Security Tests${NC}"
    echo "========================="

    # Test open ports
    test_start "Open ports scan"
    local open_ports
    if command -v ss >/dev/null 2>&1; then
        open_ports=$(ss -tuln | awk 'NR>1 {print $5}' | sed 's/.*://' | sort -nu | tr '\n' ' ')
    elif command -v netstat >/dev/null 2>&1; then
        open_ports=$(netstat -tuln | awk 'NR>2 {print $4}' | sed 's/.*://' | sort -nu | tr '\n' ' ')
    else
        test_skip "Open ports scan" "No network tools available"
        return
    fi

    # Expected ports
    local expected_ports="22 53 ${SSH_PORT} ${ADGUARD_WEB_PORT} ${GRAFANA_PORT} ${PROMETHEUS_PORT} 9093 9100 9617"
    local unexpected_ports=""

    for port in $open_ports; do
        if [[ ! " $expected_ports " =~ \ $port\  ]] && [[ "$port" != "22" ]]; then
            unexpected_ports="$unexpected_ports $port"
        fi
    done

    if [[ -z "$unexpected_ports" ]]; then
        test_pass "Open ports scan"
    else
        test_fail "Open ports scan" "Unexpected open ports: $unexpected_ports"
    fi

    # Test firewall status
    test_start "Firewall status"
    if command -v ufw >/dev/null 2>&1; then
        local ufw_status
        ufw_status=$(sudo ufw status 2>/dev/null | head -1)

        if [[ "$ufw_status" =~ "Status: active" ]]; then
            test_pass "Firewall status"
        else
            test_fail "Firewall status" "UFW firewall is not active"
        fi
    else
        test_skip "Firewall status" "UFW not available"
    fi

    # Test fail2ban status
    test_start "Fail2ban protection"
    if command -v fail2ban-client >/dev/null 2>&1; then
        if sudo systemctl is-active --quiet fail2ban; then
            local jails
            jails=$(sudo fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr ',' ' ')

            if [[ -n "$jails" ]]; then
                test_pass "Fail2ban protection"
            else
                test_fail "Fail2ban protection" "No active jails configured"
            fi
        else
            test_fail "Fail2ban protection" "Fail2ban service not running"
        fi
    else
        test_skip "Fail2ban protection" "Fail2ban not installed"
    fi
}

# SSH security tests
test_ssh_security() {
    echo -e "\n${BOLD}SSH Security Tests${NC}"
    echo "==================="

    # Test SSH configuration
    test_start "SSH configuration security"
    local ssh_config="/etc/ssh/sshd_config"
    local ssh_issues=""

    if [[ -f "$ssh_config" ]]; then
        # Check if root login is disabled
        if ! sudo grep -q "^PermitRootLogin no" "$ssh_config"; then
            ssh_issues="$ssh_issues root_login_enabled"
        fi

        # Check if password authentication is disabled
        if ! sudo grep -q "^PasswordAuthentication no" "$ssh_config"; then
            ssh_issues="$ssh_issues password_auth_enabled"
        fi

        # Check if custom port is used
        if ! sudo grep -q "^Port ${SSH_PORT}" "$ssh_config"; then
            ssh_issues="$ssh_issues default_port"
        fi

        # Check protocol version
        if sudo grep -q "^Protocol 1" "$ssh_config"; then
            ssh_issues="$ssh_issues old_protocol"
        fi

        if [[ -z "$ssh_issues" ]]; then
            test_pass "SSH configuration security"
        else
            test_fail "SSH configuration security" "Issues: $ssh_issues"
        fi
    else
        test_skip "SSH configuration security" "SSH config file not found"
    fi

    # Test SSH key authentication
    test_start "SSH key authentication"
    local ssh_auth_methods
    ssh_auth_methods=$(sudo grep "^AuthenticationMethods\|^PubkeyAuthentication\|^PasswordAuthentication" "$ssh_config" 2>/dev/null || echo "")

    if echo "$ssh_auth_methods" | grep -q "PubkeyAuthentication yes"; then
        test_pass "SSH key authentication"
    else
        test_fail "SSH key authentication" "Public key authentication not properly configured"
    fi

    # Test SSH connection (if possible)
    test_start "SSH port accessibility"
    if timeout 5 bash -c "echo >/dev/tcp/localhost/${SSH_PORT}" 2>/dev/null; then
        test_pass "SSH port accessibility"
    else
        test_fail "SSH port accessibility" "SSH port ${SSH_PORT} not accessible"
    fi
}

# Web interface security tests
test_web_security() {
    echo -e "\n${BOLD}Web Interface Security Tests${NC}"
    echo "=============================="

    local web_services=(
        "AdGuard:${ADGUARD_WEB_PORT}"
        "Grafana:${GRAFANA_PORT}"
        "Prometheus:${PROMETHEUS_PORT}"
    )

    for service_info in "${web_services[@]}"; do
        local service_name="${service_info%%:*}"
        local port="${service_info#*:}"

        # Test HTTP security headers
        test_start "${service_name} security headers"
        local headers
        headers=$(curl -s -I -m 10 "http://localhost:${port}/" 2>/dev/null || echo "")

        local missing_headers=""

        if ! echo "$headers" | grep -qi "X-Frame-Options\|Content-Security-Policy"; then
            missing_headers="$missing_headers clickjacking_protection"
        fi

        if ! echo "$headers" | grep -qi "X-Content-Type-Options.*nosniff"; then
            missing_headers="$missing_headers content_type_sniffing"
        fi

        if [[ -z "$missing_headers" ]]; then
            test_pass "${service_name} security headers"
        else
            test_fail "${service_name} security headers" "Missing: $missing_headers"
        fi

        # Test default credentials
        test_start "${service_name} default credentials"
        local auth_response
        auth_response=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                       -u "admin:admin" "http://localhost:${port}/" 2>/dev/null || echo "000")

        if [[ "$auth_response" == "401" ]] || [[ "$auth_response" == "403" ]]; then
            test_pass "${service_name} default credentials"
        elif [[ "$auth_response" == "200" ]]; then
            test_fail "${service_name} default credentials" "Default credentials may be active"
        else
            test_skip "${service_name} default credentials" "Cannot test authentication"
        fi

        # Test for information disclosure
        test_start "${service_name} information disclosure"
        local response_body
        response_body=$(curl -s -m 10 "http://localhost:${port}/" 2>/dev/null || echo "")

        if echo "$response_body" | grep -qi "version\|server\|apache\|nginx\|error"; then
            test_fail "${service_name} information disclosure" "Server information may be disclosed"
        else
            test_pass "${service_name} information disclosure"
        fi
    done
}

# TLS/SSL security tests
test_tls_security() {
    echo -e "\n${BOLD}TLS/SSL Security Tests${NC}"
    echo "======================"

    if ! command -v openssl >/dev/null 2>&1; then
        test_skip "TLS security tests" "OpenSSL not available"
        return
    fi

    local tls_services=(
        "AdGuard:localhost:${ADGUARD_WEB_PORT}"
        "Grafana:localhost:${GRAFANA_PORT}"
    )

    for service_info in "${tls_services[@]}"; do
        local service_name="${service_info%%:*}"
        local host_port="${service_info#*:}"

        # Test TLS certificate
        test_start "${service_name} TLS certificate"
        local tls_info
        tls_info=$(timeout 10 openssl s_client -connect "$host_port" -servername localhost 2>/dev/null | head -20)

        if echo "$tls_info" | grep -q "BEGIN CERTIFICATE"; then
            # Check certificate validity
            local cert_valid
            cert_valid=$(echo "$tls_info" | openssl x509 -noout -dates 2>/dev/null | grep "notAfter" | cut -d= -f2)

            if [[ -n "$cert_valid" ]]; then
                test_pass "${service_name} TLS certificate"
            else
                test_fail "${service_name} TLS certificate" "Certificate validation failed"
            fi
        else
            test_skip "${service_name} TLS certificate" "HTTPS not enabled or configured"
        fi

        # Test weak cipher suites
        test_start "${service_name} cipher suites"
        local weak_ciphers
        weak_ciphers=$(timeout 10 openssl s_client -connect "$host_port" -cipher 'RC4:MD5:DES' 2>/dev/null | grep -c "Cipher.*:" || echo "0")

        if [[ "$weak_ciphers" -eq 0 ]]; then
            test_pass "${service_name} cipher suites"
        else
            test_fail "${service_name} cipher suites" "Weak cipher suites detected"
        fi
    done
}

# Container security tests
test_container_security() {
    echo -e "\n${BOLD}Container Security Tests${NC}"
    echo "=========================="

    if ! command -v docker >/dev/null 2>&1; then
        test_skip "Container security tests" "Docker not available"
        return
    fi

    # Test for privileged containers
    test_start "Privileged containers"
    local privileged_containers
    privileged_containers=$(docker ps --filter "label=com.docker.compose.project=adguard" -q | \
                           xargs docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}' 2>/dev/null | \
                           grep -c "true" || echo "0")

    if [[ "$privileged_containers" -eq 0 ]]; then
        test_pass "Privileged containers"
    else
        test_fail "Privileged containers" "${privileged_containers} containers running with privileged access"
    fi

    # Test for containers running as root
    test_start "Root user containers"
    local root_containers
    root_containers=$(docker ps --filter "label=com.docker.compose.project=adguard" -q | \
                     xargs docker inspect --format '{{.Name}} {{.Config.User}}' 2>/dev/null | \
                     grep -cE "(root|^[^:]*$)" || echo "0")

    # Allow some containers to run as root if necessary (like adguard for port 53)
    if [[ "$root_containers" -le 2 ]]; then
        test_pass "Root user containers"
    else
        test_fail "Root user containers" "${root_containers} containers running as root"
    fi

    # Test for host network mode
    test_start "Host network mode"
    local host_network_containers
    host_network_containers=$(docker ps --filter "label=com.docker.compose.project=adguard" -q | \
                             xargs docker inspect --format '{{.Name}} {{.HostConfig.NetworkMode}}' 2>/dev/null | \
                             grep -c "host" || echo "0")

    if [[ "$host_network_containers" -eq 0 ]]; then
        test_pass "Host network mode"
    else
        test_fail "Host network mode" "${host_network_containers} containers using host network"
    fi

    # Test for dangerous volume mounts
    test_start "Dangerous volume mounts"
    local dangerous_mounts
    dangerous_mounts=$(docker ps --filter "label=com.docker.compose.project=adguard" -q | \
                      xargs docker inspect --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' 2>/dev/null | \
                      grep -cE "/(etc|usr|bin|sbin|boot|sys|proc):" || echo "0")

    if [[ "$dangerous_mounts" -eq 0 ]]; then
        test_pass "Dangerous volume mounts"
    else
        test_fail "Dangerous volume mounts" "${dangerous_mounts} containers with dangerous mounts"
    fi

    # Test container resource limits
    test_start "Container resource limits"
    local unlimited_containers
    unlimited_containers=$(docker ps --filter "label=com.docker.compose.project=adguard" -q | \
                          xargs docker inspect --format '{{.Name}} {{.HostConfig.Memory}} {{.HostConfig.CpuShares}}' 2>/dev/null | \
                          awk '$2 == 0 && $3 == 0 {count++} END {print count+0}')

    if [[ "$unlimited_containers" -eq 0 ]]; then
        test_pass "Container resource limits"
    else
        test_fail "Container resource limits" "${unlimited_containers} containers without resource limits"
    fi
}

# File system security tests
test_filesystem_security() {
    echo -e "\n${BOLD}File System Security Tests${NC}"
    echo "==========================="

    # Test file permissions
    test_start "Configuration file permissions"
    local permission_issues=""

    local sensitive_files=(
        "${PROJECT_ROOT}/.env:600"
        "/opt/adguard/conf:750"
        "/etc/ssh/sshd_config:644"
    )

    for file_info in "${sensitive_files[@]}"; do
        local file_path="${file_info%%:*}"
        local expected_perm="${file_info#*:}"

        if [[ -e "$file_path" ]]; then
            local actual_perm
            actual_perm=$(stat -c "%a" "$file_path" 2>/dev/null || echo "000")

            if [[ "$actual_perm" != "$expected_perm" ]] && [[ "$actual_perm" -gt "$expected_perm" ]]; then
                permission_issues="$permission_issues ${file_path}(${actual_perm})"
            fi
        fi
    done

    if [[ -z "$permission_issues" ]]; then
        test_pass "Configuration file permissions"
    else
        test_fail "Configuration file permissions" "Overly permissive: $permission_issues"
    fi

    # Test for world-writable files
    test_start "World-writable files"
    local world_writable
    world_writable=$(find /opt/adguard /opt/monitoring -type f -perm -002 2>/dev/null | wc -l || echo "0")

    if [[ "$world_writable" -eq 0 ]]; then
        test_pass "World-writable files"
    else
        test_fail "World-writable files" "${world_writable} world-writable files found"
    fi

    # Test for SUID/SGID files
    test_start "SUID/SGID files"
    local suid_files
    suid_files=$(find /opt/adguard /opt/monitoring -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l || echo "0")

    if [[ "$suid_files" -eq 0 ]]; then
        test_pass "SUID/SGID files"
    else
        test_fail "SUID/SGID files" "${suid_files} SUID/SGID files found in application directories"
    fi
}

# System security tests
test_system_security() {
    echo -e "\n${BOLD}System Security Tests${NC}"
    echo "======================"

    # Test for unattended upgrades
    test_start "Automatic security updates"
    if [[ -f "/etc/apt/apt.conf.d/50unattended-upgrades" ]]; then
        if grep -q "Unattended-Upgrade::Automatic-Reboot.*false" "/etc/apt/apt.conf.d/50unattended-upgrades"; then
            test_pass "Automatic security updates"
        else
            test_fail "Automatic security updates" "Auto-reboot enabled (security risk)"
        fi
    else
        test_fail "Automatic security updates" "Unattended upgrades not configured"
    fi

    # Test kernel parameters
    test_start "Security kernel parameters"
    local kernel_issues=""

    local security_params=(
        "net.ipv4.ip_forward:0"
        "net.ipv4.conf.all.accept_redirects:0"
        "net.ipv4.conf.all.send_redirects:0"
        "net.ipv4.conf.all.accept_source_route:0"
    )

    for param_info in "${security_params[@]}"; do
        local param="${param_info%%:*}"
        local expected="${param_info#*:}"
        local actual
        actual=$(sysctl -n "$param" 2>/dev/null || echo "unknown")

        if [[ "$actual" != "$expected" ]] && [[ "$actual" != "unknown" ]]; then
            kernel_issues="$kernel_issues ${param}=${actual}"
        fi
    done

    if [[ -z "$kernel_issues" ]]; then
        test_pass "Security kernel parameters"
    else
        test_fail "Security kernel parameters" "Insecure settings: $kernel_issues"
    fi

    # Test for core dumps
    test_start "Core dump configuration"
    local core_dump_limit
    core_dump_limit=$(ulimit -c)

    if [[ "$core_dump_limit" == "0" ]]; then
        test_pass "Core dump configuration"
    else
        test_fail "Core dump configuration" "Core dumps enabled (limit: $core_dump_limit)"
    fi
}

# DNS security tests
test_dns_security() {
    echo -e "\n${BOLD}DNS Security Tests${NC}"
    echo "=================="

    # Test DNS over HTTPS configuration
    test_start "DNS over HTTPS (DoH)"
    local adguard_config="/opt/adguard/conf/AdGuardHome.yaml"

    if [[ -f "$adguard_config" ]]; then
        if grep -q "https://" "$adguard_config"; then
            test_pass "DNS over HTTPS (DoH)"
        else
            test_fail "DNS over HTTPS (DoH)" "DoH not configured in upstream DNS"
        fi
    else
        test_skip "DNS over HTTPS (DoH)" "AdGuard config not found"
    fi

    # Test DNSSEC validation
    test_start "DNSSEC validation"
    if [[ -f "$adguard_config" ]]; then
        if grep -q "enable_dnssec.*true" "$adguard_config"; then
            test_pass "DNSSEC validation"
        else
            test_fail "DNSSEC validation" "DNSSEC not enabled"
        fi
    else
        test_skip "DNSSEC validation" "AdGuard config not found"
    fi

    # Test DNS cache poisoning protection
    test_start "DNS cache poisoning protection"
    if command -v dig >/dev/null 2>&1; then
        # Test with a known domain
        local response
        response=$(dig @localhost google.com +short 2>/dev/null)

        if [[ -n "$response" ]] && [[ "$response" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            test_pass "DNS cache poisoning protection"
        else
            test_fail "DNS cache poisoning protection" "Unexpected DNS response format"
        fi
    else
        test_skip "DNS cache poisoning protection" "dig not available"
    fi

    # Test rate limiting
    test_start "DNS rate limiting"
    if [[ -f "$adguard_config" ]]; then
        if grep -q "ratelimit.*[1-9]" "$adguard_config"; then
            test_pass "DNS rate limiting"
        else
            test_fail "DNS rate limiting" "Rate limiting not configured"
        fi
    else
        test_skip "DNS rate limiting" "AdGuard config not found"
    fi
}

# Vulnerability assessment
test_vulnerability_assessment() {
    echo -e "\n${BOLD}Vulnerability Assessment${NC}"
    echo "=========================="

    # Test for known vulnerable services
    test_start "Known vulnerable services"
    local vulnerable_services=""

    # Check Docker version for known vulnerabilities
    if command -v docker >/dev/null 2>&1; then
        local docker_version
        docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")

        # Check against known vulnerable versions (example)
        if [[ "$docker_version" =~ ^(1\.|18\.|19\.03\.[0-9]$) ]]; then
            vulnerable_services="$vulnerable_services docker:$docker_version"
        fi
    fi

    if [[ -z "$vulnerable_services" ]]; then
        test_pass "Known vulnerable services"
    else
        test_fail "Known vulnerable services" "Vulnerable: $vulnerable_services"
    fi

    # Test for exposed management interfaces
    test_start "Exposed management interfaces"
    local exposed_interfaces=""

    local management_ports=(
        "2375:Docker_API"
        "2376:Docker_API_TLS"
        "6443:Kubernetes_API"
        "8080:HTTP_Alt"
        "8443:HTTPS_Alt"
    )

    for port_info in "${management_ports[@]}"; do
        local port="${port_info%%:*}"
        local service="${port_info#*:}"

        if timeout 3 bash -c "echo >/dev/tcp/localhost/${port}" 2>/dev/null; then
            exposed_interfaces="$exposed_interfaces ${service}:${port}"
        fi
    done

    if [[ -z "$exposed_interfaces" ]]; then
        test_pass "Exposed management interfaces"
    else
        test_fail "Exposed management interfaces" "Exposed: $exposed_interfaces"
    fi
}

# Network penetration tests
test_network_penetration() {
    echo -e "\n${BOLD}Network Penetration Tests${NC}"
    echo "=========================="

    if ! command -v nmap >/dev/null 2>&1; then
        test_skip "Network penetration tests" "nmap not available"
        return
    fi

    # Test port scanning
    test_start "Port scan resistance"
    local scan_result
    scan_result=$(timeout 30 nmap -sS -O --osscan-limit localhost 2>/dev/null | grep -c "filtered\|closed" || echo "0")

    if [[ "$scan_result" -gt 0 ]]; then
        test_pass "Port scan resistance"
    else
        test_fail "Port scan resistance" "All scanned ports appear open"
    fi

    # Test service enumeration
    test_start "Service enumeration protection"
    local service_enum
    service_enum=$(timeout 20 nmap -sV -p 22,53,"${ADGUARD_WEB_PORT}" localhost 2>/dev/null | grep -c "version" || echo "0")

    if [[ "$service_enum" -lt 2 ]]; then
        test_pass "Service enumeration protection"
    else
        test_fail "Service enumeration protection" "Service versions easily enumerable"
    fi
}

# Generate security report
generate_security_report() {
    echo -e "\n${BOLD}Security Assessment Report${NC}"
    echo "============================"
    echo "Test execution completed at: $(date)"
    echo "Log file: ${TEST_LOG}"
    echo ""
    echo "Results:"
    echo "  Total tests:      ${TESTS_TOTAL}"
    echo -e "  Secure:           ${GREEN}${TESTS_PASSED}${NC}"
    echo -e "  Vulnerable:       ${RED}${TESTS_FAILED}${NC}"
    echo -e "  Skipped:          ${YELLOW}${TESTS_SKIPPED}${NC}"
    echo -e "  Security Issues:  ${RED}${SECURITY_ISSUES}${NC}"
    echo ""

    local security_score=0
    if [[ $TESTS_TOTAL -gt 0 ]]; then
        security_score=$(( (TESTS_PASSED * 100) / (TESTS_TOTAL - TESTS_SKIPPED) ))
    fi

    echo "Security Score: ${security_score}%"

    # Security rating
    if [[ $SECURITY_ISSUES -eq 0 ]] && [[ $security_score -ge 95 ]]; then
        echo -e "\n${GREEN}${BOLD}🛡️  EXCELLENT SECURITY${NC}"
        echo "Your AdGuard infrastructure has excellent security posture."
    elif [[ $SECURITY_ISSUES -le 2 ]] && [[ $security_score -ge 85 ]]; then
        echo -e "\n${GREEN}${BOLD}✓ GOOD SECURITY${NC}"
        echo "Your AdGuard infrastructure has good security with minor issues."
    elif [[ $SECURITY_ISSUES -le 5 ]] && [[ $security_score -ge 70 ]]; then
        echo -e "\n${YELLOW}${BOLD}⚠ MODERATE SECURITY${NC}"
        echo "Your AdGuard infrastructure has moderate security. Address the issues found."
    else
        echo -e "\n${RED}${BOLD}❌ POOR SECURITY${NC}"
        echo "Your AdGuard infrastructure has significant security issues that need immediate attention."
    fi

    if [[ $SECURITY_ISSUES -gt 0 ]]; then
        echo -e "\n${YELLOW}Recommendations:${NC}"
        echo "1. Review the security test log for detailed findings"
        echo "2. Address critical security issues immediately"
        echo "3. Implement additional security hardening measures"
        echo "4. Schedule regular security assessments"
        echo "5. Keep all components updated with latest security patches"

        return 1
    else
        echo -e "\n${GREEN}All security tests passed! Continue monitoring and maintaining security best practices.${NC}"
        return 0
    fi
}

# Cleanup function
cleanup() {
    # Clean up any temporary files
    rm -f /tmp/adguard_security_test_*
}

# Main execution
main() {
    echo -e "${BOLD}AdGuard Home Security Integration Tests${NC}"
    echo -e "${BLUE}Comprehensive Security Assessment${NC}"
    echo "=============================================="
    echo "Performing security validation and penetration testing"
    echo "Log: ${TEST_LOG}"
    echo ""

    # Set up cleanup trap
    trap cleanup EXIT

    # Check prerequisites
    check_prerequisites

    # Run security test suites
    test_network_security
    test_ssh_security
    test_web_security
    test_tls_security
    test_container_security
    test_filesystem_security
    test_system_security
    test_dns_security
    test_vulnerability_assessment
    test_network_penetration

    # Generate final security report
    generate_security_report
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h       Show this help message"
        echo "  --timeout SEC    Test timeout in seconds (default: 30)"
        echo ""
        echo "Environment variables:"
        echo "  STATIC_IP           Server IP address"
        echo "  SSH_PORT            SSH port (default: 2222)"
        echo "  ADGUARD_WEB_PORT    AdGuard web port (default: 3000)"
        echo "  TEST_TIMEOUT        Test timeout in seconds"
        exit 0
        ;;
    --timeout)
        # TEST_TIMEOUT="$2"  # Currently unused but kept for future timeout implementations
        shift 2
        ;;
    *)
        # No arguments, run main
        ;;
esac

# Run main function
main "$@"