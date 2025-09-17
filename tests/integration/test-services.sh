#!/bin/bash
# AdGuard Home Infrastructure - Service Integration Tests
# Comprehensive service health and integration testing

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_LOG="/tmp/adguard-services-test-$(date +%Y%m%d-%H%M%S).log"

# Test configuration
# TEST_TIMEOUT=30  # Currently unused but available for future timeout implementations
# MAX_RETRIES=3  # Currently unused but available for future retry logic
HEALTH_CHECK_INTERVAL=5

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

# Load environment if available
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
    set -a
    # shellcheck source=./.env
    source "${PROJECT_ROOT}/.env"
    set +a
fi

# Default values
ADGUARD_WEB_PORT=${ADGUARD_WEB_PORT:-3000}
GRAFANA_PORT=${GRAFANA_PORT:-3001}
PROMETHEUS_PORT=${PROMETHEUS_PORT:-9090}
ALERTMANAGER_PORT=${ALERTMANAGER_PORT:-9093}
NODE_EXPORTER_PORT=${NODE_EXPORTER_PORT:-9100}
ADGUARD_EXPORTER_PORT=${ADGUARD_EXPORTER_PORT:-9617}

# Service endpoints
SERVICES=(
    "adguard:http://localhost:${ADGUARD_WEB_PORT}/"
    "grafana:http://localhost:${GRAFANA_PORT}/api/health"
    "prometheus:http://localhost:${PROMETHEUS_PORT}/-/healthy"
    "alertmanager:http://localhost:${ALERTMANAGER_PORT}/-/healthy"
    "node-exporter:http://localhost:${NODE_EXPORTER_PORT}/metrics"
    "adguard-exporter:http://localhost:${ADGUARD_EXPORTER_PORT}/metrics"
)

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

# Test framework functions
test_start() {
    local test_name="$1"
    ((TESTS_TOTAL++))
    echo -n "  Testing ${test_name}... "
    info "Starting test: ${test_name}"
}

test_pass() {
    local test_name="$1"
    ((TESTS_PASSED++))
    echo -e "${GREEN}✓ PASS${NC}"
    success "Test passed: ${test_name}"
}

test_fail() {
    local test_name="$1"
    local reason="$2"
    ((TESTS_FAILED++))
    echo -e "${RED}✗ FAIL${NC}"
    error "Test failed: ${test_name} - ${reason}"
}

test_skip() {
    local test_name="$1"
    local reason="$2"
    ((TESTS_SKIPPED++))
    echo -e "${YELLOW}⚠ SKIP${NC}"
    warn "Test skipped: ${test_name} - ${reason}"
}

# Utility functions
wait_for_service() {
    local service_name="$1"
    local endpoint="$2"
    local timeout="${3:-$TEST_TIMEOUT}"
    local interval="${4:-$HEALTH_CHECK_INTERVAL}"

    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if curl -f -s -m 5 "$endpoint" >/dev/null 2>&1; then
            return 0
        fi
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done
    return 1
}

check_http_endpoint() {
    local endpoint="$1"
    local expected_status="${2:-200}"
    local timeout="${3:-10}"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -m "$timeout" "$endpoint" 2>/dev/null || echo "000")

    if [[ "$status" -eq "$expected_status" ]]; then
        return 0
    else
        return 1
    fi
}

get_container_status() {
    local container_name="$1"

    if command -v docker >/dev/null 2>&1; then
        docker ps --filter "name=${container_name}" --format "{{.Status}}" 2>/dev/null | head -1
    else
        echo "Docker not available"
    fi
}

# Prerequisites check
check_prerequisites() {
    info "Checking test prerequisites..."

    # Check if curl is available
    if ! command -v curl >/dev/null 2>&1; then
        error "curl command not found. Install with: sudo apt install curl"
        exit 1
    fi

    # Check if jq is available (optional but helpful)
    if ! command -v jq >/dev/null 2>&1; then
        warn "jq not found. Some tests may be limited. Install with: sudo apt install jq"
    fi

    # Check if docker is available
    if ! command -v docker >/dev/null 2>&1; then
        warn "Docker not available. Container status checks will be skipped."
    fi

    success "Prerequisites check completed"
}

# Container health tests
test_container_health() {
    echo -e "\n${BOLD}Container Health Tests${NC}"
    echo "========================="

    if ! command -v docker >/dev/null 2>&1; then
        test_skip "Container health" "Docker not available"
        return
    fi

    local containers=(
        "adguard-home"
        "prometheus"
        "grafana"
        "alertmanager"
        "node-exporter"
        "adguard-exporter"
    )

    for container in "${containers[@]}"; do
        test_start "Container status - ${container}"

        local status
        status=$(get_container_status "$container")

        if [[ "$status" =~ "Up" ]]; then
            test_pass "Container status - ${container}"
        elif [[ "$status" =~ "Exited" ]]; then
            test_fail "Container status - ${container}" "Container exited"
        else
            test_fail "Container status - ${container}" "Container not found or not running"
        fi
    done
}

# Service endpoint tests
test_service_endpoints() {
    echo -e "\n${BOLD}Service Endpoint Tests${NC}"
    echo "========================="

    for service_info in "${SERVICES[@]}"; do
        local service_name="${service_info%%:*}"
        local endpoint="${service_info#*:}"

        test_start "Endpoint - ${service_name}"

        if check_http_endpoint "$endpoint"; then
            test_pass "Endpoint - ${service_name}"
        else
            test_fail "Endpoint - ${service_name}" "HTTP request failed"
        fi
    done
}

# AdGuard Home specific tests
test_adguard_functionality() {
    echo -e "\n${BOLD}AdGuard Home Functionality Tests${NC}"
    echo "====================================="

    # Test web interface
    test_start "AdGuard web interface"
    if check_http_endpoint "http://localhost:${ADGUARD_WEB_PORT}/"; then
        test_pass "AdGuard web interface"
    else
        test_fail "AdGuard web interface" "Web interface not accessible"
    fi

    # Test API endpoints
    test_start "AdGuard API - status"
    if check_http_endpoint "http://localhost:${ADGUARD_WEB_PORT}/control/status"; then
        test_pass "AdGuard API - status"
    else
        test_fail "AdGuard API - status" "Status API not accessible"
    fi

    test_start "AdGuard API - stats"
    if check_http_endpoint "http://localhost:${ADGUARD_WEB_PORT}/control/stats"; then
        test_pass "AdGuard API - stats"
    else
        test_fail "AdGuard API - stats" "Stats API not accessible"
    fi

    # Test filtering status
    test_start "AdGuard filtering status"
    local filtering_status
    filtering_status=$(curl -s -m 10 "http://localhost:${ADGUARD_WEB_PORT}/control/filtering/status" 2>/dev/null)

    if echo "$filtering_status" | grep -q '"enabled":true' 2>/dev/null; then
        test_pass "AdGuard filtering status"
    elif echo "$filtering_status" | grep -q '"enabled":false' 2>/dev/null; then
        test_fail "AdGuard filtering status" "Filtering is disabled"
    else
        test_fail "AdGuard filtering status" "Cannot determine filtering status"
    fi

    # Test query log
    test_start "AdGuard query log"
    if check_http_endpoint "http://localhost:${ADGUARD_WEB_PORT}/control/querylog"; then
        test_pass "AdGuard query log"
    else
        test_fail "AdGuard query log" "Query log not accessible"
    fi
}

# Prometheus tests
test_prometheus_functionality() {
    echo -e "\n${BOLD}Prometheus Functionality Tests${NC}"
    echo "=================================="

    # Test Prometheus health
    test_start "Prometheus health endpoint"
    if check_http_endpoint "http://localhost:${PROMETHEUS_PORT}/-/healthy"; then
        test_pass "Prometheus health endpoint"
    else
        test_fail "Prometheus health endpoint" "Health endpoint not responding"
    fi

    # Test Prometheus readiness
    test_start "Prometheus readiness"
    if check_http_endpoint "http://localhost:${PROMETHEUS_PORT}/-/ready"; then
        test_pass "Prometheus readiness"
    else
        test_fail "Prometheus readiness" "Readiness check failed"
    fi

    # Test targets endpoint
    test_start "Prometheus targets"
    if check_http_endpoint "http://localhost:${PROMETHEUS_PORT}/api/v1/targets"; then
        test_pass "Prometheus targets"
    else
        test_fail "Prometheus targets" "Targets endpoint not accessible"
    fi

    # Test query endpoint
    test_start "Prometheus query API"
    if check_http_endpoint "http://localhost:${PROMETHEUS_PORT}/api/v1/query?query=up"; then
        test_pass "Prometheus query API"
    else
        test_fail "Prometheus query API" "Query API not working"
    fi

    # Check target health
    test_start "Prometheus target health"
    local targets_response
    targets_response=$(curl -s -m 10 "http://localhost:${PROMETHEUS_PORT}/api/v1/targets" 2>/dev/null)

    if command -v jq >/dev/null 2>&1 && echo "$targets_response" | jq -e '.data.activeTargets' >/dev/null 2>&1; then
        local healthy_targets
        healthy_targets=$(echo "$targets_response" | jq '.data.activeTargets | map(select(.health == "up")) | length')
        local total_targets
        total_targets=$(echo "$targets_response" | jq '.data.activeTargets | length')

        if [[ "$healthy_targets" -eq "$total_targets" ]] && [[ "$total_targets" -gt 0 ]]; then
            test_pass "Prometheus target health (${healthy_targets}/${total_targets} up)"
        else
            test_fail "Prometheus target health" "${healthy_targets}/${total_targets} targets healthy"
        fi
    else
        test_skip "Prometheus target health" "Cannot parse targets response"
    fi
}

# Grafana tests
test_grafana_functionality() {
    echo -e "\n${BOLD}Grafana Functionality Tests${NC}"
    echo "=============================="

    # Test Grafana health
    test_start "Grafana health endpoint"
    if check_http_endpoint "http://localhost:${GRAFANA_PORT}/api/health"; then
        test_pass "Grafana health endpoint"
    else
        test_fail "Grafana health endpoint" "Health endpoint not responding"
    fi

    # Test Grafana API
    test_start "Grafana API"
    if check_http_endpoint "http://localhost:${GRAFANA_PORT}/api/org"; then
        test_pass "Grafana API"
    else
        test_fail "Grafana API" "API not accessible"
    fi

    # Test login page
    test_start "Grafana login page"
    if check_http_endpoint "http://localhost:${GRAFANA_PORT}/login"; then
        test_pass "Grafana login page"
    else
        test_fail "Grafana login page" "Login page not accessible"
    fi

    # Test data sources (if accessible)
    test_start "Grafana data sources"
    local datasources_response
    datasources_response=$(curl -s -m 10 "http://localhost:${GRAFANA_PORT}/api/datasources" 2>/dev/null)

    if [[ -n "$datasources_response" ]] && ! echo "$datasources_response" | grep -q "Unauthorized"; then
        test_pass "Grafana data sources"
    else
        test_skip "Grafana data sources" "Requires authentication or not configured"
    fi
}

# Metrics exporters tests
test_metrics_exporters() {
    echo -e "\n${BOLD}Metrics Exporters Tests${NC}"
    echo "=========================="

    # Test Node Exporter
    test_start "Node Exporter metrics"
    local node_metrics
    node_metrics=$(curl -s -m 10 "http://localhost:${NODE_EXPORTER_PORT}/metrics" 2>/dev/null)

    if echo "$node_metrics" | grep -q "node_" && echo "$node_metrics" | grep -q "HELP"; then
        test_pass "Node Exporter metrics"
    else
        test_fail "Node Exporter metrics" "No valid metrics found"
    fi

    # Test AdGuard Exporter
    test_start "AdGuard Exporter metrics"
    local adguard_metrics
    adguard_metrics=$(curl -s -m 10 "http://localhost:${ADGUARD_EXPORTER_PORT}/metrics" 2>/dev/null)

    if echo "$adguard_metrics" | grep -q "adguard_" && echo "$adguard_metrics" | grep -q "HELP"; then
        test_pass "AdGuard Exporter metrics"
    else
        test_fail "AdGuard Exporter metrics" "No valid AdGuard metrics found"
    fi

    # Test specific AdGuard metrics
    test_start "AdGuard specific metrics"
    if echo "$adguard_metrics" | grep -q "adguard_num_dns_queries" && \
       echo "$adguard_metrics" | grep -q "adguard_num_blocked_filtering"; then
        test_pass "AdGuard specific metrics"
    else
        test_fail "AdGuard specific metrics" "Key AdGuard metrics missing"
    fi
}

# Alertmanager tests
test_alertmanager_functionality() {
    echo -e "\n${BOLD}Alertmanager Functionality Tests${NC}"
    echo "===================================="

    # Test Alertmanager health
    test_start "Alertmanager health endpoint"
    if check_http_endpoint "http://localhost:${ALERTMANAGER_PORT}/-/healthy"; then
        test_pass "Alertmanager health endpoint"
    else
        test_fail "Alertmanager health endpoint" "Health endpoint not responding"
    fi

    # Test Alertmanager ready
    test_start "Alertmanager readiness"
    if check_http_endpoint "http://localhost:${ALERTMANAGER_PORT}/-/ready"; then
        test_pass "Alertmanager readiness"
    else
        test_fail "Alertmanager readiness" "Readiness check failed"
    fi

    # Test alerts API
    test_start "Alertmanager alerts API"
    if check_http_endpoint "http://localhost:${ALERTMANAGER_PORT}/api/v1/alerts"; then
        test_pass "Alertmanager alerts API"
    else
        test_fail "Alertmanager alerts API" "Alerts API not accessible"
    fi

    # Test status API
    test_start "Alertmanager status API"
    if check_http_endpoint "http://localhost:${ALERTMANAGER_PORT}/api/v1/status"; then
        test_pass "Alertmanager status API"
    else
        test_fail "Alertmanager status API" "Status API not accessible"
    fi
}

# Service integration tests
test_service_integration() {
    echo -e "\n${BOLD}Service Integration Tests${NC}"
    echo "==========================="

    # Test Prometheus scraping AdGuard Exporter
    test_start "Prometheus → AdGuard Exporter"
    local query_result
    query_result=$(curl -s -m 10 "http://localhost:${PROMETHEUS_PORT}/api/v1/query?query=up{job=\"adguard-exporter\"}" 2>/dev/null)

    if echo "$query_result" | grep -q '"value":\[.*,"1"\]'; then
        test_pass "Prometheus → AdGuard Exporter"
    else
        test_fail "Prometheus → AdGuard Exporter" "Target not being scraped successfully"
    fi

    # Test Prometheus scraping Node Exporter
    test_start "Prometheus → Node Exporter"
    query_result=$(curl -s -m 10 "http://localhost:${PROMETHEUS_PORT}/api/v1/query?query=up{job=\"node-exporter\"}" 2>/dev/null)

    if echo "$query_result" | grep -q '"value":\[.*,"1"\]'; then
        test_pass "Prometheus → Node Exporter"
    else
        test_fail "Prometheus → Node Exporter" "Target not being scraped successfully"
    fi

    # Test AdGuard Exporter → AdGuard Home
    test_start "AdGuard Exporter → AdGuard Home"
    local adguard_metrics
    adguard_metrics=$(curl -s -m 10 "http://localhost:${ADGUARD_EXPORTER_PORT}/metrics" 2>/dev/null)

    if echo "$adguard_metrics" | grep -q "adguard_num_dns_queries.*[1-9]"; then
        test_pass "AdGuard Exporter → AdGuard Home"
    else
        test_skip "AdGuard Exporter → AdGuard Home" "No DNS queries recorded yet"
    fi

    # Test Alertmanager → Prometheus
    test_start "Alertmanager ← Prometheus"
    local alertmanager_config
    alertmanager_config=$(curl -s -m 10 "http://localhost:${PROMETHEUS_PORT}/api/v1/alertmanagers" 2>/dev/null)

    if echo "$alertmanager_config" | grep -q "localhost:${ALERTMANAGER_PORT}"; then
        test_pass "Alertmanager ← Prometheus"
    else
        test_fail "Alertmanager ← Prometheus" "Alertmanager not configured in Prometheus"
    fi
}

# Performance tests
test_service_performance() {
    echo -e "\n${BOLD}Service Performance Tests${NC}"
    echo "============================"

    local services_perf=(
        "AdGuard:http://localhost:${ADGUARD_WEB_PORT}/"
        "Prometheus:http://localhost:${PROMETHEUS_PORT}/-/healthy"
        "Grafana:http://localhost:${GRAFANA_PORT}/api/health"
    )

    for service_info in "${services_perf[@]}"; do
        local service_name="${service_info%%:*}"
        local endpoint="${service_info#*:}"

        test_start "Response time - ${service_name}"

        local start_time end_time response_time
        start_time=$(date +%s%N)

        if curl -f -s -m 10 "$endpoint" >/dev/null 2>&1; then
            end_time=$(date +%s%N)
            response_time=$(( (end_time - start_time) / 1000000 ))  # Convert to milliseconds

            if [[ $response_time -lt 1000 ]]; then
                test_pass "Response time - ${service_name} (${response_time}ms)"
            else
                test_fail "Response time - ${service_name}" "Slow response: ${response_time}ms"
            fi
        else
            test_fail "Response time - ${service_name}" "Request failed"
        fi
    done
}

# Security tests
test_service_security() {
    echo -e "\n${BOLD}Service Security Tests${NC}"
    echo "========================="

    # Test that services are not exposing dangerous endpoints
    local dangerous_endpoints=(
        "http://localhost:${ADGUARD_WEB_PORT}/control/install/configure"
        "http://localhost:${PROMETHEUS_PORT}/api/v1/admin/tsdb/delete_series"
        "http://localhost:${GRAFANA_PORT}/api/admin/users"
    )

    for endpoint in "${dangerous_endpoints[@]}"; do
        local service_name
        service_name=$(echo "$endpoint" | sed 's|.*://localhost:[0-9]*/||' | cut -d'/' -f1)

        test_start "Security - ${service_name} admin endpoints"

        local status_code
        status_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$endpoint" 2>/dev/null || echo "000")

        if [[ "$status_code" == "401" ]] || [[ "$status_code" == "403" ]] || [[ "$status_code" == "404" ]]; then
            test_pass "Security - ${service_name} admin endpoints"
        elif [[ "$status_code" == "000" ]]; then
            test_skip "Security - ${service_name} admin endpoints" "Endpoint unreachable"
        else
            test_fail "Security - ${service_name} admin endpoints" "Admin endpoint accessible (${status_code})"
        fi
    done

    # Test HTTPS redirect (if configured)
    test_start "HTTPS enforcement"
    local http_response
    http_response=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "http://localhost:${ADGUARD_WEB_PORT}/" 2>/dev/null || echo "000")

    if [[ "$http_response" == "301" ]] || [[ "$http_response" == "302" ]]; then
        test_pass "HTTPS enforcement"
    else
        test_skip "HTTPS enforcement" "HTTPS not configured or not enforced"
    fi
}

# Resource usage tests
test_resource_usage() {
    echo -e "\n${BOLD}Resource Usage Tests${NC}"
    echo "======================="

    if ! command -v docker >/dev/null 2>&1; then
        test_skip "Resource usage" "Docker not available"
        return
    fi

    # Test container memory usage
    test_start "Container memory usage"
    local high_memory_containers
    high_memory_containers=$(docker stats --no-stream --format "table {{.Name}}\t{{.MemPerc}}" 2>/dev/null | \
                           awk 'NR>1 && $2+0 > 80 {print $1}' | wc -l)

    if [[ "$high_memory_containers" -eq 0 ]]; then
        test_pass "Container memory usage"
    else
        test_fail "Container memory usage" "${high_memory_containers} containers using >80% memory"
    fi

    # Test container CPU usage
    test_start "Container CPU usage"
    local high_cpu_containers
    high_cpu_containers=$(docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}" 2>/dev/null | \
                         awk 'NR>1 && $2+0 > 80 {print $1}' | wc -l)

    if [[ "$high_cpu_containers" -eq 0 ]]; then
        test_pass "Container CPU usage"
    else
        test_fail "Container CPU usage" "${high_cpu_containers} containers using >80% CPU"
    fi
}

# Data persistence tests
test_data_persistence() {
    echo -e "\n${BOLD}Data Persistence Tests${NC}"
    echo "========================="

    local data_directories=(
        "/opt/adguard/data"
        "/opt/monitoring/prometheus/data"
        "/opt/monitoring/grafana/data"
    )

    for data_dir in "${data_directories[@]}"; do
        local service_name
        service_name=$(basename "$(dirname "$data_dir")")

        test_start "Data persistence - ${service_name}"

        if [[ -d "$data_dir" ]] && [[ -w "$data_dir" ]]; then
            # Check if directory has some data
            local file_count
            file_count=$(find "$data_dir" -type f 2>/dev/null | wc -l)

            if [[ "$file_count" -gt 0 ]]; then
                test_pass "Data persistence - ${service_name}"
            else
                test_skip "Data persistence - ${service_name}" "No data files found (new installation?)"
            fi
        else
            test_fail "Data persistence - ${service_name}" "Data directory not accessible"
        fi
    done
}

# Generate test report
generate_report() {
    echo -e "\n${BOLD}Service Integration Test Report${NC}"
    echo "======================================"
    echo "Test execution completed at: $(date)"
    echo "Log file: ${TEST_LOG}"
    echo ""
    echo "Results:"
    echo "  Total tests:  ${TESTS_TOTAL}"
    echo -e "  Passed:       ${GREEN}${TESTS_PASSED}${NC}"
    echo -e "  Failed:       ${RED}${TESTS_FAILED}${NC}"
    echo -e "  Skipped:      ${YELLOW}${TESTS_SKIPPED}${NC}"
    echo ""

    local success_rate=0
    if [[ $TESTS_TOTAL -gt 0 ]]; then
        success_rate=$(( (TESTS_PASSED * 100) / (TESTS_TOTAL - TESTS_SKIPPED) ))
    fi

    echo "Success Rate: ${success_rate}%"

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "\n${GREEN}${BOLD}✓ All service tests passed successfully!${NC}"
        echo "AdGuard infrastructure is healthy and all services are functioning properly."
        return 0
    else
        echo -e "\n${RED}${BOLD}✗ Some service tests failed.${NC}"
        echo "Check the test log for detailed information about failures."
        return 1
    fi
}

# Cleanup function
cleanup() {
    # Clean up any temporary files
    rm -f /tmp/adguard_service_test_*
}

# Main execution
main() {
    echo -e "${BOLD}AdGuard Home Service Integration Tests${NC}"
    echo -e "${BLUE}Comprehensive Service Health Testing${NC}"
    echo "=============================================="
    echo "Testing all infrastructure services and their integration"
    echo "Log: ${TEST_LOG}"
    echo ""

    # Set up cleanup trap
    trap cleanup EXIT

    # Check prerequisites
    check_prerequisites

    # Run test suites
    test_container_health
    test_service_endpoints
    test_adguard_functionality
    test_prometheus_functionality
    test_grafana_functionality
    test_metrics_exporters
    test_alertmanager_functionality
    test_service_integration
    test_service_performance
    test_service_security
    test_resource_usage
    test_data_persistence

    # Generate final report
    generate_report
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
        echo "  ADGUARD_WEB_PORT     AdGuard web interface port (default: 3000)"
        echo "  GRAFANA_PORT         Grafana port (default: 3001)"
        echo "  PROMETHEUS_PORT      Prometheus port (default: 9090)"
        echo "  TEST_TIMEOUT         Test timeout in seconds"
        exit 0
        ;;
    --timeout)
        TEST_TIMEOUT="$2"
        shift 2
        ;;
    *)
        # No arguments, run main
        ;;
esac

# Run main function
main "$@"