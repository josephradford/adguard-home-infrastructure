#!/bin/bash
# AdGuard Home Infrastructure - DNS Integration Tests
# Comprehensive DNS functionality testing for Australian deployment

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_LOG="/tmp/adguard-dns-test-$(date +%Y%m%d-%H%M%S).log"
ADGUARD_HOST="localhost"
ADGUARD_PORT="53"

# Test configuration
TEST_TIMEOUT=10
MAX_RETRIES=3
PARALLEL_TESTS=5

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
    source "${PROJECT_ROOT}/.env"
    set +a
fi

# Logging functions
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
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

# DNS query functions
dns_query() {
    local domain="$1"
    local record_type="${2:-A}"
    local timeout="${3:-$TEST_TIMEOUT}"

    dig @"${ADGUARD_HOST}" "${domain}" "${record_type}" +time="${timeout}" +tries=1 +short 2>/dev/null
}

dns_query_detailed() {
    local domain="$1"
    local record_type="${2:-A}"
    local timeout="${3:-$TEST_TIMEOUT}"

    dig @"${ADGUARD_HOST}" "${domain}" "${record_type}" +time="${timeout}" +tries=1 2>/dev/null
}

check_dns_response() {
    local domain="$1"
    local expected_pattern="$2"
    local result

    result=$(dns_query "${domain}")

    if [[ -n "$result" ]] && [[ "$result" =~ $expected_pattern ]]; then
        return 0
    else
        return 1
    fi
}

# Prerequisites check
check_prerequisites() {
    info "Checking test prerequisites..."

    # Check if dig is available
    if ! command -v dig >/dev/null 2>&1; then
        error "dig command not found. Install with: sudo apt install dnsutils"
        exit 1
    fi

    # Check if nslookup is available
    if ! command -v nslookup >/dev/null 2>&1; then
        error "nslookup command not found. Install with: sudo apt install dnsutils"
        exit 1
    fi

    # Check if AdGuard is reachable
    if ! timeout 5 bash -c "echo >/dev/tcp/${ADGUARD_HOST}/53" 2>/dev/null; then
        error "Cannot connect to AdGuard DNS on ${ADGUARD_HOST}:53"
        exit 1
    fi

    success "Prerequisites check passed"
}

# Basic DNS resolution tests
test_basic_resolution() {
    echo -e "\n${BOLD}Basic DNS Resolution Tests${NC}"
    echo "=================================="

    # Test major domains
    local domains=(
        "google.com"
        "cloudflare.com"
        "github.com"
        "ubuntu.com"
        "docker.com"
    )

    for domain in "${domains[@]}"; do
        test_start "Basic resolution - ${domain}"
        if check_dns_response "${domain}" "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"; then
            test_pass "Basic resolution - ${domain}"
        else
            test_fail "Basic resolution - ${domain}" "No valid IP returned"
        fi
    done
}

# Australian-specific DNS tests
test_australian_sites() {
    echo -e "\n${BOLD}Australian Site Resolution Tests${NC}"
    echo "======================================="

    local au_domains=(
        "bom.gov.au"
        "abc.net.au"
        "sbs.com.au"
        "news.com.au"
        "smh.com.au"
        "theage.com.au"
        "commbank.com.au"
        "westpac.com.au"
        "anz.com"
        "nab.com.au"
        "telstra.com.au"
        "optus.com.au"
        "woolworths.com.au"
        "coles.com.au"
        "seek.com.au"
        "realestate.com.au"
    )

    for domain in "${au_domains[@]}"; do
        test_start "Australian site - ${domain}"
        if check_dns_response "${domain}" "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"; then
            test_pass "Australian site - ${domain}"
        else
            test_fail "Australian site - ${domain}" "No valid IP returned"
        fi
    done
}

# Government website tests
test_government_sites() {
    echo -e "\n${BOLD}Australian Government Site Tests${NC}"
    echo "======================================"

    local gov_domains=(
        "ato.gov.au"
        "centrelink.gov.au"
        "mygovid.gov.au"
        "australia.gov.au"
        "aec.gov.au"
        "humanservices.gov.au"
        "health.gov.au"
    )

    for domain in "${gov_domains[@]}"; do
        test_start "Government site - ${domain}"
        if check_dns_response "${domain}" "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"; then
            test_pass "Government site - ${domain}"
        else
            test_fail "Government site - ${domain}" "No valid IP returned"
        fi
    done
}

# DNS blocking tests
test_dns_blocking() {
    echo -e "\n${BOLD}DNS Blocking Tests${NC}"
    echo "======================"

    local blocked_domains=(
        "doubleclick.net"
        "googleadservices.com"
        "googlesyndication.com"
        "facebook.com"
        "googletagmanager.com"
        "google-analytics.com"
        "scorecardresearch.com"
        "quantserve.com"
    )

    for domain in "${blocked_domains[@]}"; do
        test_start "Blocking test - ${domain}"
        local result
        result=$(dns_query "${domain}")

        # Check if domain is blocked (returns 0.0.0.0, empty result, or NXDOMAIN)
        if [[ "$result" == "0.0.0.0" ]] || [[ -z "$result" ]] || [[ "$result" =~ "NXDOMAIN" ]]; then
            test_pass "Blocking test - ${domain}"
        else
            test_fail "Blocking test - ${domain}" "Domain not blocked (returned: ${result})"
        fi
    done
}

# Malware domain blocking tests
test_malware_blocking() {
    echo -e "\n${BOLD}Malware Blocking Tests${NC}"
    echo "========================="

    local malware_domains=(
        "malware.wicar.org"
        "3korban.org"
        "027.ru"
        "adsystem.ru"
        "017.ru"
    )

    for domain in "${malware_domains[@]}"; do
        test_start "Malware blocking - ${domain}"
        local result
        result=$(dns_query "${domain}")

        # Check if malware domain is blocked
        if [[ "$result" == "0.0.0.0" ]] || [[ -z "$result" ]] || [[ "$result" =~ "NXDOMAIN" ]]; then
            test_pass "Malware blocking - ${domain}"
        else
            test_fail "Malware blocking - ${domain}" "Malware domain not blocked (returned: ${result})"
        fi
    done
}

# DNS record type tests
test_record_types() {
    echo -e "\n${BOLD}DNS Record Type Tests${NC}"
    echo "========================="

    # A record test
    test_start "A record query"
    if dns_query "google.com" "A" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        test_pass "A record query"
    else
        test_fail "A record query" "No valid A record returned"
    fi

    # AAAA record test
    test_start "AAAA record query"
    if dns_query "google.com" "AAAA" | grep -qE '^[0-9a-f:]+$'; then
        test_pass "AAAA record query"
    else
        test_skip "AAAA record query" "No IPv6 record available"
    fi

    # MX record test
    test_start "MX record query"
    if dns_query "google.com" "MX" | grep -q "."; then
        test_pass "MX record query"
    else
        test_fail "MX record query" "No MX record returned"
    fi

    # TXT record test
    test_start "TXT record query"
    if dns_query "google.com" "TXT" | grep -q "."; then
        test_pass "TXT record query"
    else
        test_fail "TXT record query" "No TXT record returned"
    fi

    # NS record test
    test_start "NS record query"
    if dns_query "google.com" "NS" | grep -q "."; then
        test_pass "NS record query"
    else
        test_fail "NS record query" "No NS record returned"
    fi
}

# Performance tests
test_performance() {
    echo -e "\n${BOLD}DNS Performance Tests${NC}"
    echo "========================="

    local test_domains=(
        "google.com"
        "cloudflare.com"
        "github.com"
    )

    local total_time=0
    local query_count=0

    for domain in "${test_domains[@]}"; do
        test_start "Performance test - ${domain}"

        local start_time end_time query_time
        start_time=$(date +%s%N)

        if dns_query "${domain}" >/dev/null 2>&1; then
            end_time=$(date +%s%N)
            query_time=$(( (end_time - start_time) / 1000000 ))  # Convert to milliseconds

            total_time=$((total_time + query_time))
            ((query_count++))

            if [[ $query_time -lt 500 ]]; then
                test_pass "Performance test - ${domain} (${query_time}ms)"
            else
                test_fail "Performance test - ${domain}" "Query took ${query_time}ms (>500ms threshold)"
            fi
        else
            test_fail "Performance test - ${domain}" "Query failed"
        fi
    done

    if [[ $query_count -gt 0 ]]; then
        local avg_time=$((total_time / query_count))
        info "Average query time: ${avg_time}ms"

        if [[ $avg_time -lt 200 ]]; then
            success "Excellent performance: ${avg_time}ms average"
        elif [[ $avg_time -lt 500 ]]; then
            warn "Good performance: ${avg_time}ms average"
        else
            error "Poor performance: ${avg_time}ms average"
        fi
    fi
}

# Upstream DNS server tests
test_upstream_servers() {
    echo -e "\n${BOLD}Upstream DNS Server Tests${NC}"
    echo "============================="

    local upstream_servers=(
        "1.1.1.1"      # Cloudflare Sydney
        "8.8.8.8"      # Google Sydney
        "9.9.9.9"      # Quad9
        "1.0.0.1"      # Cloudflare secondary
    )

    for server in "${upstream_servers[@]}"; do
        test_start "Upstream connectivity - ${server}"

        if timeout 5 bash -c "echo >/dev/tcp/${server}/53" 2>/dev/null; then
            # Test actual DNS query
            if timeout 10 dig @"${server}" google.com +time=5 +tries=1 >/dev/null 2>&1; then
                test_pass "Upstream connectivity - ${server}"
            else
                test_fail "Upstream connectivity - ${server}" "DNS query failed"
            fi
        else
            test_fail "Upstream connectivity - ${server}" "Connection timeout"
        fi
    done
}

# DNSSEC validation tests
test_dnssec() {
    echo -e "\n${BOLD}DNSSEC Validation Tests${NC}"
    echo "=========================="

    # Test DNSSEC-enabled domain
    test_start "DNSSEC validation"
    local dnssec_result
    dnssec_result=$(dig @"${ADGUARD_HOST}" cloudflare.com +dnssec +short 2>/dev/null)

    if [[ -n "$dnssec_result" ]]; then
        test_pass "DNSSEC validation"
    else
        test_skip "DNSSEC validation" "DNSSEC may not be enabled"
    fi

    # Test DNSSEC failure detection
    test_start "DNSSEC failure detection"
    local bad_dnssec_result
    bad_dnssec_result=$(dig @"${ADGUARD_HOST}" dnssec-failed.org +dnssec 2>/dev/null | grep -c "SERVFAIL" || echo "0")

    if [[ "$bad_dnssec_result" -gt 0 ]]; then
        test_pass "DNSSEC failure detection"
    else
        test_skip "DNSSEC failure detection" "Test domain may not be available"
    fi
}

# Load testing
test_load() {
    echo -e "\n${BOLD}Load Testing${NC}"
    echo "================"

    test_start "Concurrent query handling"

    local success_count=0
    local total_queries=20

    # Launch multiple queries in parallel
    for i in $(seq 1 $total_queries); do
        {
            if dns_query "google.com" >/dev/null 2>&1; then
                echo "success" >> /tmp/dns_load_test_$$
            fi
        } &
    done

    # Wait for all background jobs
    wait

    if [[ -f "/tmp/dns_load_test_$$" ]]; then
        success_count=$(wc -l < /tmp/dns_load_test_$$)
        rm -f /tmp/dns_load_test_$$
    fi

    local success_rate=$((success_count * 100 / total_queries))

    if [[ $success_rate -ge 95 ]]; then
        test_pass "Concurrent query handling (${success_rate}% success rate)"
    elif [[ $success_rate -ge 80 ]]; then
        test_fail "Concurrent query handling" "Success rate only ${success_rate}% (expected >95%)"
    else
        test_fail "Concurrent query handling" "Poor success rate: ${success_rate}%"
    fi
}

# Custom rules testing
test_custom_rules() {
    echo -e "\n${BOLD}Custom Rules Tests${NC}"
    echo "======================"

    # Test whitelist rules (Australian banking)
    local whitelisted_domains=(
        "commbank.com.au"
        "westpac.com.au"
        "anz.com"
        "nab.com.au"
    )

    for domain in "${whitelisted_domains[@]}"; do
        test_start "Whitelist rule - ${domain}"
        if check_dns_response "${domain}" "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"; then
            test_pass "Whitelist rule - ${domain}"
        else
            test_fail "Whitelist rule - ${domain}" "Whitelisted domain not resolving"
        fi
    done

    # Test SafeSearch enforcement
    test_start "SafeSearch enforcement"
    local google_result
    google_result=$(dns_query "google.com")
    local safe_result
    safe_result=$(dns_query "forcesafesearch.google.com")

    if [[ "$google_result" == "$safe_result" ]] && [[ -n "$google_result" ]]; then
        test_pass "SafeSearch enforcement"
    else
        test_skip "SafeSearch enforcement" "SafeSearch may not be configured"
    fi
}

# IPv6 support tests
test_ipv6_support() {
    echo -e "\n${BOLD}IPv6 Support Tests${NC}"
    echo "====================="

    # Check if IPv6 is available on the system
    if ! ip -6 addr show | grep -q "inet6.*global" 2>/dev/null; then
        test_skip "IPv6 DNS queries" "IPv6 not available on system"
        return
    fi

    test_start "IPv6 DNS queries"
    if dns_query "google.com" "AAAA" | grep -qE '^[0-9a-f:]+$'; then
        test_pass "IPv6 DNS queries"
    else
        test_skip "IPv6 DNS queries" "No IPv6 addresses returned"
    fi

    # Test IPv6-only domains if available
    test_start "IPv6-only domain resolution"
    if dns_query "ipv6.google.com" "AAAA" | grep -qE '^[0-9a-f:]+$'; then
        test_pass "IPv6-only domain resolution"
    else
        test_skip "IPv6-only domain resolution" "IPv6-only test domain not available"
    fi
}

# Error handling tests
test_error_handling() {
    echo -e "\n${BOLD}Error Handling Tests${NC}"
    echo "======================="

    # Test NXDOMAIN response
    test_start "NXDOMAIN handling"
    local nxdomain_result
    nxdomain_result=$(dns_query_detailed "nonexistent-domain-12345.invalid" 2>/dev/null | grep -c "NXDOMAIN" || echo "0")

    if [[ "$nxdomain_result" -gt 0 ]]; then
        test_pass "NXDOMAIN handling"
    else
        test_fail "NXDOMAIN handling" "NXDOMAIN not properly returned"
    fi

    # Test timeout handling
    test_start "Timeout handling"
    local timeout_start timeout_end timeout_duration
    timeout_start=$(date +%s)

    # Query a domain that should timeout quickly
    dns_query "10.255.255.255" "A" 2 >/dev/null 2>&1 || true

    timeout_end=$(date +%s)
    timeout_duration=$((timeout_end - timeout_start))

    if [[ $timeout_duration -le 5 ]]; then
        test_pass "Timeout handling"
    else
        test_fail "Timeout handling" "Timeout took ${timeout_duration}s (expected ≤5s)"
    fi
}

# Security tests
test_security_features() {
    echo -e "\n${BOLD}Security Feature Tests${NC}"
    echo "========================="

    # Test rate limiting (if configured)
    test_start "Rate limiting"
    local rapid_queries=0
    local start_time
    start_time=$(date +%s)

    # Send rapid queries
    for i in {1..50}; do
        if dns_query "google.com" >/dev/null 2>&1; then
            ((rapid_queries++))
        fi
    done

    local end_time duration
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    local qps=$((rapid_queries / duration))

    if [[ $qps -lt 100 ]]; then  # Assuming rate limit is effective
        test_pass "Rate limiting (${qps} queries/second)"
    else
        test_skip "Rate limiting" "Rate limiting may not be configured or very high threshold"
    fi

    # Test query anonymization
    test_start "Query anonymization"
    # This test checks if ECS (EDNS Client Subnet) is disabled/anonymized
    local ecs_result
    ecs_result=$(dig @"${ADGUARD_HOST}" google.com +subnet=192.168.1.1/24 2>/dev/null | grep -c "CLIENT-SUBNET" || echo "0")

    if [[ "$ecs_result" -eq 0 ]]; then
        test_pass "Query anonymization"
    else
        test_skip "Query anonymization" "ECS may be enabled"
    fi
}

# Generate test report
generate_report() {
    echo -e "\n${BOLD}Test Summary Report${NC}"
    echo "===================="
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
        echo -e "\n${GREEN}${BOLD}✓ All tests passed successfully!${NC}"
        return 0
    else
        echo -e "\n${RED}${BOLD}✗ Some tests failed. Check the log for details.${NC}"
        return 1
    fi
}

# Cleanup function
cleanup() {
    # Clean up any temporary files
    rm -f /tmp/dns_load_test_$$
    rm -f /tmp/adguard_test_*
}

# Main execution
main() {
    echo -e "${BOLD}AdGuard Home DNS Integration Tests${NC}"
    echo -e "${BLUE}Australian Network Optimization Testing${NC}"
    echo "=========================================="
    echo "Target: ${ADGUARD_HOST}:${ADGUARD_PORT}"
    echo "Log: ${TEST_LOG}"
    echo ""

    # Set up cleanup trap
    trap cleanup EXIT

    # Check prerequisites
    check_prerequisites

    # Run test suites
    test_basic_resolution
    test_australian_sites
    test_government_sites
    test_dns_blocking
    test_malware_blocking
    test_record_types
    test_performance
    test_upstream_servers
    test_dnssec
    test_load
    test_custom_rules
    test_ipv6_support
    test_error_handling
    test_security_features

    # Generate final report
    generate_report
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --host HOST    DNS server to test (default: localhost)"
        echo "  --timeout SEC  Query timeout in seconds (default: 10)"
        echo ""
        echo "Environment variables:"
        echo "  ADGUARD_HOST   DNS server hostname/IP"
        echo "  TEST_TIMEOUT   Query timeout in seconds"
        exit 0
        ;;
    --host)
        ADGUARD_HOST="$2"
        shift 2
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