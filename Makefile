# AdGuard Home Infrastructure - Makefile
# Comprehensive operational commands for Australian home network DNS infrastructure

# Variables
SHELL := /bin/bash
.DEFAULT_GOAL := help
PROJECT_ROOT := $(shell pwd)
COMPOSE_FILE := $(PROJECT_ROOT)/docker/docker-compose.yml
ENV_FILE := $(PROJECT_ROOT)/.env
BACKUP_DIR := /opt/backups
LOG_DIR := /opt/logs

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
BOLD := \033[1m
NC := \033[0m # No Color

# Check if .env file exists
ifeq (,$(wildcard $(ENV_FILE)))
$(warning $(YELLOW)Warning: .env file not found. Copy .env.example to .env and configure it.$(NC))
endif

# Load environment variables if .env exists
ifneq (,$(wildcard $(ENV_FILE)))
include $(ENV_FILE)
export
endif

##@ Help
.PHONY: help
help: ## Display this help message
	@echo "$(BOLD)AdGuard Home Infrastructure - Management Commands$(NC)"
	@echo "$(BLUE)Optimized for Australian home networks$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "\n$(BOLD)Usage:$(NC)\n  make $(YELLOW)<target>$(NC)\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(BOLD)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Installation & Setup
.PHONY: install
install: check-root ## Complete infrastructure installation
	@echo "$(BLUE)Starting AdGuard Home Infrastructure installation...$(NC)"
	@if [ ! -f "$(ENV_FILE)" ]; then \
		echo "$(RED)Error: .env file not found. Run 'make config' first.$(NC)"; \
		exit 1; \
	fi
	@chmod +x scripts/**/*.sh configs/firewall/ufw-rules.sh
	@sudo scripts/setup/install.sh
	@echo "$(GREEN)Installation completed successfully!$(NC)"
	@echo "$(YELLOW)Access your services:$(NC)"
	@echo "  AdGuard Home: http://$(STATIC_IP):$(ADGUARD_WEB_PORT)"
	@echo "  Grafana:      http://$(STATIC_IP):$(GRAFANA_PORT)"
	@echo "  Prometheus:   http://$(STATIC_IP):$(PROMETHEUS_PORT)"

.PHONY: config
config: ## Create configuration from template
	@echo "$(BLUE)Creating configuration from template...$(NC)"
	@if [ -f "$(ENV_FILE)" ]; then \
		echo "$(YELLOW)Warning: .env file already exists. Backing up to .env.backup$(NC)"; \
		cp $(ENV_FILE) $(ENV_FILE).backup; \
	fi
	@cp .env.example $(ENV_FILE)
	@echo "$(GREEN)Configuration file created: $(ENV_FILE)$(NC)"
	@echo "$(YELLOW)Please edit $(ENV_FILE) with your specific settings before running 'make install'$(NC)"

.PHONY: dev-setup
dev-setup: ## Set up development environment
	@echo "$(BLUE)Setting up development environment...$(NC)"
	@sudo apt-get update
	@sudo apt-get install -y shellcheck yamllint jq yq docker.io docker compose
	@sudo usermod -aG docker $$USER
	@echo "$(GREEN)Development environment setup completed$(NC)"
	@echo "$(YELLOW)Please log out and back in for Docker group membership to take effect$(NC)"

##@ Service Management
.PHONY: start
start: check-env ## Start all services
	@echo "$(BLUE)Starting AdGuard infrastructure services...$(NC)"
	@cd docker && docker compose up -d
	@echo "$(GREEN)Services started successfully$(NC)"
	@$(MAKE) status

.PHONY: stop
stop: ## Stop all services
	@echo "$(BLUE)Stopping AdGuard infrastructure services...$(NC)"
	@cd docker && docker compose down --timeout 30 || true
	@echo "$(BLUE)Cleaning up docker-proxy processes...$(NC)"
	@set +e; \
	sudo pkill -f "docker-proxy.*:$(ADGUARD_WEB_PORT)" 2>/dev/null; \
	sudo pkill -f "docker-proxy.*:$(GRAFANA_PORT)" 2>/dev/null; \
	sudo pkill -f "docker-proxy.*:$(PROMETHEUS_PORT)" 2>/dev/null; \
	sudo pkill -f "docker-proxy.*:$(NODE_EXPORTER_PORT)" 2>/dev/null; \
	sudo pkill -f "docker-proxy.*:$(ADGUARD_EXPORTER_PORT)" 2>/dev/null; \
	sudo pkill -f "docker-proxy.*:$(ALERTMANAGER_PORT)" 2>/dev/null; \
	sudo pkill -f "docker-proxy.*:53" 2>/dev/null; \
	set -e
	@echo "$(GREEN)Services stopped and cleaned up successfully$(NC)"

.PHONY: restart
restart: ## Restart all services
	@echo "$(BLUE)Restarting AdGuard infrastructure services...$(NC)"
	@cd docker && docker compose restart
	@echo "$(GREEN)Services restarted successfully$(NC)"
	@$(MAKE) status

.PHONY: status
status: ## Show service status
	@echo "$(BOLD)Service Status:$(NC)"
	@cd docker && docker compose ps
	@echo ""
	@echo "$(BOLD)Resource Usage:$(NC)"
	@docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}" 2>/dev/null || echo "Docker stats unavailable"

.PHONY: logs
logs: ## View service logs (use 'make logs service=adguard' for specific service)
	@if [ -n "$(service)" ]; then \
		echo "$(BLUE)Showing logs for service: $(service)$(NC)"; \
		cd docker && docker compose logs -f $(service); \
	else \
		echo "$(BLUE)Showing logs for all services...$(NC)"; \
		cd docker && docker compose logs -f; \
	fi

##@ Health & Monitoring
.PHONY: health
health: ## Comprehensive health check
	@echo "$(BOLD)AdGuard Infrastructure Health Check$(NC)"
	@echo "======================================="
	@echo ""

	@echo "$(BOLD)1. Container Status:$(NC)"
	@cd docker && docker compose ps || echo "$(RED)Failed to get container status$(NC)"
	@echo ""

	@echo "$(BOLD)2. DNS Resolution Test:$(NC)"
	@if command -v dig >/dev/null 2>&1; then \
		echo -n "  Testing DNS resolution... "; \
		if dig @localhost google.com +time=5 +tries=1 >/dev/null 2>&1; then \
			echo "$(GREEN)✓ PASS$(NC)"; \
		else \
			echo "$(RED)✗ FAIL$(NC)"; \
		fi; \
	else \
		echo "  $(YELLOW)dig command not available$(NC)"; \
	fi

	@echo "$(BOLD)3. Web Interface Tests:$(NC)"
	@echo -n "  AdGuard Home (port $(ADGUARD_WEB_PORT))... "
	@if curl -f -s -m 5 http://localhost:$(ADGUARD_WEB_PORT)/ >/dev/null 2>&1; then \
		echo "$(GREEN)✓ PASS$(NC)"; \
	else \
		echo "$(RED)✗ FAIL$(NC)"; \
	fi

	@echo -n "  Grafana (port $(GRAFANA_PORT))... "
	@if curl -f -s -m 5 http://localhost:$(GRAFANA_PORT)/api/health >/dev/null 2>&1; then \
		echo "$(GREEN)✓ PASS$(NC)"; \
	else \
		echo "$(RED)✗ FAIL$(NC)"; \
	fi

	@echo -n "  Prometheus (port $(PROMETHEUS_PORT))... "
	@if curl -f -s -m 5 http://localhost:$(PROMETHEUS_PORT)/-/healthy >/dev/null 2>&1; then \
		echo "$(GREEN)✓ PASS$(NC)"; \
	else \
		echo "$(RED)✗ FAIL$(NC)"; \
	fi

	@echo ""
	@echo "$(BOLD)4. System Resources:$(NC)"
	@echo -n "  Memory usage... "
	@mem_usage=$$(free | awk 'NR==2{printf "%.0f", $$3*100/$$2}'); \
	if [ $$mem_usage -lt 85 ]; then \
		echo "$(GREEN)$$mem_usage% ✓$(NC)"; \
	else \
		echo "$(YELLOW)$$mem_usage% ⚠$(NC)"; \
	fi

	@echo -n "  Disk usage... "
	@disk_usage=$$(df / | awk 'NR==2 {print $$5}' | sed 's/%//'); \
	if [ $$disk_usage -lt 85 ]; then \
		echo "$(GREEN)$$disk_usage% ✓$(NC)"; \
	else \
		echo "$(YELLOW)$$disk_usage% ⚠$(NC)"; \
	fi

	@echo ""
	@echo "$(BOLD)5. DNS Blocking Test:$(NC)"
	@if command -v dig >/dev/null 2>&1; then \
		echo -n "  Testing ad blocking... "; \
		result=$$(dig @localhost doubleclick.net +short +time=5 +tries=1 2>/dev/null | head -1); \
		if [ "$$result" = "0.0.0.0" ] || [ -z "$$result" ]; then \
			echo "$(GREEN)✓ BLOCKING$(NC)"; \
		else \
			echo "$(YELLOW)⚠ NOT BLOCKING$(NC)"; \
		fi; \
	fi

	@echo ""
	@if scripts/monitoring/comprehensive-monitor.sh >/dev/null 2>&1; then \
		echo "$(GREEN)Overall Health: GOOD$(NC)"; \
	else \
		echo "$(YELLOW)Overall Health: CHECK REQUIRED$(NC)"; \
	fi

.PHONY: monitor
monitor: ## Run comprehensive security monitoring
	@echo "$(BLUE)Running comprehensive security monitoring...$(NC)"
	@sudo scripts/monitoring/comprehensive-monitor.sh
	@echo "$(GREEN)Monitoring scan completed$(NC)"

.PHONY: metrics
metrics: ## Show key metrics
	@echo "$(BOLD)AdGuard Infrastructure Metrics$(NC)"
	@echo "=================================="
	@echo ""

	@if curl -s -m 5 http://localhost:${ADGUARD_EXPORTER_PORT:-9617}/metrics >/dev/null 2>&1; then \
		echo "$(BOLD)DNS Metrics:$(NC)"; \
		queries=$$(curl -s http://localhost:${ADGUARD_EXPORTER_PORT:-9617}/metrics | grep "adguard_num_dns_queries" | grep -v "#" | awk '{print $$2}' || echo "N/A"); \
		blocked=$$(curl -s http://localhost:${ADGUARD_EXPORTER_PORT:-9617}/metrics | grep "adguard_num_blocked_filtering" | grep -v "#" | awk '{print $$2}' || echo "N/A"); \
		echo "  Total DNS Queries: $$queries"; \
		echo "  Blocked Queries: $$blocked"; \
		if [ "$$queries" != "N/A" ] && [ "$$blocked" != "N/A" ] && [ $$queries -gt 0 ]; then \
			block_rate=$$(echo "scale=1; $$blocked * 100 / $$queries" | bc 2>/dev/null || echo "N/A"); \
			echo "  Block Rate: $$block_rate%"; \
		fi; \
	else \
		echo "$(YELLOW)Metrics unavailable$(NC)"; \
	fi

##@ Backup & Recovery
.PHONY: backup
backup: check-root ## Create encrypted backup
	@echo "$(BLUE)Creating backup of AdGuard infrastructure...$(NC)"
	@sudo scripts/backup/backup.sh
	@echo "$(GREEN)Backup completed successfully$(NC)"
	@ls -la $(BACKUP_DIR)/ | tail -5

.PHONY: restore
restore: check-root ## Restore from latest backup
	@echo "$(YELLOW)Warning: This will restore from the latest backup and restart services$(NC)"
	@read -p "Continue? (y/N): " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo "$(BLUE)Restoring from latest backup...$(NC)"
	@sudo scripts/backup/restore.sh
	@echo "$(GREEN)Restore completed successfully$(NC)"

.PHONY: list-backups
list-backups: ## List available backups
	@echo "$(BOLD)Available Backups:$(NC)"
	@if [ -d "$(BACKUP_DIR)" ]; then \
		ls -la $(BACKUP_DIR)/adguard-backup-*.tar.gz* 2>/dev/null | \
		awk '{print "  " $$9 " (" $$5 " bytes) " $$6 " " $$7 " " $$8}' || \
		echo "  No backups found"; \
	else \
		echo "  Backup directory not found"; \
	fi

##@ Updates & Maintenance
.PHONY: update
update: check-root ## Update system and containers
	@echo "$(BLUE)Updating AdGuard infrastructure...$(NC)"
	@sudo scripts/maintenance/update.sh
	@echo "$(GREEN)Update completed successfully$(NC)"

.PHONY: pull
pull: ## Pull latest container images
	@echo "$(BLUE)Pulling latest container images...$(NC)"
	@cd docker && docker compose pull
	@echo "$(GREEN)Images updated successfully$(NC)"
	@echo "$(YELLOW)Run 'make restart' to use updated images$(NC)"

.PHONY: upgrade
upgrade: pull restart ## Upgrade containers to latest versions
	@echo "$(GREEN)Container upgrade completed$(NC)"

.PHONY: security-update
security-update: check-root ## Apply security updates only
	@echo "$(BLUE)Applying security updates...$(NC)"
	@sudo apt-get update
	@sudo apt-get upgrade -y
	@sudo scripts/monitoring/comprehensive-monitor.sh
	@echo "$(GREEN)Security updates completed$(NC)"

##@ Configuration Management
.PHONY: config-backup
config-backup: ## Backup current configuration
	@echo "$(BLUE)Backing up current configuration...$(NC)"
	@mkdir -p backups/config-$(shell date +%Y%m%d-%H%M%S)
	@cp -r docker/configs backups/config-$(shell date +%Y%m%d-%H%M%S)/
	@cp $(ENV_FILE) backups/config-$(shell date +%Y%m%d-%H%M%S)/ 2>/dev/null || true
	@echo "$(GREEN)Configuration backed up to backups/config-$(shell date +%Y%m%d-%H%M%S)/$(NC)"

.PHONY: config-validate
config-validate: ## Validate configuration files
	@echo "$(BLUE)Validating configuration files...$(NC)"
	@echo -n "  Docker Compose... "
	@if cd docker && docker compose config >/dev/null 2>&1; then \
		echo "$(GREEN)✓$(NC)"; \
	else \
		echo "$(RED)✗$(NC)"; \
	fi

	@echo -n "  AdGuard YAML... "
	@if command -v yq >/dev/null 2>&1; then \
		if yq eval docker/configs/adguard/AdGuardHome.yaml >/dev/null 2>&1; then \
			echo "$(GREEN)✓$(NC)"; \
		else \
			echo "$(RED)✗$(NC)"; \
		fi; \
	else \
		echo "$(YELLOW)yq not available$(NC)"; \
	fi

	@echo -n "  Environment file... "
	@if [ -f "$(ENV_FILE)" ]; then \
		echo "$(GREEN)✓$(NC)"; \
	else \
		echo "$(RED)✗$(NC)"; \
	fi

.PHONY: config-diff
config-diff: ## Show differences from default configuration
	@echo "$(BLUE)Configuration differences from defaults:$(NC)"
	@if [ -f "$(ENV_FILE)" ]; then \
		echo "$(BOLD)Environment variables:$(NC)"; \
		diff -u .env.example $(ENV_FILE) | grep "^[+-]" | grep -v "^[+-][+-][+-]" || echo "No differences"; \
	else \
		echo "$(RED)No .env file found$(NC)"; \
	fi

##@ Testing & Validation
.PHONY: test
test: ## Run all tests
	@echo "$(BLUE)Running AdGuard infrastructure tests...$(NC)"
	@$(MAKE) test-syntax
	@$(MAKE) test-services
	@$(MAKE) test-dns
	@$(MAKE) test-security
	@echo "$(GREEN)All tests completed$(NC)"

.PHONY: test-syntax
test-syntax: ## Test configuration syntax
	@echo "$(BOLD)Testing configuration syntax...$(NC)"
	@echo -n "  Shell scripts... "
	@if command -v shellcheck >/dev/null 2>&1; then \
		if find scripts -name "*.sh" -exec shellcheck {} \; >/dev/null 2>&1; then \
			echo "$(GREEN)✓$(NC)"; \
		else \
			echo "$(RED)✗$(NC)"; \
		fi; \
	else \
		echo "$(YELLOW)shellcheck not available$(NC)"; \
	fi

	@echo -n "  YAML files... "
	@if command -v yamllint >/dev/null 2>&1; then \
		if find . -name "*.yml" -o -name "*.yaml" | grep -v ".github" | xargs yamllint -d relaxed >/dev/null 2>&1; then \
			echo "$(GREEN)✓$(NC)"; \
		else \
			echo "$(RED)✗$(NC)"; \
		fi; \
	else \
		echo "$(YELLOW)yamllint not available$(NC)"; \
	fi

.PHONY: test-services
test-services: ## Test service connectivity
	@echo "$(BOLD)Testing service connectivity...$(NC)"
	@echo -n "  AdGuard Home... "
	@if curl -f -s -m 5 http://localhost:$(ADGUARD_WEB_PORT)/ >/dev/null 2>&1; then \
		echo "$(GREEN)✓$(NC)"; \
	else \
		echo "$(RED)✗$(NC)"; \
	fi

	@echo -n "  Prometheus... "
	@if curl -f -s -m 5 http://localhost:$(PROMETHEUS_PORT)/-/healthy >/dev/null 2>&1; then \
		echo "$(GREEN)✓$(NC)"; \
	else \
		echo "$(RED)✗$(NC)"; \
	fi

	@echo -n "  Grafana... "
	@if curl -f -s -m 5 http://localhost:$(GRAFANA_PORT)/api/health >/dev/null 2>&1; then \
		echo "$(GREEN)✓$(NC)"; \
	else \
		echo "$(RED)✗$(NC)"; \
	fi

.PHONY: test-dns
test-dns: ## Test DNS functionality
	@echo "$(BOLD)Testing DNS functionality...$(NC)"
	@echo -n "  Basic resolution... "
	@if command -v dig >/dev/null 2>&1; then \
		if dig @localhost google.com +time=5 +tries=1 >/dev/null 2>&1; then \
			echo "$(GREEN)✓$(NC)"; \
		else \
			echo "$(RED)✗$(NC)"; \
		fi; \
	else \
		echo "$(YELLOW)dig not available$(NC)"; \
	fi

	@echo -n "  Australian sites... "
	@if command -v dig >/dev/null 2>&1; then \
		if dig @localhost bom.gov.au +time=5 +tries=1 >/dev/null 2>&1; then \
			echo "$(GREEN)✓$(NC)"; \
		else \
			echo "$(RED)✗$(NC)"; \
		fi; \
	else \
		echo "$(YELLOW)dig not available$(NC)"; \
	fi

	@echo -n "  Ad blocking... "
	@if command -v dig >/dev/null 2>&1; then \
		result=$$(dig @localhost doubleclick.net +short +time=5 +tries=1 2>/dev/null | head -1); \
		if [ "$$result" = "0.0.0.0" ] || [ -z "$$result" ]; then \
			echo "$(GREEN)✓$(NC)"; \
		else \
			echo "$(YELLOW)⚠$(NC)"; \
		fi; \
	else \
		echo "$(YELLOW)dig not available$(NC)"; \
	fi

.PHONY: test-security
test-security: ## Test security configuration
	@echo "$(BOLD)Testing security configuration...$(NC)"
	@echo -n "  Firewall status... "
	@if sudo ufw status | grep -q "Status: active"; then \
		echo "$(GREEN)✓$(NC)"; \
	else \
		echo "$(RED)✗$(NC)"; \
	fi

	@echo -n "  Fail2ban status... "
	@if sudo systemctl is-active --quiet fail2ban; then \
		echo "$(GREEN)✓$(NC)"; \
	else \
		echo "$(RED)✗$(NC)"; \
	fi

	@echo -n "  SSH configuration... "
	@if sudo grep -q "Port $(SSH_PORT)" /etc/ssh/sshd_config 2>/dev/null; then \
		echo "$(GREEN)✓$(NC)"; \
	else \
		echo "$(YELLOW)⚠$(NC)"; \
	fi

##@ Security & Firewall
.PHONY: security-scan
security-scan: check-root ## Run comprehensive security scan
	@echo "$(BLUE)Running security scan...$(NC)"
	@sudo scripts/monitoring/comprehensive-monitor.sh
	@if command -v lynis >/dev/null 2>&1; then \
		echo "$(BLUE)Running Lynis security audit...$(NC)"; \
		sudo lynis audit system --quick; \
	else \
		echo "$(YELLOW)Lynis not available - install with: sudo apt install lynis$(NC)"; \
	fi

.PHONY: firewall-status
firewall-status: ## Show firewall status
	@echo "$(BOLD)Firewall Status:$(NC)"
	@sudo ufw status verbose
	@echo ""
	@echo "$(BOLD)Fail2ban Status:$(NC)"
	@sudo fail2ban-client status 2>/dev/null || echo "Fail2ban not running"

.PHONY: firewall-reset
firewall-reset: check-root ## Reset and reconfigure firewall
	@echo "$(YELLOW)Warning: This will reset all firewall rules$(NC)"
	@read -p "Continue? (y/N): " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo "$(BLUE)Resetting firewall configuration...$(NC)"
	@sudo configs/firewall/ufw-rules.sh
	@echo "$(GREEN)Firewall reset completed$(NC)"

##@ Utilities
.PHONY: cleanup-ports
cleanup-ports: ## Force cleanup of docker-proxy port conflicts
	@echo "$(BLUE)Force cleaning up docker-proxy processes...$(NC)"
	@set +e; \
	sudo pkill -f "docker-proxy" 2>/dev/null; \
	echo "$(BLUE)Stopping Docker daemon...$(NC)"; \
	sudo systemctl stop docker 2>/dev/null; \
	sleep 2; \
	echo "$(BLUE)Starting Docker daemon...$(NC)"; \
	sudo systemctl start docker; \
	echo "$(BLUE)Waiting for Docker to be ready...$(NC)"; \
	timeout 30 bash -c 'until docker info >/dev/null 2>&1; do sleep 1; done' || echo "$(YELLOW)Docker startup timeout - continuing anyway$(NC)"; \
	set -e
	@echo "$(GREEN)Port cleanup completed$(NC)"

.PHONY: clean
clean: ## Clean up temporary files and old images
	@echo "$(BLUE)Cleaning up temporary files and old images...$(NC)"
	@docker system prune -f
	@docker volume prune -f
	@sudo find $(LOG_DIR) -name "*.log" -mtime +30 -delete 2>/dev/null || true
	@sudo find /tmp -name "adguard-*" -mtime +1 -delete 2>/dev/null || true
	@echo "$(GREEN)Cleanup completed$(NC)"

.PHONY: reset
reset: check-root ## Reset entire infrastructure (DESTRUCTIVE)
	@echo "$(RED)$(BOLD)WARNING: This will destroy all data and reset to defaults!$(NC)"
	@echo "$(YELLOW)This action cannot be undone. Make sure you have backups!$(NC)"
	@read -p "Type 'DESTROY' to confirm: " confirm && [ "$$confirm" = "DESTROY" ] || exit 1
	@echo "$(BLUE)Stopping services...$(NC)"
	@cd docker && docker compose down -v || true
	@echo "$(BLUE)Removing data directories...$(NC)"
	@sudo rm -rf /opt/adguard/data/* /opt/monitoring/*/data/* || true
	@echo "$(BLUE)Resetting configuration...$(NC)"
	@cp .env.example $(ENV_FILE)
	@echo "$(GREEN)Reset completed. Run 'make install' to reinstall$(NC)"

.PHONY: info
info: ## Show system information
	@echo "$(BOLD)AdGuard Infrastructure Information$(NC)"
	@echo "======================================"
	@echo "$(BOLD)Version:$(NC) $$(cat VERSION 2>/dev/null || echo 'Development')"
	@echo "$(BOLD)Location:$(NC) $(PROJECT_ROOT)"
	@echo "$(BOLD)Environment:$(NC) $$([ -f $(ENV_FILE) ] && echo 'Configured' || echo 'Not configured')"
	@echo ""
	@echo "$(BOLD)System Information:$(NC)"
	@echo "  OS: $$(lsb_release -d 2>/dev/null | cut -f2 || uname -s)"
	@echo "  Kernel: $$(uname -r)"
	@echo "  Architecture: $$(uname -m)"
	@echo "  Timezone: $$(timedatectl show --property=Timezone --value 2>/dev/null || echo 'Unknown')"
	@echo ""
	@echo "$(BOLD)Network Configuration:$(NC)"
	@echo "  IP Address: $$(ip route get 1.1.1.1 2>/dev/null | awk '{print $$7; exit}' || echo 'Unknown')"
	@if [ -n "$(STATIC_IP)" ]; then \
		echo "  Configured IP: $(STATIC_IP)"; \
	fi
	@echo ""
	@echo "$(BOLD)Service URLs:$(NC)"
	@echo "  AdGuard Home: http://$$(ip route get 1.1.1.1 2>/dev/null | awk '{print $$7; exit}' || echo 'localhost'):$(ADGUARD_WEB_PORT)"
	@echo "  Grafana:      http://$$(ip route get 1.1.1.1 2>/dev/null | awk '{print $$7; exit}' || echo 'localhost'):$(GRAFANA_PORT)"
	@echo "  Prometheus:   http://$$(ip route get 1.1.1.1 2>/dev/null | awk '{print $$7; exit}' || echo 'localhost'):$(PROMETHEUS_PORT)"

##@ Development
.PHONY: lint
lint: ## Run code quality checks
	@echo "$(BLUE)Running code quality checks...$(NC)"
	@if command -v shellcheck >/dev/null 2>&1; then \
		echo "$(BOLD)Checking shell scripts...$(NC)"; \
		find scripts configs -name "*.sh" -exec shellcheck {} \; || true; \
	else \
		echo "$(YELLOW)shellcheck not available$(NC)"; \
	fi

	@if command -v yamllint >/dev/null 2>&1; then \
		echo "$(BOLD)Checking YAML files...$(NC)"; \
		find . -name "*.yml" -o -name "*.yaml" | grep -v ".github" | xargs yamllint -d relaxed || true; \
	else \
		echo "$(YELLOW)yamllint not available$(NC)"; \
	fi

	@echo "$(BOLD)Checking Docker Compose syntax...$(NC)"
	@cd docker && docker compose config >/dev/null && echo "$(GREEN)✓ Docker Compose syntax OK$(NC)" || echo "$(RED)✗ Docker Compose syntax error$(NC)"

.PHONY: dev-test
dev-test: ## Run development tests
	@echo "$(BLUE)Running development tests...$(NC)"
	@$(MAKE) lint
	@$(MAKE) test-syntax
	@echo "$(GREEN)Development tests completed$(NC)"

##@ CI/CD Integration
.PHONY: ci-setup
ci-setup: ## Set up CI environment
	@echo "$(BLUE)Setting up CI environment...$(NC)"
	@cp .env.example .env
	@sed -i 's/ADGUARD_PASSWORD=change_this_password/ADGUARD_PASSWORD=ci_test_password/' .env
	@sed -i 's/GRAFANA_ADMIN_PASSWORD=change_this_password/GRAFANA_ADMIN_PASSWORD=ci_test_password/' .env
	@sed -i 's/GRAFANA_SECRET_KEY=change_this_secret/GRAFANA_SECRET_KEY=ci_test_secret/' .env
	@echo "$(GREEN)CI environment configured$(NC)"

.PHONY: ci-test
ci-test: ## Run CI tests
	@echo "$(BLUE)Running CI tests...$(NC)"
	@$(MAKE) lint
	@$(MAKE) config-validate
	@echo "$(GREEN)CI tests completed$(NC)"

.PHONY: release
release: ## Prepare release artifacts
	@echo "$(BLUE)Preparing release artifacts...$(NC)"
	@$(MAKE) lint
	@$(MAKE) config-validate
	@echo "$(GREEN)Release preparation completed$(NC)"

##@ Internal Functions
.PHONY: check-root
check-root:
	@if [ "$$(id -u)" -eq 0 ]; then \
		echo "$(YELLOW)Warning: Running as root$(NC)"; \
	elif ! sudo -n true 2>/dev/null; then \
		echo "$(RED)Error: This command requires sudo access$(NC)"; \
		exit 1; \
	fi

.PHONY: check-env
check-env:
	@if [ ! -f "$(ENV_FILE)" ]; then \
		echo "$(RED)Error: .env file not found. Run 'make config' first.$(NC)"; \
		exit 1; \
	fi

# Ensure scripts are executable
$(shell find scripts -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true)
$(shell chmod +x configs/firewall/ufw-rules.sh 2>/dev/null || true)

# Default values for environment variables (if not set)
STATIC_IP ?= 192.168.1.100
ADGUARD_WEB_PORT ?= 3000
GRAFANA_PORT ?= 3001
PROMETHEUS_PORT ?= 9090
SSH_PORT ?= 2222