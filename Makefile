###############################################################################
# Wazuh Docker Monitoring Platform — Makefile
# Single entry point for all operations
###############################################################################
.DEFAULT_GOAL := help
SHELL := /bin/bash

COMPOSE := docker compose
ENV_FILE := .env
ANSIBLE_DIR := ansible
DISCOVERY_DIR := scripts/discovery

# Colors
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
NC     := \033[0m

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

# ─── Setup ───────────────────────────────────────────────────────────────────

.PHONY: preflight
preflight: ## Run pre-deployment checks on this host
	@bash scripts/utils/preflight-check.sh

.PHONY: preflight-fix
preflight-fix: ## Run pre-deployment checks and auto-fix issues
	@bash scripts/utils/preflight-check.sh --fix

.PHONY: init
init: preflight ## First-time setup: preflight + env + certs
	@test -f $(ENV_FILE) || (cp .env.example $(ENV_FILE) && echo "$(YELLOW)Created .env — edit passwords before deploying$(NC)")
	@bash scripts/utils/generate-certs.sh
	@echo "$(GREEN)Init complete. Edit .env, then run: make deploy$(NC)"

.PHONY: certs
certs: ## Generate TLS certificates
	@bash scripts/utils/generate-certs.sh

# ─── Deploy ──────────────────────────────────────────────────────────────────

.PHONY: deploy
deploy: ## Deploy Wazuh stack
	@test -f $(ENV_FILE) || (echo "$(RED)Missing .env — run: make init$(NC)" && exit 1)
	$(COMPOSE) up -d
	@echo "$(GREEN)Stack deployed. Dashboard: https://localhost:5601$(NC)"

.PHONY: deploy-nginx
deploy-nginx: ## Deploy with NGINX reverse proxy
	$(COMPOSE) --profile with-nginx up -d

.PHONY: stop
stop: ## Stop all containers (keep data)
	$(COMPOSE) down

.PHONY: teardown
teardown: ## Stop and remove all containers AND volumes
	@echo "$(RED)This will DELETE all Wazuh data. Press Ctrl+C to cancel.$(NC)"
	@sleep 5
	$(COMPOSE) down -v

.PHONY: restart
restart: ## Restart all containers
	$(COMPOSE) restart

.PHONY: status
status: ## Show stack status and health
	@$(COMPOSE) ps
	@echo ""
	@bash scripts/utils/healthcheck.sh

.PHONY: logs
logs: ## Tail all container logs
	$(COMPOSE) logs -f --tail=100

.PHONY: logs-manager
logs-manager: ## Tail Wazuh manager logs
	$(COMPOSE) logs -f --tail=100 wazuh-manager

.PHONY: update
update: ## Pull latest images and recreate
	$(COMPOSE) pull
	$(COMPOSE) up -d

# ─── Agents ──────────────────────────────────────────────────────────────────

.PHONY: deploy-agents-linux
deploy-agents-linux: ## Deploy Wazuh agent to Linux servers
	cd $(ANSIBLE_DIR) && ansible-playbook -i inventories/production playbooks/deploy-linux-agent.yml --ask-vault-pass

.PHONY: deploy-agents-windows
deploy-agents-windows: ## Deploy Wazuh agent to Windows servers
	cd $(ANSIBLE_DIR) && ansible-playbook -i inventories/production playbooks/deploy-windows-agent.yml --ask-vault-pass

.PHONY: deploy-agents-docker
deploy-agents-docker: ## Deploy agent to Docker hosts (with Docker-specific monitoring)
	cd $(ANSIBLE_DIR) && ansible-playbook -i inventories/production playbooks/deploy-docker-host-agent.yml --ask-vault-pass

.PHONY: verify-agents
verify-agents: ## Verify all agent connections
	cd $(ANSIBLE_DIR) && ansible-playbook -i inventories/production playbooks/verify-agents.yml

.PHONY: upgrade-agents
upgrade-agents: ## Upgrade agents (usage: make upgrade-agents VERSION=4.10.0)
	@test -n "$(VERSION)" || (echo "$(RED)Usage: make upgrade-agents VERSION=4.10.0$(NC)" && exit 1)
	cd $(ANSIBLE_DIR) && ansible-playbook -i inventories/production playbooks/upgrade-agents.yml -e wazuh_agent_version=$(VERSION)

.PHONY: remove-agent
remove-agent: ## Remove agent from host (usage: make remove-agent HOST=web-prod-01)
	@test -n "$(HOST)" || (echo "$(RED)Usage: make remove-agent HOST=web-prod-01$(NC)" && exit 1)
	cd $(ANSIBLE_DIR) && ansible-playbook -i inventories/production playbooks/remove-agent.yml --limit $(HOST)

.PHONY: list-agents
list-agents: ## List all registered agents
	docker exec wazuh-manager /var/ossec/bin/agent_control -l

# ─── Discovery & Onboarding ─────────────────────────────────────────────────

.PHONY: discover
discover: ## Run network discovery (usage: make discover SUBNET=10.0.0.0/24)
	@test -n "$(SUBNET)" || (echo "$(RED)Usage: make discover SUBNET=10.0.0.0/24$(NC)" && exit 1)
	python3 $(DISCOVERY_DIR)/network_discovery.py --subnet $(SUBNET) --output json

.PHONY: onboard
onboard: ## Full onboarding pipeline (usage: make onboard SUBNET=10.0.0.0/24)
	@test -n "$(SUBNET)" || (echo "$(RED)Usage: make onboard SUBNET=10.0.0.0/24$(NC)" && exit 1)
	bash scripts/onboarding/auto_onboard.sh --subnet $(SUBNET) --env production

.PHONY: onboard-dry
onboard-dry: ## Onboarding dry run
	@test -n "$(SUBNET)" || (echo "$(RED)Usage: make onboard-dry SUBNET=10.0.0.0/24$(NC)" && exit 1)
	bash scripts/onboarding/auto_onboard.sh --subnet $(SUBNET) --dry-run

# ─── Backup ──────────────────────────────────────────────────────────────────

.PHONY: backup
backup: ## Backup Wazuh data and configuration
	@bash scripts/utils/backup.sh

.PHONY: restore
restore: ## Restore from backup (usage: make restore FILE=backups/wazuh_backup_xxx.tar.gz)
	@test -n "$(FILE)" || (echo "$(RED)Usage: make restore FILE=backups/wazuh_backup_xxx.tar.gz$(NC)" && exit 1)
	@bash scripts/utils/restore.sh $(FILE)

# ─── Index Management ────────────────────────────────────────────────────────

.PHONY: retention
retention: ## Set index retention (usage: make retention DAYS=30)
	@bash scripts/utils/index-lifecycle.sh --retention-days $(DAYS)

# ─── Rules ───────────────────────────────────────────────────────────────────

.PHONY: reload-rules
reload-rules: ## Reload custom rules (restart manager)
	docker exec wazuh-manager /var/ossec/bin/wazuh-control restart
	@echo "$(GREEN)Rules reloaded$(NC)"

.PHONY: logtest
logtest: ## Interactive rule tester (paste log lines to test)
	docker exec -it wazuh-manager /var/ossec/bin/wazuh-logtest

.PHONY: test-rules
test-rules: ## Validate all XML rule files
	@find rules/ -name '*.xml' -exec xmllint --noout {} \; && echo "$(GREEN)All rules valid$(NC)"

# ─── Lint ────────────────────────────────────────────────────────────────────

.PHONY: lint
lint: lint-yaml lint-xml lint-python ## Run all linters

.PHONY: lint-yaml
lint-yaml:
	yamllint -d "{extends: relaxed, rules: {line-length: {max: 200}}}" ansible/ docker-compose.yml

.PHONY: lint-xml
lint-xml:
	find rules/ -name '*.xml' -exec xmllint --noout {} \;

.PHONY: lint-python
lint-python:
	ruff check scripts/
