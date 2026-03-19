#!/usr/bin/env bash
###############################################################################
# Wazuh Pre-Flight Check
# Validates that the host meets all prerequisites before deploying.
# Run this BEFORE docker compose up or Ansible playbooks.
#
# Usage: ./preflight-check.sh [--fix]
#   --fix    Attempt to auto-fix issues where possible
###############################################################################
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

FIX_MODE=false
[[ "${1:-}" == "--fix" ]] && FIX_MODE=true

ERRORS=0
WARNINGS=0

pass()  { printf "${GREEN}[PASS]${NC}  %s\n" "$1"; }
fail()  { printf "${RED}[FAIL]${NC}  %s\n" "$1"; ((ERRORS++)); }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$1"; ((WARNINGS++)); }
info()  { printf "        → %s\n" "$1"; }
fix()   { printf "${YELLOW}[FIX]${NC}   %s\n" "$1"; }

echo "╔══════════════════════════════════════════╗"
echo "║   Wazuh Platform Pre-Flight Check        ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ─── 1. System Requirements ─────────────────────────────────────────────────
echo "── System Requirements ──"

# Docker
if command -v docker &>/dev/null; then
    DOCKER_VER=$(docker --version | grep -oP '\d+\.\d+\.\d+')
    DOCKER_MAJOR=$(echo "$DOCKER_VER" | cut -d. -f1)
    if [[ "$DOCKER_MAJOR" -ge 24 ]]; then
        pass "Docker $DOCKER_VER installed"
    else
        warn "Docker $DOCKER_VER found — version 24.0+ recommended"
    fi
else
    fail "Docker not installed"
    info "Install: https://docs.docker.com/engine/install/"
fi

# Docker Compose
if docker compose version &>/dev/null; then
    COMPOSE_VER=$(docker compose version --short 2>/dev/null || echo "unknown")
    pass "Docker Compose $COMPOSE_VER installed"
else
    fail "Docker Compose v2 not available"
    info "Ensure Docker Compose plugin is installed"
fi

# Docker daemon running
if docker info &>/dev/null; then
    pass "Docker daemon is running"
else
    fail "Docker daemon is not running"
    info "Start with: sudo systemctl start docker"
fi

# Current user in docker group
if groups | grep -qw docker; then
    pass "Current user is in 'docker' group"
else
    warn "Current user not in 'docker' group — may need sudo for Docker commands"
    if [[ "$FIX_MODE" == true ]]; then
        sudo usermod -aG docker "$USER"
        fix "Added $USER to docker group (re-login required)"
    else
        info "Fix: sudo usermod -aG docker $USER && newgrp docker"
    fi
fi

echo ""

# ─── 2. Kernel Parameters ───────────────────────────────────────────────────
echo "── Kernel Parameters ──"

# vm.max_map_count (required by OpenSearch)
MAP_COUNT=$(sysctl -n vm.max_map_count 2>/dev/null || echo "0")
if [[ "$MAP_COUNT" -ge 262144 ]]; then
    pass "vm.max_map_count = $MAP_COUNT (≥ 262144)"
else
    fail "vm.max_map_count = $MAP_COUNT (needs ≥ 262144)"
    if [[ "$FIX_MODE" == true ]]; then
        sudo sysctl -w vm.max_map_count=262144
        echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf >/dev/null
        fix "Set vm.max_map_count=262144 (persistent)"
    else
        info "Fix: sudo sysctl -w vm.max_map_count=262144"
        info "Persistent: echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf"
    fi
fi

# File descriptors
NOFILE_LIMIT=$(ulimit -n)
if [[ "$NOFILE_LIMIT" -ge 65536 ]]; then
    pass "Open file limit = $NOFILE_LIMIT (≥ 65536)"
else
    warn "Open file limit = $NOFILE_LIMIT (65536+ recommended for production)"
    info "Fix: add to /etc/security/limits.conf:"
    info "  * soft nofile 65536"
    info "  * hard nofile 65536"
fi

echo ""

# ─── 3. Memory & Disk ───────────────────────────────────────────────────────
echo "── Resources ──"

# RAM
TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
if [[ "$TOTAL_RAM_MB" -ge 8192 ]]; then
    pass "RAM: ${TOTAL_RAM_MB}MB (≥ 8GB recommended)"
elif [[ "$TOTAL_RAM_MB" -ge 4096 ]]; then
    warn "RAM: ${TOTAL_RAM_MB}MB (4GB minimum, 8GB+ recommended)"
else
    fail "RAM: ${TOTAL_RAM_MB}MB (minimum 4GB required)"
fi

# Disk space
AVAIL_GB=$(df -BG . | awk 'NR==2{print $4}' | tr -d 'G')
if [[ "$AVAIL_GB" -ge 20 ]]; then
    pass "Available disk: ${AVAIL_GB}GB (≥ 20GB)"
elif [[ "$AVAIL_GB" -ge 10 ]]; then
    warn "Available disk: ${AVAIL_GB}GB (20GB+ recommended for production)"
else
    fail "Available disk: ${AVAIL_GB}GB (minimum 10GB required)"
fi

echo ""

# ─── 4. Network & Ports ─────────────────────────────────────────────────────
echo "── Network Ports ──"

check_port() {
    local port=$1 name=$2
    if ss -tlnp 2>/dev/null | grep -q ":${port} " || netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
        warn "Port $port ($name) already in use"
        info "Check: ss -tlnp | grep :$port"
    else
        pass "Port $port ($name) is available"
    fi
}

check_port 9200  "Indexer"
check_port 1514  "Agent"
check_port 1515  "Syslog/Registration"
check_port 5601  "Dashboard"
check_port 55000 "API"

echo ""

# ─── 5. Configuration Files ─────────────────────────────────────────────────
echo "── Configuration ──"

# .env file
if [[ -f .env ]]; then
    if grep -q "CHANGE_ME" .env; then
        fail ".env exists but contains CHANGE_ME placeholders — update passwords"
    else
        pass ".env configured"
    fi
else
    warn ".env not found — run: cp .env.example .env"
fi

# Certificates
if [[ -f docker/wazuh/certs/root-ca.pem ]]; then
    # Check expiry
    EXPIRY=$(openssl x509 -enddate -noout -in docker/wazuh/certs/root-ca.pem 2>/dev/null | cut -d= -f2)
    if openssl x509 -checkend 2592000 -noout -in docker/wazuh/certs/root-ca.pem 2>/dev/null; then
        pass "TLS certificates present (CA expires: $EXPIRY)"
    else
        warn "TLS CA certificate expires within 30 days: $EXPIRY"
    fi
else
    warn "TLS certificates not generated — run: make certs"
fi

echo ""

# ─── 6. Optional Tools ──────────────────────────────────────────────────────
echo "── Optional Tools ──"

for tool in ansible python3 nmap xmllint yamllint; do
    if command -v "$tool" &>/dev/null; then
        pass "$tool available"
    else
        warn "$tool not installed (needed for: $(case $tool in
            ansible) echo 'agent deployment';;
            python3) echo 'discovery scripts';;
            nmap) echo 'network discovery';;
            xmllint) echo 'rule validation';;
            yamllint) echo 'YAML linting';;
        esac))"
    fi
done

echo ""

# ─── Summary ─────────────────────────────────────────────────────────────────
echo "══════════════════════════════════════════"
if [[ "$ERRORS" -gt 0 ]]; then
    echo -e "${RED}RESULT: $ERRORS error(s), $WARNINGS warning(s)${NC}"
    echo "Fix the errors above before deploying."
    echo "Run with --fix to auto-fix where possible: ./preflight-check.sh --fix"
    exit 1
elif [[ "$WARNINGS" -gt 0 ]]; then
    echo -e "${YELLOW}RESULT: 0 errors, $WARNINGS warning(s)${NC}"
    echo "Deployment possible but review warnings above."
    exit 0
else
    echo -e "${GREEN}RESULT: All checks passed. Ready to deploy!${NC}"
    exit 0
fi
