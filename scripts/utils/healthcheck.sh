#!/usr/bin/env bash
###############################################################################
# Wazuh Stack Health Check
# Verifies all components are running and responsive.
###############################################################################
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

check() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" &>/dev/null; then
        printf "${GREEN}✓${NC} %-25s %s\n" "$name" "healthy"
    else
        printf "${RED}✗${NC} %-25s %s\n" "$name" "UNHEALTHY"
        FAILED=true
    fi
}

FAILED=false
echo "─── Wazuh Stack Health ───"
echo ""

check "Wazuh Indexer"    "docker exec wazuh-indexer curl -sk https://localhost:9200 -u admin:\${INDEXER_PASSWORD:-admin} 2>/dev/null | grep -q wazuh-indexer"
check "Wazuh Manager"    "docker exec wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q 'is running'"
check "Wazuh Dashboard"  "curl -sk https://localhost:5601/api/status 2>/dev/null | grep -q available"
check "Manager API"      "curl -sk https://localhost:55000/ 2>/dev/null | grep -q 'Wazuh'"

# Agent count
AGENT_COUNT=$(docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -c "ID:" || echo "0")
printf "\n─── Agents ───\n"
printf "Registered agents: %s\n" "$AGENT_COUNT"

# Disk usage
printf "\n─── Volume Usage ───\n"
docker system df --verbose 2>/dev/null | grep -E "wazuh" || echo "No volume data available"

echo ""
if [[ "$FAILED" == "true" ]]; then
    echo -e "${RED}Some components are unhealthy. Check: docker compose logs${NC}"
    exit 1
else
    echo -e "${GREEN}All components healthy.${NC}"
fi
