#!/usr/bin/env bash
###############################################################################
# Wazuh Index Lifecycle Management (ISM)
# Creates an OpenSearch ISM policy for automatic index retention.
#
# Default: hot 30 days → delete
# Usage: ./index-lifecycle.sh [--retention-days 90]
###############################################################################
set -euo pipefail

INDEXER_URL="https://localhost:9200"
INDEXER_USER="${INDEXER_USERNAME:-admin}"
INDEXER_PASS="${INDEXER_PASSWORD:-admin}"
RETENTION_DAYS="${1:-30}"

# Parse named arg
[[ "${1:-}" == "--retention-days" ]] && RETENTION_DAYS="${2:-30}"

log() { echo "[ISM] $*"; }

log "Configuring index lifecycle: retention = ${RETENTION_DAYS} days"

# ─── Create ISM Policy ──────────────────────────────────────────────────────
POLICY_JSON=$(cat <<EOF
{
  "policy": {
    "description": "Wazuh alerts index lifecycle — delete after ${RETENTION_DAYS} days",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": {
              "min_index_age": "${RETENTION_DAYS}d"
            }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [
          {
            "delete": {}
          }
        ],
        "transitions": []
      }
    ],
    "ism_template": [
      {
        "index_patterns": ["wazuh-alerts-*"],
        "priority": 100
      },
      {
        "index_patterns": ["wazuh-archives-*"],
        "priority": 90
      }
    ]
  }
}
EOF
)

# Apply policy
RESPONSE=$(docker exec wazuh-indexer curl -sk -X PUT \
    "${INDEXER_URL}/_plugins/_ism/policies/wazuh-retention" \
    -H 'Content-Type: application/json' \
    -u "${INDEXER_USER}:${INDEXER_PASS}" \
    -d "${POLICY_JSON}" 2>/dev/null)

if echo "$RESPONSE" | grep -q '"_id"'; then
    log "ISM policy 'wazuh-retention' created successfully"
else
    log "Response: $RESPONSE"
    # Try update if it already exists
    RESPONSE=$(docker exec wazuh-indexer curl -sk -X PUT \
        "${INDEXER_URL}/_plugins/_ism/policies/wazuh-retention?if_seq_no=0&if_primary_term=1" \
        -H 'Content-Type: application/json' \
        -u "${INDEXER_USER}:${INDEXER_PASS}" \
        -d "${POLICY_JSON}" 2>/dev/null)
    log "Update response: $RESPONSE"
fi

# ─── Show current indices ────────────────────────────────────────────────────
log ""
log "Current Wazuh indices:"
docker exec wazuh-indexer curl -sk \
    "${INDEXER_URL}/_cat/indices/wazuh-*?h=index,docs.count,store.size,creation.date.string&s=index" \
    -u "${INDEXER_USER}:${INDEXER_PASS}" 2>/dev/null

log ""
log "Done. Indices older than ${RETENTION_DAYS} days will be automatically deleted."
log "Check policy status: curl -sk ${INDEXER_URL}/_plugins/_ism/explain/wazuh-alerts-*"
