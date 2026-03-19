#!/usr/bin/env bash
###############################################################################
# Wazuh Restore Script
# Restores manager config, agent keys, and custom rules from a backup.
#
# Usage: ./restore.sh backups/wazuh_backup_20240101_120000.tar.gz
###############################################################################
set -euo pipefail

BACKUP_FILE="${1:-}"
TEMP_DIR=""

log() { echo "[restore] $*"; }

cleanup() { [[ -n "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"; }
trap cleanup EXIT

if [[ -z "$BACKUP_FILE" || ! -f "$BACKUP_FILE" ]]; then
    echo "Usage: $0 <backup_file.tar.gz>"
    echo "Example: $0 backups/wazuh_backup_20240101_120000.tar.gz"
    exit 1
fi

log "═══ Wazuh Restore ═══"
log "Backup file: $BACKUP_FILE"
echo ""

# ─── Extract ─────────────────────────────────────────────────────────────────
TEMP_DIR=$(mktemp -d)
log "Extracting to $TEMP_DIR..."
tar -xzf "$BACKUP_FILE" -C "$TEMP_DIR"

# Find the backup directory inside (may be nested)
BACKUP_DIR=$(find "$TEMP_DIR" -maxdepth 1 -type d -name "wazuh_backup_*" | head -1)
[[ -z "$BACKUP_DIR" ]] && BACKUP_DIR="$TEMP_DIR"

log "Contents found:"
ls -la "$BACKUP_DIR/"
echo ""

# ─── Confirm ─────────────────────────────────────────────────────────────────
read -rp "[restore] This will overwrite current Wazuh manager config. Continue? [y/N] " CONFIRM
[[ "${CONFIRM,,}" != "y" ]] && { log "Aborted."; exit 0; }

# ─── Stop manager for safety ────────────────────────────────────────────────
log "Stopping Wazuh manager..."
docker compose stop wazuh-manager 2>/dev/null || docker stop wazuh-manager 2>/dev/null || true

# ─── Restore manager configuration ──────────────────────────────────────────
if [[ -d "$BACKUP_DIR/manager-etc" ]]; then
    log "Restoring manager /etc..."
    docker cp "$BACKUP_DIR/manager-etc/." wazuh-manager:/var/ossec/etc/
    log "  ✓ Manager configuration restored"
fi

# ─── Restore agent keys ─────────────────────────────────────────────────────
if [[ -f "$BACKUP_DIR/client.keys" ]]; then
    log "Restoring agent keys..."
    docker cp "$BACKUP_DIR/client.keys" wazuh-manager:/var/ossec/etc/client.keys
    log "  ✓ Agent keys restored"
fi

# ─── Restore custom rules ───────────────────────────────────────────────────
if [[ -d "$BACKUP_DIR/rules" ]]; then
    log "Restoring custom rules..."
    cp -r "$BACKUP_DIR/rules/"* rules/ 2>/dev/null || true
    log "  ✓ Custom rules restored to local rules/"
fi

# ─── Restore .env ───────────────────────────────────────────────────────────
if [[ -f "$BACKUP_DIR/.env" ]]; then
    read -rp "[restore] Restore .env file? (will overwrite current) [y/N] " CONFIRM_ENV
    if [[ "${CONFIRM_ENV,,}" == "y" ]]; then
        cp "$BACKUP_DIR/.env" .env
        log "  ✓ .env restored"
    fi
fi

# ─── Restart ─────────────────────────────────────────────────────────────────
log "Starting Wazuh manager..."
docker compose start wazuh-manager 2>/dev/null || docker start wazuh-manager 2>/dev/null || true

# Wait for manager to be ready
log "Waiting for manager to start..."
for i in $(seq 1 30); do
    if docker exec wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "is running"; then
        break
    fi
    sleep 2
done

# ─── Verify ──────────────────────────────────────────────────────────────────
log ""
if docker exec wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "is running"; then
    log "✓ Manager is running"
    AGENT_COUNT=$(docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -c "ID:" || echo "0")
    log "✓ Registered agents: $AGENT_COUNT"
else
    log "✗ Manager may not have started correctly — check: docker logs wazuh-manager"
fi

log ""
log "Restore complete."
log "If you restored from an indexer snapshot, run separately:"
log "  curl -sk -X POST https://localhost:9200/_snapshot/backup_repo/snapshot_NAME/_restore -u admin:PASSWORD"
