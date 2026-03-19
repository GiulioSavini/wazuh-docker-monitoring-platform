#!/usr/bin/env bash
###############################################################################
# Wazuh Backup Script
# Backs up manager config, agent keys, indexer data, and custom rules.
###############################################################################
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_PATH="$BACKUP_DIR/wazuh_backup_$TIMESTAMP"

log() { echo "[backup] $*"; }

mkdir -p "$BACKUP_PATH"

log "Starting Wazuh backup → $BACKUP_PATH"

# ─── Manager configuration and agent keys ────────────────────────────────────
log "Backing up manager configuration..."
docker cp wazuh-manager:/var/ossec/etc "$BACKUP_PATH/manager-etc" 2>/dev/null || log "WARN: Could not copy manager /etc"

log "Backing up agent keys..."
docker cp wazuh-manager:/var/ossec/etc/client.keys "$BACKUP_PATH/client.keys" 2>/dev/null || log "WARN: No client.keys found"

# ─── Manager rules and decoders ─────────────────────────────────────────────
log "Backing up custom rules..."
cp -r rules/ "$BACKUP_PATH/rules" 2>/dev/null || true

# ─── Manager queues (optional, can be large) ────────────────────────────────
if [[ "${BACKUP_QUEUES:-false}" == "true" ]]; then
    log "Backing up manager queues (this may take a while)..."
    docker cp wazuh-manager:/var/ossec/queue "$BACKUP_PATH/manager-queue" 2>/dev/null || true
fi

# ─── Indexer snapshot ────────────────────────────────────────────────────────
log "Creating indexer snapshot..."
docker exec wazuh-indexer curl -sk -X PUT \
    "https://localhost:9200/_snapshot/backup_repo" \
    -H 'Content-Type: application/json' \
    -u "admin:${INDEXER_PASSWORD:-admin}" \
    -d '{"type":"fs","settings":{"location":"/tmp/backup"}}' 2>/dev/null || true

docker exec wazuh-indexer curl -sk -X PUT \
    "https://localhost:9200/_snapshot/backup_repo/snapshot_$TIMESTAMP?wait_for_completion=true" \
    -u "admin:${INDEXER_PASSWORD:-admin}" 2>/dev/null || log "WARN: Indexer snapshot failed (may need shared_path configured)"

# ─── Docker Compose and env ─────────────────────────────────────────────────
log "Backing up deployment config..."
cp docker-compose.yml "$BACKUP_PATH/" 2>/dev/null || true
cp .env "$BACKUP_PATH/.env" 2>/dev/null || true

# ─── Compress ────────────────────────────────────────────────────────────────
log "Compressing backup..."
tar -czf "$BACKUP_PATH.tar.gz" -C "$BACKUP_DIR" "wazuh_backup_$TIMESTAMP"
rm -rf "$BACKUP_PATH"

SIZE=$(du -sh "$BACKUP_PATH.tar.gz" | cut -f1)
log "Backup complete: $BACKUP_PATH.tar.gz ($SIZE)"
log "To restore manager config: docker cp <backup>/manager-etc/. wazuh-manager:/var/ossec/etc/"
