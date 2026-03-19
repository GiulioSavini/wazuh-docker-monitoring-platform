# Operations Guide

Day-2 operations: maintenance, upgrades, monitoring, and incident response.

## Index Lifecycle & Retention

By default, Wazuh indices grow indefinitely. Configure automatic cleanup:

```bash
# Set 30-day retention (default)
bash scripts/utils/index-lifecycle.sh

# Custom retention
bash scripts/utils/index-lifecycle.sh --retention-days 90
```

Monitor disk usage:
```bash
make status
# or manually:
docker exec wazuh-indexer curl -sk https://localhost:9200/_cat/indices/wazuh-*?h=index,store.size -u admin:PASSWORD
```

## Backup & Restore

### Backup
```bash
make backup
# or: bash scripts/utils/backup.sh
```

Backs up: manager config, agent keys, custom rules, .env, indexer snapshot.

### Restore
```bash
bash scripts/utils/restore.sh backups/wazuh_backup_20240101_120000.tar.gz
```

### Schedule automatic backups
```bash
# Add to crontab — daily at 02:00
0 2 * * * cd /path/to/wazuh-docker-monitoring-platform && bash scripts/utils/backup.sh
```

## Agent Lifecycle

### Upgrade agents (rolling)

```bash
# Canary: upgrade one host first
ansible-playbook -i inventories/production playbooks/upgrade-agents.yml \
    -e wazuh_agent_version=4.10.0 --limit web-prod-01

# Full fleet (one at a time)
ansible-playbook -i inventories/production playbooks/upgrade-agents.yml \
    -e wazuh_agent_version=4.10.0
```

### Remove/decommission agent

```bash
ansible-playbook -i inventories/production playbooks/remove-agent.yml \
    --limit web-prod-01
```

## Alerting

Configure notifications in the Wazuh Manager. See `examples/cloud-configs/alerting-integrations.xml` for ready-to-use templates:

| Channel | Config Key | Alert Level |
|---------|-----------|-------------|
| Slack | `<integration name="slack">` | 10+ |
| PagerDuty | `<integration name="pagerduty">` | 12+ (critical) |
| Email | `<global> email_notification` | 12+ |
| Webhook | `<integration name="custom-webhook">` | Configurable |
| Syslog → SIEM | `<syslog_output>` | 5+ |
| VirusTotal | `<integration name="virustotal">` | FIM events |

After editing, restart the manager: `make reload-rules`

## Active Response

Pre-built scripts in `examples/active-response/`:

| Script | Trigger | Action |
|--------|---------|--------|
| `firewall-drop.sh` | SSH/vCenter brute force | Block IP via iptables for 1 hour |
| `disable-user.sh` | Repeated unauthorized sudo | Lock user account for 2 hours |

Deploy:
```bash
# Copy to agent
scp examples/active-response/firewall-drop.sh TARGET:/var/ossec/active-response/bin/
ssh TARGET 'chmod 750 /var/ossec/active-response/bin/firewall-drop.sh && chown root:ossec /var/ossec/active-response/bin/firewall-drop.sh'
```

## CDB Lists

Custom lookup lists for fast matching in rules:

| List | Purpose |
|------|---------|
| `rules/lists/blocked-ips.list` | Known malicious IPs |
| `rules/lists/approved-docker-images.list` | Whitelisted container images |

After editing lists, rebuild and restart:
```bash
make reload-rules
```

## Secret Rotation

### Rotate indexer/dashboard passwords

1. Update passwords in `.env`
2. Recreate containers:
   ```bash
   docker compose down
   docker compose up -d
   ```
3. Update the internal security configuration:
   ```bash
   docker exec wazuh-indexer bash -c 'JAVA_HOME=/usr/share/wazuh-indexer/jdk \
       /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
       -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/ \
       -icl -nhnv \
       -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
       -cert /usr/share/wazuh-indexer/certs/admin.pem \
       -key /usr/share/wazuh-indexer/certs/admin-key.pem'
   ```

### Rotate TLS certificates

```bash
# Remove old certs
rm -f docker/wazuh/certs/*.pem docker/nginx/ssl/*.pem

# Regenerate
bash scripts/utils/generate-certs.sh

# Restart stack
docker compose restart
```

### Rotate agent registration password

1. Update `authd` password on the manager:
   ```bash
   docker exec wazuh-manager bash -c 'echo "NEW_PASSWORD" > /var/ossec/etc/authd.pass'
   docker exec wazuh-manager /var/ossec/bin/wazuh-control restart
   ```
2. Update Ansible vault:
   ```bash
   ansible-vault edit ansible/group_vars/all/vault.yml
   ```

## Log Rotation

### Container logs

Configured in `docker-compose.yml` per container:
- Indexer: 50MB x 5 files = 250MB max
- Manager: 100MB x 5 files = 500MB max
- Dashboard: 30MB x 3 files = 90MB max

### Agent logs

Logrotate is deployed automatically by Ansible:
- Daily rotation, 14 days retention, compressed
- Config at `/etc/logrotate.d/wazuh-agent`

### Manager internal logs

Inside the container at `/var/ossec/logs/`:
```bash
docker exec wazuh-manager ls -lh /var/ossec/logs/
```

## Performance Tuning

| Parameter | Location | Default | Production |
|-----------|----------|---------|------------|
| Indexer heap | `.env` → `INDEXER_HEAP` | 1g | 50% of available RAM (max 32g) |
| Manager queue | `ossec.conf` → `queue_size` | 131072 | Increase for >100 agents |
| Agent buffer | Agent `ossec.conf` → `events_per_second` | 500 | Increase for busy hosts |
| Filebeat workers | Manager container | auto | Match CPU cores |
| `vm.max_map_count` | Host kernel | 65530 | 262144 (required) |
| `nofile` limit | Host | 1024 | 65536 |

## Testing Rules (wazuh-logtest)

Test rules and decoders before deploying to production:

```bash
# Interactive mode — paste a log line and see which rule matches
docker exec -it wazuh-manager /var/ossec/bin/wazuh-logtest
```

Example session:
```
Starting wazuh-logtest v4.9.0
Type one log per line

# Paste a Docker event:
{"Type":"container","Action":"start","Actor":{"Attributes":{"name":"test-container","image":"nginx:latest"}}}

# Output shows: decoder matched, rule triggered, alert level
```

Test a specific log file against rules:
```bash
# Feed logs from a file
docker exec -i wazuh-manager /var/ossec/bin/wazuh-logtest < test_events.log
```

Validate XML syntax only (fast, no manager needed):
```bash
make test-rules
```

## Server Stack Upgrade

### Pre-upgrade checklist

1. **Backup everything**: `make backup`
2. Check [Wazuh release notes](https://documentation.wazuh.com/current/release-notes/) for breaking changes
3. Verify agent/manager version compatibility
4. Plan maintenance window — agents queue events during manager downtime

### Upgrade procedure

```bash
# 1. Backup
make backup

# 2. Update version in .env
sed -i 's/WAZUH_VERSION=.*/WAZUH_VERSION=4.10.0/' .env

# 3. Pull new images
docker compose pull

# 4. Stop stack (agents will queue events)
docker compose down

# 5. Start with new version
docker compose up -d

# 6. Verify health
make status

# 7. Check indexer compatibility
docker exec wazuh-indexer curl -sk https://localhost:9200 -u admin:$INDEXER_PASSWORD
```

### Rollback

If the upgrade fails:
```bash
# 1. Stop broken stack
docker compose down

# 2. Revert .env
sed -i 's/WAZUH_VERSION=.*/WAZUH_VERSION=4.9.0/' .env

# 3. Restore config from backup
make restore FILE=backups/wazuh_backup_LATEST.tar.gz

# 4. Start previous version
docker compose up -d
```

### Version compatibility

| Manager | Agent | Compatible |
|---------|-------|------------|
| 4.9.x | 4.9.x | Yes |
| 4.9.x | 4.8.x | Yes (backward) |
| 4.9.x | 4.10.x | No — upgrade manager first |

Rule: **always upgrade manager before agents**.

## Health Monitoring

```bash
# Quick status
make status

# Detailed check
bash scripts/utils/healthcheck.sh

# Set up external monitoring (cron every 5 min)
*/5 * * * * /path/to/scripts/utils/healthcheck.sh || curl -X POST https://your-uptime-webhook/alert
```
