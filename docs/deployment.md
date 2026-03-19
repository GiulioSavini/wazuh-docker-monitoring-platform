# Deployment Guide

## Prerequisites

- Docker 24.0+ and Docker Compose v2+
- Minimum 4 GB RAM (8 GB recommended)
- `vm.max_map_count` ≥ 262144 (required by OpenSearch)

```bash
# Set permanently
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## Step 1: Environment Configuration

```bash
cp .env.example .env
```

Edit `.env` and set **all** `CHANGE_ME` values. Use strong, unique passwords.

## Step 2: Generate Certificates

```bash
bash scripts/utils/generate-certs.sh
```

This creates self-signed certs in `docker/wazuh/certs/` and `docker/nginx/ssl/`. For production, replace with certs from your internal CA.

## Step 3: Deploy

### Core Stack

```bash
docker compose up -d
```

### With NGINX Reverse Proxy

```bash
docker compose --profile with-nginx up -d
```

### Verify Health

```bash
docker compose ps
# All containers should show "healthy"
```

## Step 4: Initial Access

| Service   | URL | Credentials |
|-----------|-----|-------------|
| Dashboard | `https://localhost:5601` | `admin` / (your INDEXER_PASSWORD) |
| API       | `https://localhost:55000` | `wazuh-wui` / (your API_PASSWORD) |

## Updating

```bash
# Pull new images
docker compose pull

# Recreate containers (data persists in volumes)
docker compose up -d
```

## Production Hardening

1. Replace self-signed certs with organization CA certs.
2. Restrict `WAZUH_SUBNET` to needed range.
3. Enable email notifications in `ossec.conf`.
4. Set up log rotation for manager logs.
5. Configure firewall rules: only allow 1514/TCP from agent subnets.
6. Use a proper reverse proxy with rate limiting.
