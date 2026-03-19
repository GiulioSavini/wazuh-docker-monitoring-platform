# Architecture

## Component Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    Docker Host                                │
│                                                               │
│  ┌─────────────┐  ┌────────────────┐  ┌──────────────────┐  │
│  │ Wazuh       │  │ Wazuh          │  │ Wazuh            │  │
│  │ Indexer     │◄─┤ Manager        │  │ Dashboard        │  │
│  │ (OpenSearch)│  │ (Filebeat)     │  │ (OpenSearch Dash)│  │
│  │ :9200       │  │ :1514 (agent)  │  │ :5601            │  │
│  │             │  │ :1515 (syslog) │  │                  │  │
│  │             │  │ :55000 (API)   │  │                  │  │
│  └─────────────┘  └────────────────┘  └──────────────────┘  │
│         │                  │                    │             │
│         └──────────┬───────┘                    │             │
│                    │                            │             │
│  ┌─────────────────┴────────────────────────────┘            │
│  │ wazuh-net (172.25.0.0/24)                                 │
│  └───────────────────────────────────────────────            │
│                                                               │
│  ┌─────────────┐  (optional, via --profile)                  │
│  │ NGINX       │                                              │
│  │ :443 → :5601│                                              │
│  └─────────────┘                                              │
└──────────────────────────────────────────────────────────────┘
```

## Data Flow

1. **Agent → Manager** (TCP 1514): Wazuh agents send events encrypted with AES.
2. **Syslog → Manager** (UDP 1515): vCenter/ESXi and network devices send syslog.
3. **Cloud → Manager**: AWS (S3 pull) and GCP (Pub/Sub pull) modules fetch logs.
4. **Manager → Indexer** (HTTPS 9200): Filebeat ships decoded/enriched alerts.
5. **Dashboard → Indexer** (HTTPS 9200): Visualization queries.

## Security Model

- All inter-component communication uses TLS mutual authentication.
- Agent registration requires a shared secret (`authd` password).
- API access uses username/password + JWT tokens.
- No secrets stored in plaintext — all via `.env` or Ansible Vault.
- Network isolation via dedicated Docker bridge network.

## Storage

| Volume | Purpose | Persistence |
|--------|---------|-------------|
| `wazuh-indexer-data` | Alert indices, search data | Critical |
| `wazuh-manager-data` | Agent keys, queues | Critical |
| `wazuh-manager-logs` | Manager logs | Important |
| `wazuh-manager-etc` | Configuration | Important |

## Scaling Considerations

- **Single-node**: Current setup — suitable for up to ~100 agents.
- **Multi-node indexer**: Add indexer nodes for horizontal search scaling.
- **Manager cluster**: Active/active or active/passive for HA.
- **Worker nodes**: Distribute agent load across multiple manager workers.
