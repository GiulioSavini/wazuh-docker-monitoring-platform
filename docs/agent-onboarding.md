# Agent Onboarding Guide

## Automated Pipeline

The onboarding script automates the full workflow:

```bash
./scripts/onboarding/auto_onboard.sh --subnet 10.0.0.0/24 --env production
```

### Pipeline Steps

1. **Discovery** — scans the subnet for active hosts, open ports, OS hints
2. **Inventory Generation** — creates an Ansible inventory from discovery results
3. **Agent Deployment** — runs Ansible playbooks to install/configure agents
4. **Verification** — generates a report of monitored vs. unmonitored hosts

### Dry Run

```bash
./scripts/onboarding/auto_onboard.sh --subnet 10.0.0.0/24 --dry-run
```

This runs discovery and inventory generation without deploying agents.

## Manual Deployment

### Linux

```bash
cd ansible
ansible-playbook -i inventories/production playbooks/deploy-linux-agent.yml \
    --limit web-prod-01 \
    --ask-vault-pass
```

### Windows

```bash
ansible-playbook -i inventories/production playbooks/deploy-windows-agent.yml \
    --limit dc-prod-01 \
    --ask-vault-pass
```

## Agent Groups

Agents are assigned to groups during registration. Groups control which shared configuration and rules they receive.

| Group | Use Case |
|-------|----------|
| `default` | Base configuration |
| `linux` | Linux-specific log collection |
| `windows` | Windows Event Log collection |
| `web` | Web server monitoring |
| `docker` | Docker host monitoring |
| `database` | Database server monitoring |
| `production` | Production environment tag |
| `lab` | Lab environment tag |

Combine groups with commas: `web,linux,production`

## Verifying Agent Connectivity

```bash
# From the Wazuh Manager container
docker exec wazuh-manager /var/ossec/bin/agent_control -l

# Check specific agent
docker exec wazuh-manager /var/ossec/bin/agent_control -i 001
```

## Removing an Agent

```bash
# List agents
docker exec wazuh-manager /var/ossec/bin/manage_agents -l

# Remove by ID
docker exec wazuh-manager /var/ossec/bin/manage_agents -r 001
```
