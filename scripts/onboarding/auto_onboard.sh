#!/usr/bin/env bash
###############################################################################
# Wazuh Automated Onboarding Pipeline
# Runs: discovery → inventory generation → agent deployment → verification
#
# Usage:
#   ./auto_onboard.sh --subnet 10.0.0.0/24 [--env production|lab] [--dry-run]
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DISCOVERY_DIR="$PROJECT_ROOT/scripts/discovery"
ANSIBLE_DIR="$PROJECT_ROOT/ansible"
OUTPUT_DIR="$SCRIPT_DIR/output/$(date +%Y%m%d_%H%M%S)"

# Defaults
SUBNET=""
ENV_NAME="production"
DRY_RUN=false
WORKERS=50

usage() {
    echo "Usage: $0 --subnet CIDR [--env production|lab] [--workers N] [--dry-run]"
    exit 1
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --subnet)   SUBNET="$2"; shift 2 ;;
        --env)      ENV_NAME="$2"; shift 2 ;;
        --workers)  WORKERS="$2"; shift 2 ;;
        --dry-run)  DRY_RUN=true; shift ;;
        -h|--help)  usage ;;
        *)          echo "Unknown option: $1"; usage ;;
    esac
done

[[ -z "$SUBNET" ]] && { echo "Error: --subnet is required"; usage; }

mkdir -p "$OUTPUT_DIR"
log "=== Wazuh Automated Onboarding ==="
log "Subnet:      $SUBNET"
log "Environment: $ENV_NAME"
log "Output:      $OUTPUT_DIR"
log "Dry run:     $DRY_RUN"
echo ""

# ─── Step 1: Network Discovery ───────────────────────────────────────────────
log "Step 1/4: Running network discovery..."
python3 "$DISCOVERY_DIR/network_discovery.py" \
    --subnet "$SUBNET" \
    --output json \
    --file "$OUTPUT_DIR/discovery.json" \
    --workers "$WORKERS"

HOSTS_FOUND=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/discovery.json')); print(d['scan_metadata']['total_hosts_found'])")
log "  Found $HOSTS_FOUND active hosts"

if [[ "$HOSTS_FOUND" -eq 0 ]]; then
    log "No hosts found — exiting."
    exit 0
fi

# ─── Step 2: Generate Ansible Inventory ──────────────────────────────────────
log "Step 2/4: Generating Ansible inventory..."
python3 -c "
import json, yaml
from pathlib import Path

data = json.load(open('$OUTPUT_DIR/discovery.json'))
inventory = data['ansible_inventory']

# Inject global vars
inventory['all']['vars'] = {
    'wazuh_manager_ip': '$(grep -oP "wazuh_manager_ip:\s*\"\K[^\"]*" "$ANSIBLE_DIR/inventories/$ENV_NAME/hosts.yml" 2>/dev/null || echo "10.0.1.10")',
    'wazuh_manager_port': 1514,
    'wazuh_agent_version': '4.9.0',
}

Path('$OUTPUT_DIR/inventory.yml').write_text(yaml.dump(inventory, default_flow_style=False))
print(f'  Generated inventory with {len(data[\"hosts\"])} hosts')
"
log "  Inventory written to $OUTPUT_DIR/inventory.yml"

# ─── Step 3: Deploy Agents ──────────────────────────────────────────────────
log "Step 3/4: Deploying Wazuh agents..."

if [[ "$DRY_RUN" == true ]]; then
    log "  [DRY RUN] Would run:"
    log "  ansible-playbook -i $OUTPUT_DIR/inventory.yml $ANSIBLE_DIR/playbooks/deploy-linux-agent.yml"
    log "  ansible-playbook -i $OUTPUT_DIR/inventory.yml $ANSIBLE_DIR/playbooks/deploy-windows-agent.yml"
else
    # Deploy to Linux hosts
    LINUX_COUNT=$(python3 -c "import yaml; inv=yaml.safe_load(open('$OUTPUT_DIR/inventory.yml')); print(len(inv.get('all',{}).get('children',{}).get('linux_servers',{}).get('hosts',{})))")
    if [[ "$LINUX_COUNT" -gt 0 ]]; then
        log "  Deploying to $LINUX_COUNT Linux hosts..."
        ansible-playbook \
            -i "$OUTPUT_DIR/inventory.yml" \
            "$ANSIBLE_DIR/playbooks/deploy-linux-agent.yml" \
            --limit linux_servers 2>&1 | tee "$OUTPUT_DIR/ansible_linux.log"
    fi

    # Deploy to Windows hosts
    WIN_COUNT=$(python3 -c "import yaml; inv=yaml.safe_load(open('$OUTPUT_DIR/inventory.yml')); print(len(inv.get('all',{}).get('children',{}).get('windows_servers',{}).get('hosts',{})))")
    if [[ "$WIN_COUNT" -gt 0 ]]; then
        log "  Deploying to $WIN_COUNT Windows hosts..."
        ansible-playbook \
            -i "$OUTPUT_DIR/inventory.yml" \
            "$ANSIBLE_DIR/playbooks/deploy-windows-agent.yml" \
            --limit windows_servers 2>&1 | tee "$OUTPUT_DIR/ansible_windows.log"
    fi
fi

# ─── Step 4: Verify & Report ────────────────────────────────────────────────
log "Step 4/4: Generating onboarding report..."
python3 -c "
import json
from datetime import datetime, timezone

data = json.load(open('$OUTPUT_DIR/discovery.json'))
hosts = data['hosts']

report = {
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'subnet': '$SUBNET',
    'environment': '$ENV_NAME',
    'summary': {
        'total_discovered': len(hosts),
        'linux_hosts': sum(1 for h in hosts if h['os_hint'] == 'linux'),
        'windows_hosts': sum(1 for h in hosts if h['os_hint'] == 'windows'),
        'unknown_os': sum(1 for h in hosts if h['os_hint'] == 'unknown'),
        'already_monitored': sum(1 for h in hosts if h['wazuh_agent_detected']),
        'needs_agent': sum(1 for h in hosts if not h['wazuh_agent_detected']),
    },
    'hosts': hosts,
}

with open('$OUTPUT_DIR/onboarding_report.json', 'w') as f:
    json.dump(report, f, indent=2)

s = report['summary']
print(f'''
╔══════════════════════════════════════════╗
║       Onboarding Report Summary          ║
╠══════════════════════════════════════════╣
║  Total discovered:    {s[\"total_discovered\"]:>5}              ║
║  Linux hosts:         {s[\"linux_hosts\"]:>5}              ║
║  Windows hosts:       {s[\"windows_hosts\"]:>5}              ║
║  Unknown OS:          {s[\"unknown_os\"]:>5}              ║
║  Already monitored:   {s[\"already_monitored\"]:>5}              ║
║  Needs agent:         {s[\"needs_agent\"]:>5}              ║
╚══════════════════════════════════════════╝
''')
"

log "=== Onboarding complete ==="
log "Outputs saved to: $OUTPUT_DIR/"
log "  discovery.json         — raw discovery data"
log "  inventory.yml          — generated Ansible inventory"
log "  onboarding_report.json — summary report"
