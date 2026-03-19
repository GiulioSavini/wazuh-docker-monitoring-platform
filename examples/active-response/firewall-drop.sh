#!/usr/bin/env bash
###############################################################################
# Wazuh Active Response: Firewall IP Block
# Blocks an attacking IP via iptables/nftables when triggered by a rule.
#
# Configuration in ossec.conf:
#   <active-response>
#     <command>firewall-drop</command>
#     <location>local</location>
#     <rules_id>100501,100252</rules_id>  <!-- SSH brute force, vCenter brute force -->
#     <timeout>3600</timeout>              <!-- Unblock after 1 hour -->
#   </active-response>
#
#   <command>
#     <name>firewall-drop</name>
#     <executable>firewall-drop.sh</executable>
#     <expect>srcip</expect>
#   </command>
#
# Deploy: copy to /var/ossec/active-response/bin/ on agent hosts
###############################################################################

LOCAL=$(dirname "$0")
LOG_FILE="/var/ossec/logs/active-responses.log"

# Read parameters from STDIN (Wazuh AR protocol)
read -r INPUT
COMMAND=$(echo "$INPUT" | cut -d' ' -f1)
USER=$(echo "$INPUT" | cut -d' ' -f2)
IP=$(echo "$INPUT" | cut -d' ' -f3)
ALERT_ID=$(echo "$INPUT" | cut -d' ' -f4)
RULE_ID=$(echo "$INPUT" | cut -d' ' -f5)

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') active-response/firewall-drop: $*" >> "$LOG_FILE"
}

# Validate IP format
if ! echo "$IP" | grep -qP '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'; then
    log "ERROR: Invalid IP: $IP"
    exit 1
fi

# Safety: never block localhost or private management ranges
case "$IP" in
    127.*|0.0.0.0|10.0.1.1|10.0.1.10)
        log "SKIP: refusing to block protected IP $IP"
        exit 0
        ;;
esac

case "$COMMAND" in
    add)
        # Block the IP
        if command -v iptables &>/dev/null; then
            iptables -I INPUT -s "$IP" -j DROP 2>/dev/null
            iptables -I FORWARD -s "$IP" -j DROP 2>/dev/null
        fi
        if command -v nft &>/dev/null; then
            nft add rule inet filter input ip saddr "$IP" drop 2>/dev/null
        fi
        log "BLOCKED: $IP (rule=$RULE_ID, alert=$ALERT_ID)"
        ;;

    delete)
        # Unblock the IP (called after timeout)
        if command -v iptables &>/dev/null; then
            iptables -D INPUT -s "$IP" -j DROP 2>/dev/null
            iptables -D FORWARD -s "$IP" -j DROP 2>/dev/null
        fi
        if command -v nft &>/dev/null; then
            nft delete rule inet filter input ip saddr "$IP" drop 2>/dev/null
        fi
        log "UNBLOCKED: $IP (rule=$RULE_ID)"
        ;;

    *)
        log "ERROR: Unknown command: $COMMAND"
        exit 1
        ;;
esac

exit 0
