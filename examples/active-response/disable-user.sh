#!/usr/bin/env bash
###############################################################################
# Wazuh Active Response: Disable User Account
# Locks a local user account when brute-force or unauthorized access is detected.
#
# Configuration in ossec.conf:
#   <command>
#     <name>disable-user</name>
#     <executable>disable-user.sh</executable>
#     <expect>user</expect>
#   </command>
#
#   <active-response>
#     <command>disable-user</command>
#     <location>local</location>
#     <rules_id>100513</rules_id>  <!-- Repeated unauthorized sudo -->
#     <timeout>7200</timeout>      <!-- Re-enable after 2 hours -->
#   </active-response>
#
# Deploy: copy to /var/ossec/active-response/bin/ on agent hosts
###############################################################################

LOG_FILE="/var/ossec/logs/active-responses.log"

read -r INPUT
COMMAND=$(echo "$INPUT" | cut -d' ' -f1)
USER=$(echo "$INPUT" | cut -d' ' -f2)

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') active-response/disable-user: $*" >> "$LOG_FILE"
}

# Safety: never lock critical accounts
case "$USER" in
    root|admin|deploy|ansible|ossec|wazuh)
        log "SKIP: refusing to disable protected user: $USER"
        exit 0
        ;;
esac

case "$COMMAND" in
    add)
        if id "$USER" &>/dev/null; then
            passwd -l "$USER" 2>/dev/null
            log "LOCKED: user $USER"
        else
            log "SKIP: user $USER does not exist"
        fi
        ;;
    delete)
        if id "$USER" &>/dev/null; then
            passwd -u "$USER" 2>/dev/null
            log "UNLOCKED: user $USER"
        fi
        ;;
    *)
        log "ERROR: Unknown command: $COMMAND"
        exit 1
        ;;
esac

exit 0
