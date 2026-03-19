#!/usr/bin/env bash
###############################################################################
# Linux Target Host Preparation
# Detects OS (Ubuntu/Debian, RHEL/CentOS/Rocky/Alma, SUSE) and configures
# everything needed for Wazuh agent deployment.
#
# Usage:
#   sudo bash setup-target-linux.sh --ansible-user deploy --manager-ip 10.0.1.10
#   sudo bash setup-target-linux.sh --ansible-user deploy --manager-ip 10.0.1.10 --ssh-key "ssh-rsa ..."
###############################################################################
set -euo pipefail

ANSIBLE_USER="${ANSIBLE_USER:-deploy}"
MANAGER_IP="${MANAGER_IP:-10.0.1.10}"
MANAGER_PORT=1514
REG_PORT=1515
SSH_PUB_KEY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ansible-user) ANSIBLE_USER="$2"; shift 2 ;;
        --manager-ip)   MANAGER_IP="$2"; shift 2 ;;
        --ssh-key)      SSH_PUB_KEY="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--ansible-user NAME] [--manager-ip IP] [--ssh-key 'ssh-rsa ...']"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

log()  { echo "[setup] $*"; }
ok()   { echo -e "[setup] \033[0;32m✓\033[0m $*"; }
warn() { echo -e "[setup] \033[0;33m!\033[0m $*"; }
err()  { echo -e "[setup] \033[0;31m✗\033[0m $*"; }

[[ $EUID -ne 0 ]] && { err "Run as root (or sudo)"; exit 1; }

# ─── OS Detection ───────────────────────────────────────────────────────────
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="${ID,,}"
        OS_VERSION="${VERSION_ID}"
        OS_FAMILY=""
        case "$OS_ID" in
            ubuntu|debian|linuxmint|pop)
                OS_FAMILY="debian" ;;
            rhel|centos|rocky|almalinux|ol|fedora|amazon)
                OS_FAMILY="redhat" ;;
            sles|opensuse*|suse)
                OS_FAMILY="suse" ;;
            *)
                # Fallback: check for ID_LIKE
                if echo "${ID_LIKE:-}" | grep -qi debian; then
                    OS_FAMILY="debian"
                elif echo "${ID_LIKE:-}" | grep -qi rhel; then
                    OS_FAMILY="redhat"
                else
                    OS_FAMILY="unknown"
                fi ;;
        esac
    else
        err "Cannot detect OS — /etc/os-release not found"
        exit 1
    fi
}

detect_os
log "═══ Linux Target Host Preparation ═══"
log "Detected OS:  $OS_ID $OS_VERSION ($OS_FAMILY family)"
log "Ansible user: $ANSIBLE_USER"
log "Manager IP:   $MANAGER_IP"
echo ""

# ─── 1. Install base dependencies ───────────────────────────────────────────
log "── Step 1: Base Dependencies ──"

install_packages() {
    case "$OS_FAMILY" in
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq curl gnupg apt-transport-https \
                lsb-release ca-certificates acl auditd audispd-plugins \
                net-tools 2>/dev/null
            ok "Packages installed (apt)"
            ;;
        redhat)
            if command -v dnf &>/dev/null; then
                PKG_MGR="dnf"
            else
                PKG_MGR="yum"
            fi
            $PKG_MGR install -y -q curl gnupg2 policycoreutils-python-utils \
                audit audit-libs acl net-tools 2>/dev/null || \
            $PKG_MGR install -y -q curl gnupg2 policycoreutils-python \
                audit audit-libs acl net-tools 2>/dev/null
            ok "Packages installed ($PKG_MGR)"
            ;;
        suse)
            zypper -n install -y curl audit acl net-tools 2>/dev/null
            ok "Packages installed (zypper)"
            ;;
        *)
            warn "Unknown OS family '$OS_FAMILY' — install dependencies manually"
            ;;
    esac
}

install_packages
echo ""

# ─── 2. Service account ─────────────────────────────────────────────────────
log "── Step 2: Service Account ──"

if id "$ANSIBLE_USER" &>/dev/null; then
    ok "User '$ANSIBLE_USER' already exists"
else
    useradd -m -s /bin/bash -c "Ansible automation account" "$ANSIBLE_USER"
    ok "Created user: $ANSIBLE_USER"
fi

# SSH key
if [[ -n "$SSH_PUB_KEY" ]]; then
    SSHDIR="/home/$ANSIBLE_USER/.ssh"
    mkdir -p "$SSHDIR"
    echo "$SSH_PUB_KEY" >> "$SSHDIR/authorized_keys"
    sort -u "$SSHDIR/authorized_keys" -o "$SSHDIR/authorized_keys"
    chown -R "$ANSIBLE_USER:$ANSIBLE_USER" "$SSHDIR"
    chmod 700 "$SSHDIR"
    chmod 600 "$SSHDIR/authorized_keys"
    ok "SSH public key added"
fi

# Sudoers
SUDOERS_FILE="/etc/sudoers.d/$ANSIBLE_USER"
if [[ -f "$SUDOERS_FILE" ]]; then
    ok "Sudoers entry exists"
else
    cat > "$SUDOERS_FILE" <<EOF
# Ansible automation — passwordless sudo for Wazuh deployment
$ANSIBLE_USER ALL=(ALL) NOPASSWD: ALL
EOF
    chmod 440 "$SUDOERS_FILE"
    visudo -cf "$SUDOERS_FILE" || { rm -f "$SUDOERS_FILE"; err "Invalid sudoers"; exit 1; }
    ok "Sudoers configured: $SUDOERS_FILE"
fi
echo ""

# ─── 3. Firewall ────────────────────────────────────────────────────────────
log "── Step 3: Firewall ──"

configure_firewall() {
    # ufw (Ubuntu default)
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
        log "Detected: ufw (Ubuntu/Debian)"
        ufw allow from "$MANAGER_IP" to any port 22 proto tcp comment "SSH Ansible" 2>/dev/null || true
        ufw allow out to "$MANAGER_IP" port "$MANAGER_PORT" proto tcp comment "Wazuh agent" 2>/dev/null || true
        ufw allow out to "$MANAGER_IP" port "$REG_PORT" proto tcp comment "Wazuh registration" 2>/dev/null || true
        ok "ufw rules configured"
        return
    fi

    # firewalld (RHEL/CentOS/Rocky/Alma/Fedora default)
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        log "Detected: firewalld (RHEL family)"
        firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$MANAGER_IP accept" 2>/dev/null || true
        firewall-cmd --permanent --add-port=$MANAGER_PORT/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=$REG_PORT/tcp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null
        ok "firewalld rules configured"
        return
    fi

    # iptables fallback
    if command -v iptables &>/dev/null; then
        log "Detected: iptables (fallback)"
        iptables -A OUTPUT -p tcp -d "$MANAGER_IP" --dport $MANAGER_PORT -j ACCEPT 2>/dev/null || true
        iptables -A OUTPUT -p tcp -d "$MANAGER_IP" --dport $REG_PORT -j ACCEPT 2>/dev/null || true

        # Persist rules based on distro
        if command -v netfilter-persistent &>/dev/null; then
            netfilter-persistent save 2>/dev/null || true
            ok "iptables rules saved (netfilter-persistent)"
        elif command -v iptables-save &>/dev/null && [[ -d /etc/sysconfig ]]; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            ok "iptables rules saved (/etc/sysconfig/iptables)"
        else
            warn "iptables rules added but NOT persisted — save manually"
        fi
        return
    fi

    # nftables (newer systems)
    if command -v nft &>/dev/null; then
        log "Detected: nftables"
        warn "nftables detected — add rules manually or use firewalld frontend"
        return
    fi

    warn "No active firewall detected"
}

configure_firewall
echo ""

# ─── 4. SELinux / AppArmor ──────────────────────────────────────────────────
log "── Step 4: Security Modules ──"

if command -v getenforce &>/dev/null; then
    SELINUX_STATUS=$(getenforce 2>/dev/null || echo "unknown")
    log "SELinux: $SELINUX_STATUS"
    if [[ "$SELINUX_STATUS" == "Enforcing" ]]; then
        # Wazuh-specific booleans
        for bool in wazuh_agent_connect_all daemons_enable_cluster_mode; do
            setsebool -P "$bool" 1 2>/dev/null && ok "SELinux bool: $bool = on" || true
        done
        # If on RHEL 8+ with custom policy
        if command -v semanage &>/dev/null; then
            semanage port -a -t wazuh_port_t -p tcp $MANAGER_PORT 2>/dev/null || true
        fi
        ok "SELinux configured for Wazuh agent"
        warn "If agent fails later: ausearch -m AVC -ts recent | audit2allow"
    fi
elif command -v aa-status &>/dev/null; then
    log "AppArmor: active"
    # Ubuntu: check if wazuh profile might block
    if [[ -d /etc/apparmor.d ]]; then
        ok "AppArmor detected — Wazuh agent typically runs without profile conflicts"
        warn "If agent fails: check dmesg | grep apparmor"
    fi
else
    ok "No mandatory access control (SELinux/AppArmor) detected"
fi
echo ""

# ─── 5. auditd ──────────────────────────────────────────────────────────────
log "── Step 5: Audit Framework ──"

if ! command -v auditctl &>/dev/null; then
    warn "auditd not found after package install — may need manual installation"
fi

if systemctl is-active auditd &>/dev/null; then
    ok "auditd is running"
else
    systemctl enable --now auditd 2>/dev/null || true
    ok "auditd enabled and started"
fi

# Tune auditd config
if [[ -f /etc/audit/auditd.conf ]]; then
    sed -i 's/^num_logs.*/num_logs = 10/' /etc/audit/auditd.conf 2>/dev/null || true
    sed -i 's/^max_log_file .*/max_log_file = 50/' /etc/audit/auditd.conf 2>/dev/null || true
    sed -i 's/^space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf 2>/dev/null || true
    ok "auditd tuned: num_logs=10, max_log_file=50MB"
fi

# Dispatcher for RHEL/CentOS (audispd)
case "$OS_FAMILY" in
    redhat)
        if [[ -f /etc/audisp/plugins.d/syslog.conf ]]; then
            sed -i 's/active = no/active = yes/' /etc/audisp/plugins.d/syslog.conf 2>/dev/null || true
            ok "audisp syslog plugin enabled (RHEL)"
        fi
        ;;
    debian)
        if [[ -f /etc/audisp/plugins.d/syslog.conf ]]; then
            sed -i 's/active = no/active = yes/' /etc/audisp/plugins.d/syslog.conf 2>/dev/null || true
            ok "audisp syslog plugin enabled (Debian)"
        fi
        ;;
esac
echo ""

# ─── 6. Log permissions ─────────────────────────────────────────────────────
log "── Step 6: Directories & Permissions ──"

# Wazuh agent runs as ossec user — needs read access to logs
LOGFILES=()
case "$OS_FAMILY" in
    debian)
        LOGFILES=(/var/log/syslog /var/log/auth.log /var/log/dpkg.log /var/log/kern.log)
        ;;
    redhat)
        LOGFILES=(/var/log/messages /var/log/secure /var/log/yum.log /var/log/cron)
        ;;
    suse)
        LOGFILES=(/var/log/messages /var/log/secure /var/log/zypper.log)
        ;;
esac

# Common logs
LOGFILES+=(/var/log/audit/audit.log)

for logfile in "${LOGFILES[@]}"; do
    if [[ -f "$logfile" ]]; then
        setfacl -m g:ossec:r "$logfile" 2>/dev/null || chmod o+r "$logfile" 2>/dev/null || true
    fi
done

# Ensure /var/log directories are traversable
for dir in /var/log /var/log/audit; do
    [[ -d "$dir" ]] && setfacl -m g:ossec:rx "$dir" 2>/dev/null || chmod o+rx "$dir" 2>/dev/null || true
done

mkdir -p /var/ossec 2>/dev/null || true
ok "Log permissions configured for $OS_FAMILY"
echo ""

# ─── 7. Distro-specific log collection config ───────────────────────────────
log "── Step 7: Log Source Configuration ──"

# Create a reference file so Ansible knows which logs to collect
CONFIG_HINT="/tmp/wazuh_agent_log_sources.txt"
cat > "$CONFIG_HINT" <<EOF
# Auto-detected log sources for $OS_ID $OS_VERSION
# OS family: $OS_FAMILY
EOF

case "$OS_FAMILY" in
    debian)
        cat >> "$CONFIG_HINT" <<'EOF'
syslog=/var/log/syslog
auth=/var/log/auth.log
dpkg=/var/log/dpkg.log
kern=/var/log/kern.log
audit=/var/log/audit/audit.log
EOF
        ok "Log sources: syslog, auth.log, dpkg.log, kern.log, audit.log"
        ;;
    redhat)
        cat >> "$CONFIG_HINT" <<'EOF'
syslog=/var/log/messages
auth=/var/log/secure
yum=/var/log/yum.log
cron=/var/log/cron
audit=/var/log/audit/audit.log
EOF
        ok "Log sources: messages, secure, yum.log, cron, audit.log"
        # RHEL 8+ uses rsyslog; ensure it's running
        if systemctl is-active rsyslog &>/dev/null; then
            ok "rsyslog is running"
        else
            systemctl enable --now rsyslog 2>/dev/null || true
            ok "rsyslog enabled"
        fi
        ;;
    suse)
        cat >> "$CONFIG_HINT" <<'EOF'
syslog=/var/log/messages
auth=/var/log/secure
zypper=/var/log/zypper.log
audit=/var/log/audit/audit.log
EOF
        ok "Log sources: messages, secure, zypper.log, audit.log"
        ;;
esac

# journald — all modern distros
if command -v journalctl &>/dev/null; then
    echo "journald=yes" >> "$CONFIG_HINT"
    # Ensure persistent journal (some minimal installs use volatile)
    mkdir -p /var/log/journal 2>/dev/null || true
    systemd-tmpfiles --create --prefix /var/log/journal 2>/dev/null || true
    ok "journald available (persistent storage ensured)"
fi
echo ""

# ─── 8. NTP ─────────────────────────────────────────────────────────────────
log "── Step 8: Time Synchronization ──"

case "$OS_FAMILY" in
    debian)
        # Ubuntu 18.04+: systemd-timesyncd; or chrony
        if command -v timedatectl &>/dev/null; then
            timedatectl set-ntp true 2>/dev/null || true
            NTP_SYNC=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo "n/a")
            ok "NTP status: $NTP_SYNC (timedatectl)"
        fi
        ;;
    redhat)
        # RHEL 8+: chrony by default
        if systemctl is-active chronyd &>/dev/null; then
            ok "chronyd is running"
        elif command -v chronyc &>/dev/null; then
            systemctl enable --now chronyd 2>/dev/null || true
            ok "chronyd enabled"
        elif command -v timedatectl &>/dev/null; then
            timedatectl set-ntp true 2>/dev/null || true
            ok "NTP enabled via timedatectl"
        fi
        ;;
    suse)
        if systemctl is-active chronyd &>/dev/null; then
            ok "chronyd is running"
        fi
        ;;
esac
echo ""

# ─── 9. Logrotate for Wazuh agent logs ──────────────────────────────────────
log "── Step 9: Logrotate ──"

if command -v logrotate &>/dev/null; then
    cat > /etc/logrotate.d/wazuh-agent <<'EOF'
/var/ossec/logs/ossec.log
/var/ossec/logs/active-responses.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root ossec
    postrotate
        systemctl reload wazuh-agent 2>/dev/null || true
    endscript
}
EOF
    ok "Logrotate configured for Wazuh agent logs"
else
    warn "logrotate not found — install for log management"
fi
echo ""

# ─── Summary ─────────────────────────────────────────────────────────────────
log "═══ Preparation Complete ═══"
log ""
log "OS:            $OS_ID $OS_VERSION ($OS_FAMILY)"
log "User:          $ANSIBLE_USER (sudo enabled)"
log "Firewall:      configured"
log "Audit:         auditd running"
log "Log sources:   see $CONFIG_HINT"
log "Logrotate:     configured"
log ""
log "Next steps:"
log "  1. Deploy auditd rules:  copy rules/linux/auditd_recommended.rules → /etc/audit/rules.d/"
log "  2. Run Ansible playbook: ansible-playbook playbooks/deploy-linux-agent.yml"
log "  3. Verify agent: docker exec wazuh-manager /var/ossec/bin/agent_control -l"
