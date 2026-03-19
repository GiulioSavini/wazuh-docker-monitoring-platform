# Prerequisites & Permissions Guide

Complete checklist for preparing the environment before deploying Wazuh.

## 1. Wazuh Server (Docker Host)

### Hardware

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU      | 2 cores | 4+ cores    |
| RAM      | 4 GB    | 8+ GB       |
| Disk     | 20 GB   | 50+ GB SSD  |

### Software

- Docker 24.0+
- Docker Compose v2+
- OpenSSL (for certificate generation)
- Python 3.10+ (for discovery scripts)

### Kernel Parameters

```bash
# Required — OpenSearch will not start without this
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# Recommended for production
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf
```

### Network Ports (Wazuh Server)

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 9200 | TCP | Internal only | Indexer (OpenSearch) |
| 5601 | TCP | Inbound | Dashboard (HTTPS) |
| 55000 | TCP | Inbound | Manager API (HTTPS) |
| 1514 | TCP | Inbound | Agent communication |
| 1515 | UDP | Inbound | Syslog (vCenter, devices) |
| 443 | TCP | Inbound | NGINX reverse proxy (optional) |

### Docker Host User

```bash
# Add your user to the docker group (avoids sudo for docker commands)
sudo usermod -aG docker $USER
newgrp docker
```

### Automated Pre-Flight Check

```bash
bash scripts/utils/preflight-check.sh
# Auto-fix issues where possible:
bash scripts/utils/preflight-check.sh --fix
```

---

## 2. Linux Target Hosts (Agent Deployment)

### Required Access

The Ansible controller needs SSH access with a user that can sudo.

#### Option A: Automated Setup (Recommended)

Run on each target host:

```bash
sudo bash scripts/utils/setup-target-linux.sh \
    --ansible-user deploy \
    --manager-ip 10.0.1.10 \
    --ssh-key "ssh-rsa AAAA..."
```

This script configures:
- Service account with sudo
- Firewall rules (ufw/firewalld/iptables)
- SELinux booleans
- auditd installation and configuration
- Log directory permissions
- NTP synchronization

#### Option B: Manual Setup

**Service account:**
```bash
sudo useradd -m -s /bin/bash deploy
echo "deploy ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/deploy
sudo chmod 440 /etc/sudoers.d/deploy
```

**SSH key:**
```bash
sudo mkdir -p /home/deploy/.ssh
echo "ssh-rsa AAAA..." | sudo tee /home/deploy/.ssh/authorized_keys
sudo chown -R deploy:deploy /home/deploy/.ssh
sudo chmod 700 /home/deploy/.ssh && sudo chmod 600 /home/deploy/.ssh/authorized_keys
```

**Firewall (allow outbound to Wazuh Manager):**
```bash
# ufw
sudo ufw allow out to 10.0.1.10 port 1514 proto tcp

# firewalld
sudo firewall-cmd --permanent --add-port=1514/tcp && sudo firewall-cmd --reload

# iptables
sudo iptables -A OUTPUT -p tcp -d 10.0.1.10 --dport 1514 -j ACCEPT
```

**SELinux (if enforcing):**
```bash
sudo setsebool -P wazuh_agent_connect_all 1
# If agent still has issues:
sudo ausearch -m AVC -ts recent  # Check denials
sudo audit2allow -a -M wazuh_agent  # Generate policy
sudo semodule -i wazuh_agent.pp
```

**auditd:**
```bash
sudo apt install auditd   # Debian/Ubuntu
sudo yum install audit     # RHEL/CentOS
sudo systemctl enable --now auditd
```

### Minimum Permissions for Wazuh Agent

The agent (`ossec` user/group) needs:

| Path | Permission | Purpose |
|------|-----------|---------|
| `/var/log/syslog` | Read | System log monitoring |
| `/var/log/auth.log` | Read | Authentication events |
| `/var/log/audit/audit.log` | Read | Audit events |
| `/var/ossec/` | Read/Write | Agent installation directory |
| `/etc/` (selected files) | Read | File integrity monitoring |

---

## 3. Windows Target Hosts (Agent Deployment)

### Required Access

Ansible connects via WinRM (HTTPS, port 5986).

#### Option A: Automated Setup (Recommended)

Run on each Windows target as Administrator:

```powershell
.\scripts\utils\setup-target-windows.ps1 -ManagerIP 10.0.1.10
```

This script configures:
- Service account in Administrators group
- WinRM HTTPS with self-signed certificate
- Firewall rules (WinRM inbound + Wazuh outbound)
- Advanced audit policies (logon, account management, process creation)
- Command-line logging for Event 4688
- Event log size increases
- PowerShell script block & module logging
- Time synchronization

#### Option B: Manual Setup

**Enable WinRM:**
```powershell
# Run as Administrator
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# Create HTTPS listener
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
New-WSManInstance -ResourceURI winrm/config/Listener `
    -SelectorSet @{Address="*"; Transport="HTTPS"} `
    -ValueSet @{CertificateThumbprint=$cert.Thumbprint}

# Security settings
Set-Item WSMan:\localhost\Service\AllowUnencrypted $false
Set-Item WSMan:\localhost\Service\Auth\Basic $true
```

**Firewall:**
```powershell
# WinRM HTTPS inbound
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow

# Wazuh agent outbound
New-NetFirewallRule -DisplayName "Wazuh Agent" -Direction Outbound -Protocol TCP -RemotePort 1514 -RemoteAddress 10.0.1.10 -Action Allow
```

**Test WinRM from Ansible controller:**
```bash
ansible windows_servers -i inventories/production -m win_ping
```

### Recommended: Sysmon

Install Sysmon for enhanced process/network monitoring:

```powershell
# Download from Microsoft Sysinternals
# Install with a config optimized for security:
sysmon64.exe -accepteula -i sysmonconfig.xml
```

Wazuh agent automatically collects from `Microsoft-Windows-Sysmon/Operational`.

### Audit Policies

The setup script enables these audit subcategories:

| Category | Subcategory | Events |
|----------|-------------|--------|
| Logon/Logoff | Logon | 4624, 4625 |
| Account Management | User Account Management | 4720, 4722, 4723 |
| Account Management | Security Group Management | 4728, 4732 |
| Detailed Tracking | Process Creation | 4688 |
| Policy Change | Audit Policy Change | 4719 |
| Privilege Use | Sensitive Privilege Use | 4672, 4673 |

---

## 4. VMware vCenter

### Syslog Configuration

| Setting | Value |
|---------|-------|
| Target | `udp://WAZUH_MANAGER_IP:1515` |
| vCenter path | Configure → Advanced Settings → `Syslog.global.logHost` |
| ESXi path | Configure → System → Advanced System Settings → `Syslog.global.logHost` |

### API Access (for event export script)

Create a read-only vCenter user:

1. vCenter → Administration → Single Sign-On → Users
2. Create user: `wazuh-monitor@vsphere.local`
3. Assign role: **Read-Only** at the root datacenter level
4. Propagate to children: Yes

```bash
python3 scripts/utils/vcenter_event_export.py \
    --vcenter vcenter.example.com \
    --username wazuh-monitor@vsphere.local
```

---

## 5. Cloud Accounts

### AWS

Minimum IAM policy for CloudTrail log ingestion:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "WazuhCloudTrailRead",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::YOUR-CLOUDTRAIL-BUCKET",
                "arn:aws:s3:::YOUR-CLOUDTRAIL-BUCKET/*"
            ]
        }
    ]
}
```

Best practice: use an IAM role (if manager runs on EC2) instead of access keys.

### GCP

Minimum service account permissions:

| Role | Purpose |
|------|---------|
| `roles/pubsub.subscriber` | Read audit logs from Pub/Sub |
| `roles/logging.viewer` | (Optional) Direct log access |

```bash
gcloud iam service-accounts create wazuh-reader --display-name "Wazuh Log Reader"
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="serviceAccount:wazuh-reader@PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/pubsub.subscriber"
```

---

## Quick Reference: All Required Ports

```
Ansible Controller → Linux targets:    22/TCP   (SSH)
Ansible Controller → Windows targets:  5986/TCP (WinRM HTTPS)
Agents → Wazuh Manager:                1514/TCP (encrypted agent protocol)
vCenter/ESXi → Wazuh Manager:          1515/UDP (syslog)
Browser → Wazuh Dashboard:             5601/TCP (HTTPS)
Admin → Wazuh API:                     55000/TCP (HTTPS)
```
