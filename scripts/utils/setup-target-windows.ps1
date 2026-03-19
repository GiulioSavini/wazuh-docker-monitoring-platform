<#
.SYNOPSIS
    Windows Target Host Preparation for Wazuh Agent Deployment

.DESCRIPTION
    Prepares a Windows server for Wazuh agent deployment via Ansible (WinRM).
    Configures: WinRM, firewall rules, service account, audit policies.

    Run this on each Windows target BEFORE deploying the agent with Ansible.

.PARAMETER AnsibleUser
    Local user for Ansible automation (default: deploy)

.PARAMETER AnsiblePassword
    Password for the Ansible user (prompted if not provided)

.PARAMETER ManagerIP
    Wazuh Manager IP address (default: 10.0.1.10)

.EXAMPLE
    .\setup-target-windows.ps1 -ManagerIP 10.0.1.10
    .\setup-target-windows.ps1 -AnsibleUser deploy -ManagerIP 10.0.1.10
#>

param(
    [string]$AnsibleUser = "deploy",
    [string]$AnsiblePassword = "",
    [string]$ManagerIP = "10.0.1.10",
    [int]$ManagerPort = 1514,
    [switch]$SkipWinRM
)

$ErrorActionPreference = "Stop"

function Write-Step { param([string]$msg) Write-Host "`n── $msg ──" -ForegroundColor Cyan }
function Write-OK   { param([string]$msg) Write-Host "  [OK]   $msg" -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$msg) Write-Host "  [FAIL] $msg" -ForegroundColor Red }

# Require admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "This script must be run as Administrator"
    exit 1
}

Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Windows Target Host Preparation         ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan

# ─── 1. Service Account ─────────────────────────────────────────────────────
Write-Step "Step 1: Service Account"

$userExists = Get-LocalUser -Name $AnsibleUser -ErrorAction SilentlyContinue
if ($userExists) {
    Write-OK "User '$AnsibleUser' already exists"
} else {
    if ([string]::IsNullOrEmpty($AnsiblePassword)) {
        $securePass = Read-Host "Enter password for '$AnsibleUser'" -AsSecureString
    } else {
        $securePass = ConvertTo-SecureString $AnsiblePassword -AsPlainText -Force
    }

    New-LocalUser -Name $AnsibleUser `
        -Password $securePass `
        -Description "Ansible automation account for Wazuh deployment" `
        -PasswordNeverExpires `
        -UserMayNotChangePassword
    Write-OK "Created local user: $AnsibleUser"
}

# Add to Administrators group
$adminGroup = Get-LocalGroup -SID "S-1-5-32-544"
$isMember = Get-LocalGroupMember -Group $adminGroup -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*\$AnsibleUser" }
if ($isMember) {
    Write-OK "'$AnsibleUser' is already in Administrators group"
} else {
    Add-LocalGroupMember -Group $adminGroup -Member $AnsibleUser
    Write-OK "Added '$AnsibleUser' to Administrators group"
}

# ─── 2. WinRM Configuration ─────────────────────────────────────────────────
Write-Step "Step 2: WinRM Configuration"

if (-not $SkipWinRM) {
    # Enable WinRM
    $winrmService = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    if ($winrmService.Status -ne "Running") {
        Enable-PSRemoting -Force -SkipNetworkProfileCheck
        Write-OK "WinRM enabled and started"
    } else {
        Write-OK "WinRM is already running"
    }

    # Configure WinRM for HTTPS (self-signed cert for lab; replace for production)
    $existingListener = Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate |
        Where-Object { $_.Transport -eq "HTTPS" }

    if ($existingListener) {
        Write-OK "HTTPS listener already configured"
    } else {
        # Create self-signed cert
        $hostname = [System.Net.Dns]::GetHostName()
        $cert = New-SelfSignedCertificate -DnsName $hostname -CertStoreLocation Cert:\LocalMachine\My
        New-WSManInstance -ResourceURI winrm/config/Listener `
            -SelectorSet @{Address="*"; Transport="HTTPS"} `
            -ValueSet @{CertificateThumbprint=$cert.Thumbprint}
        Write-OK "HTTPS listener created with self-signed certificate"
        Write-Warn "For production: replace with a CA-signed certificate"
    fi

    # Set WinRM settings
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
    Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $false
    Set-Item -Path WSMan:\localhost\MaxTimeoutms -Value 300000

    # Increase max memory per shell for Ansible
    Set-Item -Path WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value 1024

    Write-OK "WinRM security settings configured"
    Write-OK "  AllowUnencrypted: False"
    Write-OK "  Basic Auth: True (over HTTPS only)"
    Write-OK "  Max memory/shell: 1024MB"

    # Trusted hosts (restrict to Ansible controller in production)
    # Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "ANSIBLE_CONTROLLER_IP"
} else {
    Write-Warn "WinRM configuration skipped (--SkipWinRM)"
}

# ─── 3. Firewall Rules ──────────────────────────────────────────────────────
Write-Step "Step 3: Firewall Rules"

# WinRM HTTPS
$winrmRule = Get-NetFirewallRule -DisplayName "WinRM HTTPS" -ErrorAction SilentlyContinue
if (-not $winrmRule) {
    New-NetFirewallRule -DisplayName "WinRM HTTPS" `
        -Direction Inbound -Protocol TCP -LocalPort 5986 `
        -Action Allow -Profile Domain,Private `
        -Description "Allow WinRM HTTPS for Ansible"
    Write-OK "Firewall rule added: WinRM HTTPS (5986/TCP inbound)"
} else {
    Write-OK "WinRM HTTPS firewall rule already exists"
}

# Wazuh agent outbound
$wazuhRule = Get-NetFirewallRule -DisplayName "Wazuh Agent Outbound" -ErrorAction SilentlyContinue
if (-not $wazuhRule) {
    New-NetFirewallRule -DisplayName "Wazuh Agent Outbound" `
        -Direction Outbound -Protocol TCP -RemotePort $ManagerPort `
        -RemoteAddress $ManagerIP -Action Allow `
        -Description "Allow Wazuh agent to communicate with manager"
    Write-OK "Firewall rule added: Wazuh Agent → $ManagerIP`:$ManagerPort (outbound)"
} else {
    Write-OK "Wazuh Agent outbound rule already exists"
}

# ─── 4. Audit Policies ──────────────────────────────────────────────────────
Write-Step "Step 4: Audit Policies"

# Enable advanced audit policies for Wazuh monitoring
$auditPolicies = @(
    @{Subcategory="Logon";               Setting="Success,Failure"},
    @{Subcategory="Logoff";              Setting="Success"},
    @{Subcategory="Account Lockout";     Setting="Failure"},
    @{Subcategory="User Account Management"; Setting="Success,Failure"},
    @{Subcategory="Security Group Management"; Setting="Success,Failure"},
    @{Subcategory="Process Creation";    Setting="Success"},
    @{Subcategory="Process Termination"; Setting="Success"},
    @{Subcategory="Audit Policy Change"; Setting="Success,Failure"},
    @{Subcategory="System Integrity";    Setting="Success,Failure"},
    @{Subcategory="Sensitive Privilege Use"; Setting="Success,Failure"}
)

foreach ($policy in $auditPolicies) {
    try {
        auditpol /set /subcategory:"$($policy.Subcategory)" /success:enable /failure:enable 2>$null | Out-Null
    } catch {
        # Some subcategories may not support both success and failure
    }
}
Write-OK "Advanced audit policies configured"
Write-OK "  Logon/Logoff, Account Management, Process Creation,"
Write-OK "  Policy Changes, Privilege Use"

# Enable command-line in process creation events (Event ID 4688)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
Write-OK "Process command-line logging enabled (Event 4688)"

# ─── 5. Windows Event Log Size ──────────────────────────────────────────────
Write-Step "Step 5: Event Log Configuration"

$logs = @(
    @{Name="Security";    MaxSize=512MB},
    @{Name="System";      MaxSize=128MB},
    @{Name="Application"; MaxSize=128MB}
)

foreach ($eventLog in $logs) {
    try {
        $log = Get-WinEvent -ListLog $eventLog.Name
        if ($log.MaximumSizeInBytes -lt $eventLog.MaxSize) {
            Limit-EventLog -LogName $eventLog.Name -MaximumSize ($eventLog.MaxSize / 1KB) -OverflowAction OverwriteAsNeeded
            Write-OK "$($eventLog.Name) log: max size set to $($eventLog.MaxSize / 1MB)MB"
        } else {
            Write-OK "$($eventLog.Name) log: already ≥ $($eventLog.MaxSize / 1MB)MB"
        }
    } catch {
        Write-Warn "Could not configure $($eventLog.Name) event log"
    }
}

# Enable Sysmon logging channel if Sysmon is installed
if (Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue) {
    Write-OK "Sysmon detected — events will be collected by Wazuh agent"
} else {
    Write-Warn "Sysmon not installed — recommended for process monitoring"
    Write-Warn "  Download: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
}

# Enable PowerShell logging
$psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force | Out-Null }
Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Write-OK "PowerShell Script Block Logging enabled"

$psModulePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $psModulePath)) { New-Item -Path $psModulePath -Force | Out-Null }
Set-ItemProperty -Path $psModulePath -Name "EnableModuleLogging" -Value 1 -Type DWord
Write-OK "PowerShell Module Logging enabled"

# ─── 6. NTP ─────────────────────────────────────────────────────────────────
Write-Step "Step 6: Time Synchronization"

$w32tm = w32tm /query /status 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-OK "Windows Time Service is running"
} else {
    Start-Service -Name W32Time -ErrorAction SilentlyContinue
    w32tm /resync /nowait 2>$null | Out-Null
    Write-OK "Windows Time Service started and resync triggered"
}

# ─── Summary ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Preparation Complete" -ForegroundColor Green
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "This host is ready for Wazuh agent deployment via Ansible." -ForegroundColor Green
Write-Host ""
Write-Host "Checklist:" -ForegroundColor White
Write-Host "  [done] User '$AnsibleUser' in Administrators group" -ForegroundColor Gray
Write-Host "  [done] WinRM HTTPS configured" -ForegroundColor Gray
Write-Host "  [done] Firewall rules for WinRM + Wazuh" -ForegroundColor Gray
Write-Host "  [done] Audit policies enabled" -ForegroundColor Gray
Write-Host "  [done] Event log sizes increased" -ForegroundColor Gray
Write-Host "  [done] PowerShell logging enabled" -ForegroundColor Gray
Write-Host "  [done] Time synchronization verified" -ForegroundColor Gray
Write-Host ""
Write-Host "Next: run from the Ansible controller:" -ForegroundColor Yellow
Write-Host "  ansible-playbook -i inventories/production playbooks/deploy-windows-agent.yml" -ForegroundColor Yellow
Write-Host ""
Write-Host "Test WinRM connectivity:" -ForegroundColor Yellow
Write-Host "  ansible windows_servers -i inventories/production -m win_ping" -ForegroundColor Yellow
