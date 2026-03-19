# Integration Guide

## Docker Monitoring

### Setup

Wazuh monitors Docker via two channels:

1. **Docker daemon logs** — collected by the agent from `/var/log/docker.log`
2. **Docker audit events** — captured via Linux audit rules

Add these audit rules on Docker hosts:

```bash
# /etc/audit/rules.d/docker.rules
-w /usr/bin/docker -p rwxa -k docker_commands
-w /var/lib/docker -p rwxa -k docker_filesystem
-w /etc/docker -p rwxa -k docker_config
-w /var/run/docker.sock -p rwxa -k docker_socket
```

Then restart auditd: `systemctl restart auditd`

### Custom Rules

Pre-built rules in `rules/docker/docker_rules.xml` detect:
- Container start/stop/die/create/destroy
- `exec` commands inside containers
- Image pull/build/push
- Privileged containers
- Sensitive host mounts (Docker socket, /etc, /proc)
- Ports exposed on 0.0.0.0
- Container crash loops

## VMware vCenter / ESXi

### Option A: Syslog Forwarding (Recommended)

Configure vCenter to send syslog to the Wazuh Manager:

1. In vCenter: **Configure → Advanced Settings**
2. Set `Syslog.global.logHost` to `udp://WAZUH_MANAGER_IP:1515`
3. For ESXi hosts: **Configure → System → Advanced System Settings → Syslog.global.logHost**

### Option B: Event Export Script

For more granular data, use the export script on a schedule:

```bash
python3 scripts/utils/vcenter_event_export.py \
    --vcenter vcenter.example.com \
    --username monitoring@vsphere.local \
    --output /var/log/vcenter_events.json
```

Then configure the Wazuh agent to monitor the output file:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/vcenter_events.json</location>
  <label key="source">vcenter</label>
</localfile>
```

## AWS

### CloudTrail

See `examples/cloud-configs/aws-cloudtrail.xml` for the full configuration.

Summary:
1. Enable CloudTrail → S3 bucket
2. Configure the `aws-s3` wodle in Wazuh Manager
3. Custom rules in `rules/aws/` will fire on IAM, security group, and EC2 events

### VPC Flow Logs

See `examples/cloud-configs/aws-vpc-flowlogs.xml`.

## GCP

### Audit Logs via Pub/Sub

See `examples/cloud-configs/gcp-pubsub.xml` for the full configuration with setup steps.

Summary:
1. Create Pub/Sub topic + subscription
2. Create a log sink routing audit logs to the topic
3. Configure the `gcp-pubsub` wodle in Wazuh Manager
4. Custom rules in `rules/gcp/` detect firewall, IAM, compute, and storage events

## Adding Custom Integrations

1. Create a decoder in `rules/<source>/<source>_decoders.xml`
2. Create rules in `rules/<source>/<source>_rules.xml`
3. Rules are auto-loaded via the volume mount in `docker-compose.yml`
4. Restart the manager: `docker exec wazuh-manager /var/ossec/bin/wazuh-control restart`
