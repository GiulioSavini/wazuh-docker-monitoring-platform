#!/usr/bin/env python3
"""
vCenter Event & Inventory Exporter for Wazuh
Connects to vCenter via pyvmomi, exports events and VM inventory
to JSON for Wazuh ingestion via syslog or file monitoring.

Usage:
    python3 vcenter_event_export.py \
        --vcenter vcenter.example.com \
        --username admin@vsphere.local \
        --output /var/log/vcenter_events.json

Dependencies:
    pip install pyvmomi
"""

import argparse
import getpass
import json
import logging
import ssl
import sys
from datetime import datetime, timedelta, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

try:
    from pyVim.connect import SmartConnect, Disconnect
    from pyVmomi import vim
except ImportError:
    log.error("pyvmomi is required: pip install pyvmomi")
    sys.exit(1)


def connect_vcenter(host: str, username: str, password: str, port: int = 443):
    """Connect to vCenter with SSL verification disabled for lab use."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    log.info("Connecting to vCenter: %s", host)
    si = SmartConnect(host=host, user=username, pwd=password, port=port, sslContext=context)
    return si


def get_events(si, hours_back: int = 24, max_events: int = 1000) -> list[dict]:
    """Retrieve recent events from vCenter Event Manager."""
    event_manager = si.content.eventManager

    filter_spec = vim.event.EventFilterSpec()
    now = datetime.now(timezone.utc)
    filter_spec.time = vim.event.EventFilterSpec.ByTime()
    filter_spec.time.beginTime = now - timedelta(hours=hours_back)
    filter_spec.time.endTime = now

    collector = event_manager.CreateCollectorForEvents(filter_spec)
    collector.ResetCollector()

    events = []
    batch = collector.ReadNextEvents(maxCount=max_events)
    while batch:
        for event in batch:
            events.append({
                "timestamp": event.createdTime.isoformat() if event.createdTime else "",
                "event_type": type(event).__name__,
                "message": event.fullFormattedMessage or "",
                "user": event.userName or "",
                "datacenter": event.datacenter.name if event.datacenter else "",
                "host": event.host.name if event.host else "",
                "vm": event.vm.name if event.vm else "",
                "severity": getattr(event, "severity", "info"),
            })
        batch = collector.ReadNextEvents(maxCount=max_events)

    collector.DestroyCollector()
    log.info("Retrieved %d events from last %d hours", len(events), hours_back)
    return events


def get_vm_inventory(si) -> list[dict]:
    """Retrieve VM inventory from vCenter."""
    content = si.content
    container = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.VirtualMachine], True
    )

    vms = []
    for vm in container.view:
        summary = vm.summary
        vms.append({
            "name": summary.config.name,
            "uuid": summary.config.uuid,
            "power_state": summary.runtime.powerState,
            "guest_os": summary.config.guestFullName or "",
            "ip_address": summary.guest.ipAddress or "",
            "host": summary.runtime.host.name if summary.runtime.host else "",
            "cpu_count": summary.config.numCpu,
            "memory_mb": summary.config.memorySizeMB,
            "tools_status": str(summary.guest.toolsStatus) if summary.guest else "",
            "annotation": summary.config.annotation or "",
        })

    container.Destroy()
    log.info("Retrieved inventory for %d VMs", len(vms))
    return vms


def main():
    parser = argparse.ArgumentParser(description="vCenter event/inventory exporter for Wazuh")
    parser.add_argument("--vcenter", required=True, help="vCenter hostname or IP")
    parser.add_argument("--username", required=True, help="vCenter username")
    parser.add_argument("--password", help="vCenter password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=443, help="vCenter API port")
    parser.add_argument("--hours", type=int, default=24, help="Hours of events to retrieve")
    parser.add_argument("--output", help="Output JSON file path")
    parser.add_argument("--mode", choices=["events", "inventory", "both"], default="both")
    args = parser.parse_args()

    password = args.password or getpass.getpass("vCenter password: ")
    si = connect_vcenter(args.vcenter, args.username, password, args.port)

    try:
        result = {"vcenter": args.vcenter, "export_time": datetime.now(timezone.utc).isoformat()}

        if args.mode in ("events", "both"):
            result["events"] = get_events(si, args.hours)

        if args.mode in ("inventory", "both"):
            result["vm_inventory"] = get_vm_inventory(si)

        output = json.dumps(result, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            log.info("Output written to %s", args.output)
        else:
            print(output)

    finally:
        Disconnect(si)


if __name__ == "__main__":
    main()
