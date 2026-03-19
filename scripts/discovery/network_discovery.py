#!/usr/bin/env python3
"""
Enterprise Network Discovery Tool
Safe, controlled asset discovery for Wazuh monitoring onboarding.
Identifies active hosts, open ports, and services relevant to monitoring.

Usage:
    python3 network_discovery.py --subnet 10.0.0.0/24 --output json
    python3 network_discovery.py --subnet 192.168.1.0/24 --output csv --ports 22,80,443,5985,5986
"""

import argparse
import csv
import io
import ipaddress
import json
import logging
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# Ports relevant for monitoring agent deployment and service detection
DEFAULT_PORTS = [
    22,     # SSH
    80,     # HTTP
    135,    # WMI
    443,    # HTTPS
    445,    # SMB
    1514,   # Wazuh agent
    3389,   # RDP
    5985,   # WinRM HTTP
    5986,   # WinRM HTTPS
    8443,   # vCenter/HTTPS alt
    9200,   # Elasticsearch/OpenSearch
]

SERVICE_MAP = {
    22: "ssh",
    80: "http",
    135: "wmi",
    443: "https",
    445: "smb",
    1514: "wazuh-agent",
    3389: "rdp",
    5985: "winrm-http",
    5986: "winrm-https",
    8443: "https-alt",
    9200: "opensearch",
}


@dataclass
class DiscoveredHost:
    ip: str
    hostname: str = ""
    open_ports: list = field(default_factory=list)
    services: list = field(default_factory=list)
    os_hint: str = "unknown"
    wazuh_agent_detected: bool = False
    suggested_group: str = ""
    scan_time: str = ""


def resolve_hostname(ip: str) -> str:
    """Reverse DNS lookup — non-blocking, short timeout."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout, OSError):
        return ""


def check_port(ip: str, port: int, timeout: float = 1.5) -> bool:
    """TCP connect check for a single port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def ping_host(ip: str) -> bool:
    """ICMP ping with short timeout."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            capture_output=True,
            timeout=3,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def guess_os(open_ports: list[int]) -> str:
    """Heuristic OS detection based on open ports."""
    windows_indicators = {135, 445, 3389, 5985, 5986}
    linux_indicators = {22}

    port_set = set(open_ports)
    windows_score = len(port_set & windows_indicators)
    linux_score = len(port_set & linux_indicators)

    if windows_score > linux_score:
        return "windows"
    if linux_score > 0:
        return "linux"
    return "unknown"


def suggest_group(os_hint: str, services: list[str]) -> str:
    """Suggest a Wazuh agent group based on detected services."""
    groups = []
    if os_hint == "windows":
        groups.append("windows")
    elif os_hint == "linux":
        groups.append("linux")

    if "https-alt" in services or "https" in services:
        groups.append("web")
    if "opensearch" in services:
        groups.append("database")

    return ",".join(groups) if groups else "default"


def scan_host(ip: str, ports: list[int]) -> DiscoveredHost | None:
    """Full scan of a single host: ping, port scan, hostname resolution."""
    if not ping_host(ip):
        return None

    log.debug("Host %s is alive, scanning ports...", ip)
    open_ports = []
    for port in ports:
        if check_port(ip, port):
            open_ports.append(port)

    hostname = resolve_hostname(ip)
    services = [SERVICE_MAP.get(p, f"tcp/{p}") for p in open_ports]
    os_hint = guess_os(open_ports)
    wazuh_detected = 1514 in open_ports

    return DiscoveredHost(
        ip=str(ip),
        hostname=hostname,
        open_ports=open_ports,
        services=services,
        os_hint=os_hint,
        wazuh_agent_detected=wazuh_detected,
        suggested_group=suggest_group(os_hint, services),
        scan_time=datetime.now(timezone.utc).isoformat(),
    )


def discover(subnet: str, ports: list[int], workers: int = 50) -> list[DiscoveredHost]:
    """Discover all active hosts in a subnet."""
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())
    log.info("Scanning %d hosts in %s with %d workers...", len(hosts), subnet, workers)

    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_host, str(ip), ports): ip for ip in hosts}
        for future in as_completed(futures):
            host = future.result()
            if host:
                log.info("Found: %s (%s) — ports: %s", host.ip, host.hostname or "no PTR", host.open_ports)
                results.append(host)

    results.sort(key=lambda h: ipaddress.ip_address(h.ip))
    return results


def generate_ansible_inventory(hosts: list[DiscoveredHost]) -> dict:
    """Generate Ansible inventory structure from discovered hosts."""
    inventory = {
        "all": {
            "children": {
                "linux_servers": {"hosts": {}},
                "windows_servers": {"hosts": {}},
                "unknown_os": {"hosts": {}},
            }
        }
    }

    for host in hosts:
        name = host.hostname.split(".")[0] if host.hostname else host.ip.replace(".", "-")
        entry = {
            "ansible_host": host.ip,
            "wazuh_agent_groups": host.suggested_group,
        }
        if host.os_hint == "windows":
            entry["ansible_connection"] = "winrm"
            entry["ansible_port"] = 5986 if 5986 in host.open_ports else 5985
            inventory["all"]["children"]["windows_servers"]["hosts"][name] = entry
        elif host.os_hint == "linux":
            inventory["all"]["children"]["linux_servers"]["hosts"][name] = entry
        else:
            inventory["all"]["children"]["unknown_os"]["hosts"][name] = entry

    return inventory


def output_json(hosts: list[DiscoveredHost], filepath: str | None):
    """Write results as JSON."""
    data = {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_hosts_found": len(hosts),
            "hosts_with_wazuh": sum(1 for h in hosts if h.wazuh_agent_detected),
        },
        "hosts": [asdict(h) for h in hosts],
        "ansible_inventory": generate_ansible_inventory(hosts),
    }
    content = json.dumps(data, indent=2)
    if filepath:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        Path(filepath).write_text(content)
        log.info("JSON output written to %s", filepath)
    else:
        print(content)


def output_csv(hosts: list[DiscoveredHost], filepath: str | None):
    """Write results as CSV."""
    buf = io.StringIO() if not filepath else open(filepath, "w", newline="")
    writer = csv.writer(buf)
    writer.writerow(["ip", "hostname", "os_hint", "open_ports", "services", "wazuh_agent", "suggested_group", "scan_time"])
    for h in hosts:
        writer.writerow([
            h.ip, h.hostname, h.os_hint,
            ";".join(map(str, h.open_ports)),
            ";".join(h.services),
            h.wazuh_agent_detected,
            h.suggested_group,
            h.scan_time,
        ])
    if filepath:
        buf.close()
        log.info("CSV output written to %s", filepath)
    else:
        print(buf.getvalue())
        buf.close()


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise network discovery for Wazuh monitoring onboarding",
    )
    parser.add_argument("--subnet", required=True, help="CIDR subnet to scan (e.g. 10.0.0.0/24)")
    parser.add_argument("--output", choices=["json", "csv"], default="json", help="Output format")
    parser.add_argument("--file", help="Output file path (stdout if omitted)")
    parser.add_argument("--ports", help="Comma-separated ports to scan (default: monitoring-relevant ports)")
    parser.add_argument("--workers", type=int, default=50, help="Concurrent scan workers (default: 50)")
    parser.add_argument("--inventory", action="store_true", help="Also generate Ansible inventory YAML")
    args = parser.parse_args()

    ports = [int(p) for p in args.ports.split(",")] if args.ports else DEFAULT_PORTS

    try:
        ipaddress.ip_network(args.subnet, strict=False)
    except ValueError:
        log.error("Invalid subnet: %s", args.subnet)
        sys.exit(1)

    hosts = discover(args.subnet, ports, args.workers)
    log.info("Discovery complete: %d hosts found", len(hosts))

    if args.output == "json":
        output_json(hosts, args.file)
    else:
        output_csv(hosts, args.file)

    if args.inventory:
        inv = generate_ansible_inventory(hosts)
        inv_path = args.file.replace(".json", ".inventory.yml").replace(".csv", ".inventory.yml") if args.file else "discovery_inventory.yml"
        import yaml
        Path(inv_path).write_text(yaml.dump(inv, default_flow_style=False))
        log.info("Ansible inventory written to %s", inv_path)


if __name__ == "__main__":
    main()
