"""Passive network scanner - no root required."""

from __future__ import annotations

import platform
import re
import socket
import subprocess
from pathlib import Path

from bigr.models import Asset, ScanMethod, normalize_mac


def scan_arp_table() -> list[Asset]:
    """Parse system ARP table (arp -a)."""
    assets: list[Asset] = []
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return assets

        # Pattern: hostname (ip) at mac on interface
        # Also handles: ? (ip) at mac on interface
        pattern = re.compile(
            r"[\w\.\-\?]+"       # hostname or ?
            r"\s+\((\d+\.\d+\.\d+\.\d+)\)"  # (ip)
            r"\s+at\s+([0-9a-fA-F:]+)"       # at mac
        )

        for line in result.stdout.splitlines():
            match = pattern.search(line)
            if not match:
                continue

            ip_addr = match.group(1)
            mac_addr = normalize_mac(match.group(2))

            if mac_addr in (None, "(incomplete)", "ff:ff:ff:ff:ff:ff"):
                continue

            # Try to extract hostname
            hostname = None
            hostname_match = re.match(r"^([\w\.\-]+)\s+\(", line)
            if hostname_match and hostname_match.group(1) != "?":
                hostname = hostname_match.group(1)

            assets.append(Asset(
                ip=ip_addr,
                mac=mac_addr,
                hostname=hostname,
                scan_method=ScanMethod.PASSIVE,
                raw_evidence={"source": "arp_table"},
            ))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return assets


def scan_proc_net_arp() -> list[Asset]:
    """Read /proc/net/arp on Linux systems."""
    assets: list[Asset] = []
    arp_path = Path("/proc/net/arp")

    if not arp_path.exists():
        return assets

    try:
        content = arp_path.read_text()
        for line in content.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) < 4:
                continue

            ip_addr = parts[0]
            mac_addr = normalize_mac(parts[3])

            if mac_addr in (None, "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                continue

            assets.append(Asset(
                ip=ip_addr,
                mac=mac_addr,
                scan_method=ScanMethod.PASSIVE,
                raw_evidence={"source": "proc_net_arp"},
            ))
    except OSError:
        pass

    return assets


def resolve_hostname(ip: str, timeout: float = 2.0) -> str | None:
    """Reverse DNS lookup for an IP address."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def scan_netbios(ip: str, timeout: float = 2.0) -> str | None:
    """Try NetBIOS name query on a single IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # NetBIOS name query packet
        query = (
            b"\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
            b"\x00\x21\x00\x01"
        )

        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()

        if len(data) > 57:
            name = data[57:57 + 15].decode("ascii", errors="ignore").strip()
            if name:
                return name
    except (socket.timeout, OSError):
        pass

    return None


def run_passive_scan(target_ips: list[str] | None = None) -> list[Asset]:
    """Run all passive scan methods and merge results.

    Args:
        target_ips: Optional list of IPs to filter results.
                    If None, returns all discovered assets.
    """
    seen: dict[str, Asset] = {}  # key: MAC or IP

    # Source 1: ARP table
    for asset in scan_arp_table():
        key = asset.mac or asset.ip
        seen[key] = asset

    # Source 2: /proc/net/arp (Linux only)
    if platform.system() == "Linux":
        for asset in scan_proc_net_arp():
            key = asset.mac or asset.ip
            if key not in seen:
                seen[key] = asset

    # Enrich: reverse DNS for assets without hostname
    for asset in seen.values():
        if asset.hostname is None:
            asset.hostname = resolve_hostname(asset.ip)

    # Filter by target IPs if provided
    assets = list(seen.values())
    if target_ips:
        target_set = set(target_ips)
        assets = [a for a in assets if a.ip in target_set]

    return assets
