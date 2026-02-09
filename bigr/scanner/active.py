"""Active network scanner - requires root for ARP sweep."""

from __future__ import annotations

import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from bigr.models import Asset, ScanMethod, normalize_mac

# Default critical ports for BİGR classification
DEFAULT_PORTS = [
    22,    # SSH
    80,    # HTTP
    443,   # HTTPS
    3389,  # RDP
    8080,  # HTTP Alt
    3306,  # MySQL
    5432,  # PostgreSQL
    21,    # FTP
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    161,   # SNMP
    445,   # SMB
    9100,  # Printer (JetDirect)
    554,   # RTSP (cameras)
    1883,  # MQTT (IoT)
    8443,  # HTTPS Alt
    5000,  # Various services
    # Home / IoT extended ports
    548,   # AFP (Apple File Sharing)
    631,   # CUPS / IPP (printers)
    1900,  # UPnP / SSDP
    5353,  # mDNS / AirPlay
    8008,  # Chromecast HTTP
    62078, # Apple iDevice (lockdownd)
    8888,  # Common IoT web UI
    49152, # UPnP dynamic
]


def is_root() -> bool:
    """Check if running with root privileges."""
    return os.geteuid() == 0


def tcp_connect_scan(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Test if a TCP port is open using connect()."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except (socket.timeout, OSError):
        return False


def scan_ports(ip: str, ports: list[int] | None = None, timeout: float = 2.0, max_workers: int = 20) -> list[int]:
    """Scan multiple ports on a single IP concurrently."""
    if ports is None:
        ports = DEFAULT_PORTS

    open_ports: list[int] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(tcp_connect_scan, ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass

    return sorted(open_ports)


def arp_sweep(target: str) -> list[Asset]:
    """ARP sweep using scapy - requires root.

    Args:
        target: CIDR notation (e.g., "192.168.1.0/24")
    """
    if not is_root():
        return []

    try:
        from scapy.all import ARP, Ether, srp  # type: ignore[import-untyped]
    except ImportError:
        return []

    assets: list[Asset] = []

    try:
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
        answered, _ = srp(arp_request, timeout=3, verbose=False)

        for _, received in answered:
            ip_addr = received.psrc
            mac_addr = normalize_mac(received.hwsrc)

            assets.append(Asset(
                ip=ip_addr,
                mac=mac_addr,
                scan_method=ScanMethod.ACTIVE,
                raw_evidence={"source": "arp_sweep"},
            ))
    except Exception:
        pass

    return assets


def run_active_scan(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 2.0,
) -> list[Asset]:
    """Run active scan: ARP sweep + port scan on discovered hosts.

    Args:
        target: CIDR notation (e.g., "192.168.1.0/24")
        ports: Ports to scan. Defaults to DEFAULT_PORTS.
        timeout: Per-port timeout in seconds.
    """
    assets = arp_sweep(target)

    # Port scan each discovered host
    for asset in assets:
        asset.open_ports = scan_ports(asset.ip, ports=ports, timeout=timeout)

    return assets
