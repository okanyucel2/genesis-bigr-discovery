"""OS and device fingerprinting based on open ports and banners."""

from __future__ import annotations

import re
import socket


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """Attempt to grab service banner from an open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Send basic probe for HTTP
        if port in (80, 8080, 8443, 443):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner if banner else None
    except (socket.timeout, OSError, ConnectionRefusedError):
        return None


def detect_os_from_ports(open_ports: list[int]) -> str | None:
    """Heuristic OS detection based on open port combinations."""
    port_set = set(open_ports)

    # Windows indicators
    if {3389, 445}.issubset(port_set):
        return "Windows"
    if 3389 in port_set:
        return "Windows"
    if 445 in port_set and 22 not in port_set:
        return "Windows"

    # Linux/Unix indicators
    if 22 in port_set and 3389 not in port_set:
        if len(port_set) >= 3:
            return "Linux (Server)"
        return "Linux"

    # Network equipment indicators
    if {22, 161}.issubset(port_set) and 80 not in port_set:
        return "Network Equipment"
    if 161 in port_set and len(port_set) <= 2:
        return "Network Equipment"

    # IoT indicators
    if 554 in port_set:  # RTSP
        return "IP Camera"
    if 1883 in port_set:  # MQTT
        return "IoT Device"
    if 9100 in port_set:  # JetDirect
        return "Printer"

    # Web server only
    if port_set.issubset({80, 443, 8080, 8443}):
        return "Web Server"

    return None


def detect_os_from_banner(banner: str | None) -> str | None:
    """Extract OS info from service banner."""
    if not banner:
        return None

    banner_lower = banner.lower()

    patterns = [
        (r"microsoft|windows|iis", "Windows"),
        (r"ubuntu|debian|centos|fedora|red\s?hat", "Linux"),
        (r"apache|nginx|lighttpd", "Linux (Web Server)"),
        (r"openssh", "Linux"),
        (r"mikrotik|routeros", "Network Equipment (MikroTik)"),
        (r"cisco|ios", "Network Equipment (Cisco)"),
        (r"hikvision|dahua", "IP Camera"),
        (r"printer|jetdirect|cups", "Printer"),
    ]

    for pattern, os_hint in patterns:
        if re.search(pattern, banner_lower):
            return os_hint

    return None


def fingerprint_asset(ip: str, open_ports: list[int], timeout: float = 2.0) -> str | None:
    """Combined OS fingerprinting from ports and banners."""
    # First try port-based detection (fast)
    os_hint = detect_os_from_ports(open_ports)

    # Try banner grabbing for more specific detection
    banner_ports = [p for p in [22, 80, 8080] if p in open_ports]
    for port in banner_ports[:2]:  # limit to 2 banner grabs
        banner = grab_banner(ip, port, timeout=timeout)
        banner_os = detect_os_from_banner(banner)
        if banner_os:
            return banner_os  # Banner is more specific

    return os_hint
