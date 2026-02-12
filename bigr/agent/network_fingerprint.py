"""Network fingerprint detection for roaming agent support.

Detects the current network identity by fingerprinting the default gateway
(MAC + SSID). This allows the agent to tag scan results so assets from
different physical networks (even with the same CIDR) stay separated.

Cross-platform: macOS and Linux supported via subprocess calls.
No additional Python dependencies required.
"""

from __future__ import annotations

import hashlib
import logging
import platform
import re
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_SYSTEM = platform.system()  # "Darwin" or "Linux"


@dataclass
class NetworkFingerprint:
    """Identifies the current network the agent is connected to."""

    fingerprint_hash: str  # SHA-256 of "gateway_mac:ssid"
    gateway_ip: str | None
    gateway_mac: str | None
    ssid: str | None

    def to_dict(self) -> dict:
        return {
            "fingerprint_hash": self.fingerprint_hash,
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "ssid": self.ssid,
        }


def _run_cmd(args: list[str], timeout: int = 5) -> str | None:
    """Run a subprocess and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("Command %s failed: %s", args, exc)
        return None


def detect_default_gateway_ip() -> str | None:
    """Detect the default gateway IP address."""
    if _SYSTEM == "Darwin":
        # macOS: netstat -rn → look for "default" line
        output = _run_cmd(["netstat", "-rn"])
        if not output:
            return None
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "default":
                gw = parts[1]
                # Skip link-local or non-IP entries
                if re.match(r"\d+\.\d+\.\d+\.\d+", gw):
                    return gw
        return None

    # Linux: ip route → "default via X.X.X.X"
    output = _run_cmd(["ip", "route"])
    if not output:
        return None
    match = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", output)
    return match.group(1) if match else None


def detect_gateway_mac(gateway_ip: str) -> str | None:
    """Resolve the gateway IP to its MAC address via ARP table."""
    output = _run_cmd(["arp", "-n", gateway_ip])
    if not output:
        return None
    # Both macOS and Linux: look for a MAC pattern in the arp output
    # macOS format: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ..."
    # Linux format: "192.168.1.1  ether  aa:bb:cc:dd:ee:ff  C  eth0"
    mac_pattern = re.compile(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})")
    match = mac_pattern.search(output)
    if match:
        # Normalize MAC to lowercase with zero-padded octets
        raw = match.group(1)
        octets = raw.split(":")
        return ":".join(o.lower().zfill(2) for o in octets)
    return None


def detect_ssid() -> str | None:
    """Detect the current WiFi SSID, or None if wired/unavailable."""
    if _SYSTEM == "Darwin":
        # macOS: networksetup -getairportnetwork en0
        # Output: "Current Wi-Fi Network: MyNetwork"
        output = _run_cmd(["networksetup", "-getairportnetwork", "en0"])
        if not output:
            return None
        # "You are not associated with an AirPort network." means no WiFi
        if "not associated" in output.lower():
            return None
        match = re.search(r":\s*(.+)$", output)
        return match.group(1).strip() if match else None

    # Linux: iwgetid -r
    output = _run_cmd(["iwgetid", "-r"])
    return output if output else None


def compute_fingerprint_hash(gateway_mac: str | None, ssid: str | None) -> str:
    """Compute SHA-256 hash from gateway MAC and SSID."""
    mac_part = (gateway_mac or "").lower()
    ssid_part = ssid or ""
    raw = f"{mac_part}:{ssid_part}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def detect_local_subnet() -> str | None:
    """Detect the local subnet CIDR for the default interface.

    Returns e.g. "192.168.1.0/24" or "172.20.10.0/28".
    Works on macOS and Linux.
    """
    if _SYSTEM == "Darwin":
        # Get the default interface from route
        output = _run_cmd(["route", "-n", "get", "default"])
        if not output:
            return None
        iface = None
        for line in output.splitlines():
            if "interface:" in line:
                iface = line.split(":")[-1].strip()
                break
        if not iface:
            return None
        # Get IP and netmask from ifconfig
        ifconfig = _run_cmd(["ifconfig", iface])
        if not ifconfig:
            return None
        ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+)", ifconfig)
        if not ip_match:
            return None
        ip_addr = ip_match.group(1)
        netmask_hex = ip_match.group(2)
        # Convert hex netmask to prefix length
        mask_int = int(netmask_hex, 16)
        prefix_len = bin(mask_int).count("1")
        # Compute network address
        import ipaddress
        network = ipaddress.ip_network(f"{ip_addr}/{prefix_len}", strict=False)
        cidr = str(network)
        logger.info("Detected local subnet: %s (interface: %s)", cidr, iface)
        return cidr

    # Linux: ip -o -f inet addr show → find interface matching default route
    gateway_ip = detect_default_gateway_ip()
    if not gateway_ip:
        return None
    output = _run_cmd(["ip", "-o", "-f", "inet", "addr", "show"])
    if not output:
        return None
    import ipaddress
    for line in output.splitlines():
        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
        if match:
            try:
                net = ipaddress.ip_network(match.group(1), strict=False)
                if ipaddress.ip_address(gateway_ip) in net:
                    logger.info("Detected local subnet: %s", str(net))
                    return str(net)
            except ValueError:
                continue
    return None


def detect_network_fingerprint() -> NetworkFingerprint | None:
    """Detect current network fingerprint. Returns None if gateway cannot be found.

    The fingerprint is based on the default gateway's MAC address and the
    current WiFi SSID. This uniquely identifies a physical network even when
    multiple networks use the same CIDR range.
    """
    gateway_ip = detect_default_gateway_ip()
    if not gateway_ip:
        logger.info("No default gateway detected — skipping network fingerprint")
        return None

    gateway_mac = detect_gateway_mac(gateway_ip)
    if not gateway_mac:
        logger.warning(
            "Could not resolve gateway MAC for %s — skipping network fingerprint",
            gateway_ip,
        )
        return None

    ssid = detect_ssid()

    fingerprint_hash = compute_fingerprint_hash(gateway_mac, ssid)

    logger.info(
        "Network fingerprint: hash=%s gw=%s mac=%s ssid=%s",
        fingerprint_hash[:12],
        gateway_ip,
        gateway_mac,
        ssid or "(wired)",
    )

    return NetworkFingerprint(
        fingerprint_hash=fingerprint_hash,
        gateway_ip=gateway_ip,
        gateway_mac=gateway_mac,
        ssid=ssid,
    )
