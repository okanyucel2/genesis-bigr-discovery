"""Advanced device fingerprinting v2 - multi-signal approach."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TcpFingerprint:
    """TCP/IP stack fingerprint from SYN response."""
    ttl: int | None = None
    window_size: int | None = None
    df_bit: bool | None = None  # Don't Fragment
    tcp_options: list[str] = field(default_factory=list)
    os_guess: str | None = None


@dataclass
class HttpFingerprint:
    """HTTP fingerprint from User-Agent and headers."""
    user_agent: str | None = None
    server_header: str | None = None
    device_type: str | None = None  # "mobile", "desktop", "server", "iot"
    os_name: str | None = None
    os_version: str | None = None
    browser: str | None = None


@dataclass
class TlsFingerprint:
    """TLS certificate fingerprint."""
    cn: str | None = None  # Common Name
    san: list[str] = field(default_factory=list)  # Subject Alt Names
    issuer: str | None = None
    is_self_signed: bool = False
    expiry_days: int | None = None
    device_hint: str | None = None  # Extracted device type from cert


@dataclass
class DhcpFingerprint:
    """DHCP option fingerprint."""
    option55: list[int] = field(default_factory=list)  # Parameter Request List
    option60: str | None = None  # Vendor Class Identifier
    hostname: str | None = None
    os_guess: str | None = None


@dataclass
class DeviceFingerprint:
    """Combined fingerprint from all sources."""
    tcp: TcpFingerprint | None = None
    http: HttpFingerprint | None = None
    tls: TlsFingerprint | None = None
    dhcp: DhcpFingerprint | None = None
    combined_os: str | None = None
    combined_device_type: str | None = None
    confidence: float = 0.0
