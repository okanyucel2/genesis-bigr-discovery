"""Pydantic models for the firewall module."""

from __future__ import annotations

from pydantic import BaseModel


class FirewallRule(BaseModel):
    """A single firewall rule."""

    id: str
    rule_type: str  # "block_ip", "block_port", "block_domain", "allow_ip", "allow_domain"
    target: str  # IP, port number, or domain
    direction: str = "both"  # "inbound", "outbound", "both"
    protocol: str = "any"  # "tcp", "udp", "any"
    source: str = "user"  # "threat_intel", "remediation", "user", "collective"
    reason: str = ""  # Human-readable reason
    reason_tr: str = ""  # Turkish reason
    is_active: bool = True
    created_at: str = ""
    expires_at: str | None = None  # Auto-expiry for threat-based rules
    hit_count: int = 0  # How many times this rule matched


class FirewallEvent(BaseModel):
    """A logged firewall event (block/allow)."""

    id: str
    timestamp: str
    action: str  # "blocked", "allowed"
    rule_id: str | None = None
    source_ip: str
    dest_ip: str
    dest_port: int
    protocol: str = "tcp"
    process_name: str | None = None  # Which app triggered the connection
    direction: str = "outbound"


class FirewallStatus(BaseModel):
    """Current firewall status."""

    is_enabled: bool
    platform: str  # "macos", "windows", "linux"
    engine: str  # "ne_filter", "wfp", "nftables", "stub"
    total_rules: int
    active_rules: int
    blocked_today: int
    allowed_today: int
    last_updated: str
    protection_level: str  # "full", "partial", "disabled"


class FirewallConfig(BaseModel):
    """Firewall configuration."""

    enabled: bool = True
    default_action: str = "allow"  # "allow" or "block" (default allow, block by rule)
    block_known_threats: bool = True
    block_high_risk_ports: bool = True
    log_allowed: bool = False  # Log allowed connections too (verbose)
    auto_sync_threats: bool = True  # Auto-import threat intel rules
    protection_level: str = "balanced"  # "minimal", "balanced", "strict"
