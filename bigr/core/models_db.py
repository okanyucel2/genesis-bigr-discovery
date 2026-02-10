"""SQLAlchemy ORM models mirroring the bigr/db.py schema."""

from __future__ import annotations

from sqlalchemy import (
    Float,
    Integer,
    String,
    Text,
    UniqueConstraint,
    ForeignKey,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from bigr.core.database import Base


class NetworkDB(Base):
    """Known network identity (fingerprinted by gateway MAC + SSID)."""

    __tablename__ = "networks"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    fingerprint_hash: Mapped[str] = mapped_column(
        String, nullable=False, unique=True
    )
    gateway_mac: Mapped[str | None] = mapped_column(String, nullable=True)
    gateway_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    ssid: Mapped[str | None] = mapped_column(String, nullable=True)
    friendly_name: Mapped[str | None] = mapped_column(String, nullable=True)
    agent_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("agents.id"), nullable=True
    )
    first_seen: Mapped[str] = mapped_column(String, nullable=False)
    last_seen: Mapped[str] = mapped_column(String, nullable=False)
    asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class AgentDB(Base):
    """Remote agent registration."""

    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    site_name: Mapped[str] = mapped_column(String, nullable=False, default="")
    location: Mapped[str | None] = mapped_column(String, nullable=True)
    token_hash: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    registered_at: Mapped[str] = mapped_column(String, nullable=False)
    last_seen: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="offline")
    version: Mapped[str | None] = mapped_column(String, nullable=True)
    subnets: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array


class ScanDB(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    target: Mapped[str] = mapped_column(String, nullable=False)
    scan_method: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[str] = mapped_column(String, nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String, nullable=True)
    total_assets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_root: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    agent_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("agents.id"), nullable=True
    )
    site_name: Mapped[str | None] = mapped_column(String, nullable=True)
    network_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("networks.id"), nullable=True
    )

    scan_assets: Mapped[list[ScanAssetDB]] = relationship(
        "ScanAssetDB", back_populates="scan", cascade="all, delete-orphan"
    )


class AssetDB(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("ip", "mac", name="uq_asset_ip_mac"),)

    id: Mapped[str] = mapped_column(String, primary_key=True)
    ip: Mapped[str] = mapped_column(String, nullable=False)
    mac: Mapped[str | None] = mapped_column(String, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String, nullable=True)
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    os_hint: Mapped[str | None] = mapped_column(String, nullable=True)
    bigr_category: Mapped[str] = mapped_column(
        String, nullable=False, default="unclassified"
    )
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    scan_method: Mapped[str] = mapped_column(
        String, nullable=False, default="passive"
    )
    first_seen: Mapped[str] = mapped_column(String, nullable=False)
    last_seen: Mapped[str] = mapped_column(String, nullable=False)
    manual_category: Mapped[str | None] = mapped_column(String, nullable=True)
    manual_note: Mapped[str | None] = mapped_column(String, nullable=True)
    is_ignored: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    switch_host: Mapped[str | None] = mapped_column(String, nullable=True)
    switch_port: Mapped[str | None] = mapped_column(String, nullable=True)
    switch_port_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    agent_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("agents.id"), nullable=True
    )
    site_name: Mapped[str | None] = mapped_column(String, nullable=True)
    network_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("networks.id"), nullable=True
    )

    scan_assets: Mapped[list[ScanAssetDB]] = relationship(
        "ScanAssetDB", back_populates="asset", cascade="all, delete-orphan"
    )
    asset_changes: Mapped[list[AssetChangeDB]] = relationship(
        "AssetChangeDB", back_populates="asset", cascade="all, delete-orphan"
    )


class ScanAssetDB(Base):
    __tablename__ = "scan_assets"

    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id"), primary_key=True
    )
    asset_id: Mapped[str] = mapped_column(
        String, ForeignKey("assets.id"), primary_key=True
    )
    open_ports: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    bigr_category: Mapped[str] = mapped_column(
        String, nullable=False, default="unclassified"
    )
    raw_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[ScanDB] = relationship("ScanDB", back_populates="scan_assets")
    asset: Mapped[AssetDB] = relationship("AssetDB", back_populates="scan_assets")


class AssetChangeDB(Base):
    __tablename__ = "asset_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(
        String, ForeignKey("assets.id"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id"), nullable=False
    )
    change_type: Mapped[str] = mapped_column(String, nullable=False)
    field_name: Mapped[str | None] = mapped_column(String, nullable=True)
    old_value: Mapped[str | None] = mapped_column(String, nullable=True)
    new_value: Mapped[str | None] = mapped_column(String, nullable=True)
    detected_at: Mapped[str] = mapped_column(String, nullable=False)

    asset: Mapped[AssetDB] = relationship("AssetDB", back_populates="asset_changes")


class SubnetDB(Base):
    __tablename__ = "subnets"

    cidr: Mapped[str] = mapped_column(String, primary_key=True)
    label: Mapped[str] = mapped_column(String, default="")
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_scanned: Mapped[str | None] = mapped_column(String, nullable=True)
    asset_count: Mapped[int] = mapped_column(Integer, default=0)


class SwitchDB(Base):
    __tablename__ = "switches"

    host: Mapped[str] = mapped_column(String, primary_key=True)
    community: Mapped[str] = mapped_column(String, default="public")
    version: Mapped[str] = mapped_column(String, default="2c")
    label: Mapped[str] = mapped_column(String, default="")
    last_polled: Mapped[str | None] = mapped_column(String, nullable=True)
    mac_count: Mapped[int] = mapped_column(Integer, default=0)


class CertificateDB(Base):
    __tablename__ = "certificates"
    __table_args__ = (UniqueConstraint("ip", "port", name="uq_cert_ip_port"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String, nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    cn: Mapped[str | None] = mapped_column(String, nullable=True)
    issuer: Mapped[str | None] = mapped_column(String, nullable=True)
    issuer_org: Mapped[str | None] = mapped_column(String, nullable=True)
    valid_from: Mapped[str | None] = mapped_column(String, nullable=True)
    valid_to: Mapped[str | None] = mapped_column(String, nullable=True)
    serial: Mapped[str | None] = mapped_column(String, nullable=True)
    key_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    key_algorithm: Mapped[str | None] = mapped_column(String, nullable=True)
    is_self_signed: Mapped[int] = mapped_column(Integer, default=0)
    is_expired: Mapped[int] = mapped_column(Integer, default=0)
    days_until_expiry: Mapped[int | None] = mapped_column(Integer, nullable=True)
    san: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_checked: Mapped[str] = mapped_column(String, nullable=False)


class ShieldScanDB(Base):
    """Shield security scan from a remote agent."""

    __tablename__ = "shield_scans"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    agent_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("agents.id"), nullable=True
    )
    site_name: Mapped[str | None] = mapped_column(String, nullable=True)
    target: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[str] = mapped_column(String, nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String, nullable=True)
    modules_run: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array

    findings: Mapped[list[ShieldFindingDB]] = relationship(
        "ShieldFindingDB", back_populates="scan", cascade="all, delete-orphan"
    )


class ShieldFindingDB(Base):
    """Individual finding from a shield scan."""

    __tablename__ = "shield_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("shield_scans.id"), nullable=False
    )
    module: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False, default="info")
    title: Mapped[str | None] = mapped_column(String, nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_data: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON

    scan: Mapped[ShieldScanDB] = relationship("ShieldScanDB", back_populates="findings")


class SubscriptionDB(Base):
    """User subscription for plan-gated features (pricing tiers)."""

    __tablename__ = "subscriptions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    device_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    plan_id: Mapped[str] = mapped_column(String, nullable=False, default="free")
    activated_at: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[str | None] = mapped_column(String, nullable=True)
    is_active: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    stripe_customer_id: Mapped[str | None] = mapped_column(
        String, nullable=True
    )  # Future Stripe integration


class AgentCommandDB(Base):
    """Remote command queued for an agent (e.g. 'scan_now')."""

    __tablename__ = "agent_commands"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    agent_id: Mapped[str] = mapped_column(
        String, ForeignKey("agents.id"), nullable=False
    )
    command_type: Mapped[str] = mapped_column(String, nullable=False)  # scan_now, etc.
    params: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    status: Mapped[str] = mapped_column(
        String, nullable=False, default="pending"
    )  # pending/ack/running/completed/failed
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[str | None] = mapped_column(String, nullable=True)
    completed_at: Mapped[str | None] = mapped_column(String, nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON


class FamilyDeviceDB(Base):
    """Device registered under a Family Shield subscription."""

    __tablename__ = "family_devices"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    subscription_id: Mapped[str] = mapped_column(
        String, ForeignKey("subscriptions.id"), nullable=False
    )
    agent_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("agents.id"), nullable=True
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    device_type: Mapped[str] = mapped_column(String, nullable=False, default="other")
    owner_name: Mapped[str | None] = mapped_column(String, nullable=True)
    added_at: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CollectiveSignalDB(Base):
    """Anonymized threat signal from the collective network."""

    __tablename__ = "collective_signals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    subnet_hash: Mapped[str] = mapped_column(String, nullable=False, index=True)
    signal_type: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[float] = mapped_column(Float, nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    agent_hash: Mapped[str] = mapped_column(String, nullable=False)
    reported_at: Mapped[str] = mapped_column(String, nullable=False)
    is_noised: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class RemediationActionDB(Base):
    """Tracked remediation action (executed or pending)."""

    __tablename__ = "remediation_actions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    asset_ip: Mapped[str] = mapped_column(String, nullable=False)
    action_type: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False, default="medium")
    status: Mapped[str] = mapped_column(
        String, nullable=False, default="pending"
    )  # pending/executing/completed/failed
    executed_at: Mapped[str | None] = mapped_column(String, nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)


class FirewallRuleDB(Base):
    """Firewall rule persisted in the database."""

    __tablename__ = "firewall_rules"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    rule_type: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str] = mapped_column(String, nullable=False)
    direction: Mapped[str] = mapped_column(String, nullable=False, default="both")
    protocol: Mapped[str] = mapped_column(String, nullable=False, default="any")
    source: Mapped[str] = mapped_column(String, nullable=False, default="user")
    reason: Mapped[str] = mapped_column(String, nullable=False, default="")
    reason_tr: Mapped[str] = mapped_column(String, nullable=False, default="")
    is_active: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[str | None] = mapped_column(String, nullable=True)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class FirewallEventDB(Base):
    """Logged firewall event (block or allow)."""

    __tablename__ = "firewall_events"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[str] = mapped_column(String, nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String, nullable=True)
    source_ip: Mapped[str] = mapped_column(String, nullable=False)
    dest_ip: Mapped[str] = mapped_column(String, nullable=False)
    dest_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String, nullable=False, default="tcp")
    process_name: Mapped[str | None] = mapped_column(String, nullable=True)
    direction: Mapped[str] = mapped_column(String, nullable=False, default="outbound")
