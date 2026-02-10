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


class ScanDB(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    target: Mapped[str] = mapped_column(String, nullable=False)
    scan_method: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[str] = mapped_column(String, nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String, nullable=True)
    total_assets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_root: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

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
