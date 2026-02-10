"""SQLAlchemy ORM models for threat intelligence."""

from __future__ import annotations

from sqlalchemy import Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from bigr.core.database import Base


class ThreatFeedDB(Base):
    """Registered threat intelligence feeds."""

    __tablename__ = "threat_feeds"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    feed_url: Mapped[str] = mapped_column(String, nullable=False)
    feed_type: Mapped[str] = mapped_column(
        String, nullable=False
    )  # "ip_list", "json_api", "csv"
    enabled: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_synced_at: Mapped[str | None] = mapped_column(String, nullable=True)
    entries_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class ThreatIndicatorDB(Base):
    """Aggregated threat indicators at /24 subnet level."""

    __tablename__ = "threat_indicators"
    __table_args__ = (
        Index("ix_threat_indicators_subnet_hash", "subnet_hash"),
        Index("ix_threat_indicators_expires_at", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    subnet_hash: Mapped[str] = mapped_column(String, nullable=False)
    subnet_prefix: Mapped[str | None] = mapped_column(
        String, nullable=True
    )  # Only stored for private ranges
    threat_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    source_feeds: Mapped[str] = mapped_column(
        Text, nullable=False, default="[]"
    )  # JSON array of feed names
    indicator_types: Mapped[str] = mapped_column(
        Text, nullable=False, default="[]"
    )  # JSON array: "malware_c2", "scanner", etc.
    cve_refs: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON array of CVE IDs
    first_seen: Mapped[str] = mapped_column(String, nullable=False)
    last_seen: Mapped[str] = mapped_column(String, nullable=False)
    report_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    expires_at: Mapped[str] = mapped_column(
        String, nullable=False
    )  # 90-day auto-expiry (GDPR/KVKK)
