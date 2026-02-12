"""SQLAlchemy ORM models for Guardian DNS filtering."""

from __future__ import annotations

from sqlalchemy import Integer, String, Text, UniqueConstraint, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column

from bigr.core.database import Base


class GuardianBlocklistDB(Base):
    """Blocklist source metadata (e.g. StevenBlack, OISD)."""

    __tablename__ = "guardian_blocklists"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    url: Mapped[str] = mapped_column(String, nullable=False)
    format: Mapped[str] = mapped_column(
        String, nullable=False, default="hosts"
    )  # "hosts" or "domains"
    category: Mapped[str] = mapped_column(String, nullable=False, default="malware")
    domain_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_enabled: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_updated: Mapped[str | None] = mapped_column(String, nullable=True)
    etag: Mapped[str | None] = mapped_column(String, nullable=True)


class GuardianBlockedDomainDB(Base):
    """Individual blocked domain from a blocklist."""

    __tablename__ = "guardian_blocked_domains"

    domain: Mapped[str] = mapped_column(String, primary_key=True)
    blocklist_id: Mapped[str] = mapped_column(
        String, ForeignKey("guardian_blocklists.id"), nullable=False
    )
    category: Mapped[str] = mapped_column(String, nullable=False, default="malware")

    __table_args__ = (
        Index("ix_guardian_blocked_domains_domain", "domain"),
    )


class GuardianCustomRuleDB(Base):
    """User-defined allow/block rule."""

    __tablename__ = "guardian_custom_rules"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    action: Mapped[str] = mapped_column(
        String, nullable=False
    )  # "block" or "allow"
    domain: Mapped[str] = mapped_column(String, nullable=False, index=True)
    category: Mapped[str] = mapped_column(String, nullable=False, default="custom")
    reason: Mapped[str] = mapped_column(String, nullable=False, default="")
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_active: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[str] = mapped_column(String, nullable=False)


class GuardianQueryStatsDB(Base):
    """Hourly aggregated query statistics."""

    __tablename__ = "guardian_query_stats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    date: Mapped[str] = mapped_column(String, nullable=False)
    hour: Mapped[int] = mapped_column(Integer, nullable=False)
    total_queries: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    blocked_queries: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    allowed_queries: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cache_hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint("date", "hour", name="uq_guardian_stats_date_hour"),
    )


class GuardianTopDomainDB(Base):
    """Most frequently blocked domains (rolling window)."""

    __tablename__ = "guardian_top_domains"

    domain: Mapped[str] = mapped_column(String, primary_key=True)
    block_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    category: Mapped[str] = mapped_column(String, nullable=False, default="")
    last_blocked: Mapped[str | None] = mapped_column(String, nullable=True)
