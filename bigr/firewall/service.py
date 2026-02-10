"""Firewall service — manages rules, events, and synchronization."""

from __future__ import annotations

import logging
import platform
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.firewall.adapters.base import FirewallAdapter
from bigr.firewall.adapters.macos import MacOSFirewallAdapter
from bigr.firewall.models import (
    FirewallConfig,
    FirewallEvent,
    FirewallRule,
    FirewallStatus,
)
from bigr.firewall.rule_engine import FirewallRuleEngine

logger = logging.getLogger(__name__)

# High-risk ports to auto-block (from remediation engine)
_HIGH_RISK_PORTS: dict[int, str] = {
    21: "FTP - duz metin kimlik bilgisi",
    23: "Telnet - sifrelenmemis protokol",
    445: "SMB - fidye yazilimi vektoru",
    3389: "RDP - kaba kuvvet hedefi",
    5900: "VNC - sifrelenmemis uzak masaustu",
    135: "MSRPC - yatay hareket riski",
    139: "NetBIOS - fidye yazilimi vektoru",
}


class FirewallService:
    """Manages firewall rules, events, and synchronization."""

    def __init__(self) -> None:
        self._config = FirewallConfig()
        self._engine = FirewallRuleEngine()
        self._adapter: FirewallAdapter | None = None

        # Auto-select adapter based on platform
        if platform.system() == "Darwin":
            self._adapter = MacOSFirewallAdapter()

    async def get_status(self, db: AsyncSession) -> FirewallStatus:
        """Get current firewall status."""
        from bigr.core.models_db import FirewallEventDB, FirewallRuleDB

        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

        # Count rules
        total_q = await db.execute(
            select(func.count(FirewallRuleDB.id))
        )
        total_rules = total_q.scalar() or 0

        active_q = await db.execute(
            select(func.count(FirewallRuleDB.id)).where(FirewallRuleDB.is_active == 1)
        )
        active_rules = active_q.scalar() or 0

        # Count today's events
        blocked_q = await db.execute(
            select(func.count(FirewallEventDB.id)).where(
                FirewallEventDB.action == "blocked",
                FirewallEventDB.timestamp >= today_start,
            )
        )
        blocked_today = blocked_q.scalar() or 0

        allowed_q = await db.execute(
            select(func.count(FirewallEventDB.id)).where(
                FirewallEventDB.action == "allowed",
                FirewallEventDB.timestamp >= today_start,
            )
        )
        allowed_today = allowed_q.scalar() or 0

        # Determine protection level
        if not self._config.enabled:
            protection = "disabled"
        elif active_rules >= 5:
            protection = "full"
        else:
            protection = "partial"

        adapter_engine = "stub"
        adapter_platform = platform.system().lower()
        if adapter_platform == "darwin":
            adapter_platform = "macos"
            adapter_engine = "ne_filter"

        return FirewallStatus(
            is_enabled=self._config.enabled,
            platform=adapter_platform,
            engine=adapter_engine,
            total_rules=total_rules,
            active_rules=active_rules,
            blocked_today=blocked_today,
            allowed_today=allowed_today,
            last_updated=now.isoformat(),
            protection_level=protection,
        )

    async def get_rules(
        self,
        db: AsyncSession,
        rule_type: str | None = None,
        active_only: bool = True,
    ) -> list[FirewallRule]:
        """Get firewall rules, optionally filtered."""
        from bigr.core.models_db import FirewallRuleDB

        stmt = select(FirewallRuleDB)
        if active_only:
            stmt = stmt.where(FirewallRuleDB.is_active == 1)
        if rule_type:
            stmt = stmt.where(FirewallRuleDB.rule_type == rule_type)
        stmt = stmt.order_by(FirewallRuleDB.created_at.desc())

        result = await db.execute(stmt)
        rows = result.scalars().all()

        return [
            FirewallRule(
                id=r.id,
                rule_type=r.rule_type,
                target=r.target,
                direction=r.direction,
                protocol=r.protocol,
                source=r.source,
                reason=r.reason,
                reason_tr=r.reason_tr,
                is_active=bool(r.is_active),
                created_at=r.created_at,
                expires_at=r.expires_at,
                hit_count=r.hit_count,
            )
            for r in rows
        ]

    async def add_rule(self, rule: FirewallRule, db: AsyncSession) -> FirewallRule:
        """Add a new firewall rule."""
        from bigr.core.models_db import FirewallRuleDB

        now_iso = datetime.now(timezone.utc).isoformat()
        rule_id = rule.id or str(uuid.uuid4())

        db_rule = FirewallRuleDB(
            id=rule_id,
            rule_type=rule.rule_type,
            target=rule.target,
            direction=rule.direction,
            protocol=rule.protocol,
            source=rule.source,
            reason=rule.reason,
            reason_tr=rule.reason_tr,
            is_active=1 if rule.is_active else 0,
            created_at=now_iso,
            expires_at=rule.expires_at,
            hit_count=0,
        )
        db.add(db_rule)
        await db.commit()

        rule.id = rule_id
        rule.created_at = now_iso
        return rule

    async def remove_rule(self, rule_id: str, db: AsyncSession) -> dict:
        """Remove (deactivate) a firewall rule."""
        from bigr.core.models_db import FirewallRuleDB

        stmt = select(FirewallRuleDB).where(FirewallRuleDB.id == rule_id)
        result = await db.execute(stmt)
        rule = result.scalar_one_or_none()

        if rule is None:
            return {"status": "error", "message": "Kural bulunamadi."}

        rule.is_active = 0
        await db.commit()

        return {"status": "ok", "message": "Kural devre disi birakildi.", "rule_id": rule_id}

    async def toggle_rule(self, rule_id: str, db: AsyncSession) -> FirewallRule | None:
        """Toggle a rule's active state."""
        from bigr.core.models_db import FirewallRuleDB

        stmt = select(FirewallRuleDB).where(FirewallRuleDB.id == rule_id)
        result = await db.execute(stmt)
        row = result.scalar_one_or_none()

        if row is None:
            return None

        row.is_active = 0 if row.is_active else 1
        await db.commit()

        return FirewallRule(
            id=row.id,
            rule_type=row.rule_type,
            target=row.target,
            direction=row.direction,
            protocol=row.protocol,
            source=row.source,
            reason=row.reason,
            reason_tr=row.reason_tr,
            is_active=bool(row.is_active),
            created_at=row.created_at,
            expires_at=row.expires_at,
            hit_count=row.hit_count,
        )

    async def sync_threat_rules(self, db: AsyncSession) -> dict:
        """Sync rules from threat intelligence.

        Creates block rules for all high-score threat indicators.
        """
        from bigr.threat.models import ThreatIndicatorDB

        expires_iso = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()

        stmt = select(ThreatIndicatorDB).where(ThreatIndicatorDB.threat_score >= 0.7)
        result = await db.execute(stmt)
        indicators = result.scalars().all()

        rules_created = 0
        for indicator in indicators:
            # Create block rule for each high-score subnet
            if indicator.subnet_prefix:
                rule = FirewallRule(
                    id=f"threat-{indicator.id}",
                    rule_type="block_ip",
                    target=indicator.subnet_prefix.split("/")[0],
                    direction="both",
                    protocol="any",
                    source="threat_intel",
                    reason=f"High threat score: {indicator.threat_score:.2f}",
                    reason_tr=f"Yuksek tehdit skoru: {indicator.threat_score:.2f}",
                    is_active=True,
                    expires_at=expires_iso,
                )
                await self.add_rule(rule, db)
                rules_created += 1

        return {
            "status": "ok",
            "rules_created": rules_created,
            "indicators_checked": len(indicators),
            "message": f"{rules_created} tehdit kurali olusturuldu.",
        }

    async def sync_port_rules(self, db: AsyncSession) -> dict:
        """Create block rules for high-risk ports from remediation engine."""
        from bigr.core.models_db import FirewallRuleDB

        now_iso = datetime.now(timezone.utc).isoformat()
        rules_created = 0

        for port, reason_tr in _HIGH_RISK_PORTS.items():
            # Check if rule already exists
            stmt = select(FirewallRuleDB).where(
                FirewallRuleDB.rule_type == "block_port",
                FirewallRuleDB.target == str(port),
                FirewallRuleDB.source == "remediation",
            )
            result = await db.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing is None:
                rule = FirewallRule(
                    id=str(uuid.uuid4()),
                    rule_type="block_port",
                    target=str(port),
                    direction="inbound",
                    protocol="tcp",
                    source="remediation",
                    reason=f"High-risk port {port}",
                    reason_tr=reason_tr,
                    is_active=True,
                )
                await self.add_rule(rule, db)
                rules_created += 1

        return {
            "status": "ok",
            "rules_created": rules_created,
            "message": f"{rules_created} port kurali olusturuldu.",
        }

    async def log_event(self, event: FirewallEvent, db: AsyncSession) -> None:
        """Log a firewall event."""
        from bigr.core.models_db import FirewallEventDB

        db_event = FirewallEventDB(
            id=event.id or str(uuid.uuid4()),
            timestamp=event.timestamp,
            action=event.action,
            rule_id=event.rule_id,
            source_ip=event.source_ip,
            dest_ip=event.dest_ip,
            dest_port=event.dest_port,
            protocol=event.protocol,
            process_name=event.process_name,
            direction=event.direction,
        )
        db.add(db_event)
        await db.commit()

    async def get_events(
        self,
        db: AsyncSession,
        limit: int = 100,
        action: str | None = None,
    ) -> list[FirewallEvent]:
        """Get recent firewall events."""
        from bigr.core.models_db import FirewallEventDB

        stmt = select(FirewallEventDB).order_by(FirewallEventDB.timestamp.desc())
        if action:
            stmt = stmt.where(FirewallEventDB.action == action)
        stmt = stmt.limit(limit)

        result = await db.execute(stmt)
        rows = result.scalars().all()

        return [
            FirewallEvent(
                id=r.id,
                timestamp=r.timestamp,
                action=r.action,
                rule_id=r.rule_id,
                source_ip=r.source_ip,
                dest_ip=r.dest_ip,
                dest_port=r.dest_port,
                protocol=r.protocol,
                process_name=r.process_name,
                direction=r.direction,
            )
            for r in rows
        ]

    async def get_config(self) -> FirewallConfig:
        """Get firewall configuration."""
        return self._config

    async def update_config(self, config: FirewallConfig) -> FirewallConfig:
        """Update firewall configuration."""
        self._config = config
        return self._config

    async def get_daily_stats(self, db: AsyncSession) -> dict:
        """Get today's block/allow statistics."""
        from bigr.core.models_db import FirewallEventDB

        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

        blocked_q = await db.execute(
            select(func.count(FirewallEventDB.id)).where(
                FirewallEventDB.action == "blocked",
                FirewallEventDB.timestamp >= today_start,
            )
        )
        blocked = blocked_q.scalar() or 0

        allowed_q = await db.execute(
            select(func.count(FirewallEventDB.id)).where(
                FirewallEventDB.action == "allowed",
                FirewallEventDB.timestamp >= today_start,
            )
        )
        allowed = allowed_q.scalar() or 0

        total = blocked + allowed

        return {
            "date": now.strftime("%Y-%m-%d"),
            "blocked": blocked,
            "allowed": allowed,
            "total": total,
            "block_rate": round(blocked / total * 100, 1) if total > 0 else 0.0,
        }

    async def install_adapter(self) -> dict:
        """Install the platform-specific firewall adapter."""
        if self._adapter is None:
            return {
                "status": "error",
                "message": "Bu platform icin firewall adaptoru bulunamadi.",
            }
        return await self._adapter.install()

    async def get_adapter_status(self) -> dict:
        """Get adapter status."""
        if self._adapter is None:
            return {
                "platform": platform.system().lower(),
                "engine": "none",
                "is_installed": False,
                "message": "Adapter bulunamadi.",
            }
        return await self._adapter.get_status()
