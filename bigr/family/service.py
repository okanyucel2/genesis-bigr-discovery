"""Family Shield service — manages device groups, safety overview, and alerts.

The Family Shield plan ($9.99/mo) supports up to 5 devices in a family group.
Parents get a unified dashboard showing safety scores, threats, and activity
across all registered family devices.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.models_db import (
    AgentDB,
    FamilyDeviceDB,
    NetworkDB,
    ShieldFindingDB,
    ShieldScanDB,
    SubscriptionDB,
)
from bigr.family.models import (
    AddDeviceRequest,
    FamilyAlert,
    FamilyDevice,
    FamilyOverview,
    FamilyTimelineEntry,
    UpdateDeviceRequest,
)
from bigr.subscription.plans import PLANS

logger = logging.getLogger(__name__)

# Default max devices for Family Shield (also configurable via settings)
FAMILY_MAX_DEVICES = 5


class FamilyService:
    """Manages Family Shield device groups and overview."""

    async def get_overview(
        self, subscription_id: str, db: AsyncSession
    ) -> FamilyOverview:
        """Get family dashboard overview.

        Joins FamilyDeviceDB -> AgentDB to get live status.
        Calculates per-device safety scores from recent scans.
        """
        # Verify subscription exists and is family plan
        sub = await self._get_subscription(subscription_id, db)
        plan = PLANS.get(sub.plan_id, PLANS["family"])

        # Get all active family devices
        stmt = (
            select(FamilyDeviceDB)
            .where(FamilyDeviceDB.subscription_id == subscription_id)
            .where(FamilyDeviceDB.is_active == 1)
        )
        result = await db.execute(stmt)
        device_rows = result.scalars().all()

        devices: list[FamilyDevice] = []
        total_threats = 0
        devices_online = 0
        last_scan: str | None = None
        safety_scores: list[float] = []

        for dev_row in device_rows:
            agent = None
            if dev_row.agent_id:
                agent_result = await db.execute(
                    select(AgentDB).where(AgentDB.id == dev_row.agent_id)
                )
                agent = agent_result.scalar_one_or_none()

            # Calculate safety for this device
            score, level = await self._calculate_safety_score(
                dev_row.agent_id, db
            )
            open_threats = await self._count_open_threats(dev_row.agent_id, db)
            total_threats += open_threats

            is_online = False
            agent_last_seen: str | None = None
            ip: str | None = None
            network_name: str | None = None

            if agent:
                is_online = agent.status == "online"
                agent_last_seen = agent.last_seen
                ip = None  # Agent doesn't store IP directly

                # Try to get network name
                if agent.id:
                    net_result = await db.execute(
                        select(NetworkDB)
                        .where(NetworkDB.agent_id == agent.id)
                        .order_by(NetworkDB.last_seen.desc())
                        .limit(1)
                    )
                    network = net_result.scalar_one_or_none()
                    if network:
                        network_name = network.friendly_name or network.ssid

                # Get last scan time for this agent
                scan_result = await db.execute(
                    select(ShieldScanDB.completed_at)
                    .where(ShieldScanDB.agent_id == agent.id)
                    .where(ShieldScanDB.completed_at.isnot(None))
                    .order_by(ShieldScanDB.completed_at.desc())
                    .limit(1)
                )
                scan_time = scan_result.scalar_one_or_none()
                if scan_time and (last_scan is None or scan_time > last_scan):
                    last_scan = scan_time

            if is_online:
                devices_online += 1

            safety_scores.append(score)

            devices.append(
                FamilyDevice(
                    id=dev_row.id,
                    name=dev_row.name,
                    device_type=dev_row.device_type,
                    icon=self._device_icon(dev_row.device_type),
                    owner_name=dev_row.owner_name,
                    is_online=is_online,
                    last_seen=agent_last_seen or dev_row.added_at,
                    safety_score=score,
                    safety_level=level,
                    open_threats=open_threats,
                    ip=ip,
                    network_name=network_name,
                )
            )

        # Calculate averages
        avg_safety = (
            sum(safety_scores) / len(safety_scores) if safety_scores else 0.0
        )

        # Overall safety level
        if avg_safety >= 0.8:
            overall_level = "safe"
        elif avg_safety >= 0.5:
            overall_level = "warning"
        else:
            overall_level = "danger"

        return FamilyOverview(
            family_name="Ailem",
            plan_id=sub.plan_id,
            devices=devices,
            max_devices=plan.max_devices,
            total_threats=total_threats,
            avg_safety_score=round(avg_safety, 2),
            safety_level=overall_level,
            devices_online=devices_online,
            last_scan=last_scan,
        )

    async def add_device(
        self,
        subscription_id: str,
        request: AddDeviceRequest,
        db: AsyncSession,
    ) -> FamilyDevice:
        """Add a device to the family group.

        Checks device limit (Family Shield = 5 max).
        """
        sub = await self._get_subscription(subscription_id, db)
        plan = PLANS.get(sub.plan_id, PLANS["family"])

        # Count current active devices
        count_stmt = (
            select(func.count())
            .select_from(FamilyDeviceDB)
            .where(FamilyDeviceDB.subscription_id == subscription_id)
            .where(FamilyDeviceDB.is_active == 1)
        )
        result = await db.execute(count_stmt)
        current_count = result.scalar_one()

        if current_count >= plan.max_devices:
            raise ValueError(
                f"Cihaz limiti doldu! Planin en fazla {plan.max_devices} "
                f"cihaz destekliyor. Simdi {current_count} cihaz kayitli."
            )

        now = datetime.now(timezone.utc).isoformat()
        device_id = str(uuid.uuid4())

        new_device = FamilyDeviceDB(
            id=device_id,
            subscription_id=subscription_id,
            agent_id=None,
            name=request.device_name,
            device_type=request.device_type,
            owner_name=request.owner_name,
            added_at=now,
            is_active=1,
        )
        db.add(new_device)
        await db.commit()
        await db.refresh(new_device)

        logger.info(
            "Added family device %s (%s) to subscription %s",
            device_id,
            request.device_name,
            subscription_id,
        )

        score, level = await self._calculate_safety_score(None, db)

        return FamilyDevice(
            id=device_id,
            name=request.device_name,
            device_type=request.device_type,
            icon=self._device_icon(request.device_type),
            owner_name=request.owner_name,
            is_online=False,
            last_seen=now,
            safety_score=score,
            safety_level=level,
            open_threats=0,
            ip=None,
            network_name=None,
        )

    async def remove_device(
        self, device_id: str, db: AsyncSession
    ) -> dict:
        """Remove (deactivate) a device from the family group."""
        device = await self._get_device(device_id, db)
        device.is_active = 0
        await db.commit()

        logger.info("Removed family device %s (%s)", device_id, device.name)

        return {
            "status": "ok",
            "message": f"'{device.name}' aile grubundan cikarildi.",
            "device_id": device_id,
        }

    async def update_device(
        self,
        device_id: str,
        request: UpdateDeviceRequest,
        db: AsyncSession,
    ) -> FamilyDevice:
        """Update device name, type, or owner."""
        device = await self._get_device(device_id, db)

        if request.name is not None:
            device.name = request.name
        if request.device_type is not None:
            device.device_type = request.device_type
        if request.owner_name is not None:
            device.owner_name = request.owner_name

        await db.commit()
        await db.refresh(device)

        score, level = await self._calculate_safety_score(device.agent_id, db)
        open_threats = await self._count_open_threats(device.agent_id, db)

        return FamilyDevice(
            id=device.id,
            name=device.name,
            device_type=device.device_type,
            icon=self._device_icon(device.device_type),
            owner_name=device.owner_name,
            is_online=False,
            last_seen=device.added_at,
            safety_score=score,
            safety_level=level,
            open_threats=open_threats,
            ip=None,
            network_name=None,
        )

    async def get_device_detail(
        self, device_id: str, db: AsyncSession
    ) -> FamilyDevice:
        """Get detailed info for a single family device."""
        device = await self._get_device(device_id, db)

        agent = None
        if device.agent_id:
            agent_result = await db.execute(
                select(AgentDB).where(AgentDB.id == device.agent_id)
            )
            agent = agent_result.scalar_one_or_none()

        score, level = await self._calculate_safety_score(device.agent_id, db)
        open_threats = await self._count_open_threats(device.agent_id, db)

        is_online = False
        last_seen = device.added_at
        ip: str | None = None
        network_name: str | None = None

        if agent:
            is_online = agent.status == "online"
            last_seen = agent.last_seen or device.added_at

        return FamilyDevice(
            id=device.id,
            name=device.name,
            device_type=device.device_type,
            icon=self._device_icon(device.device_type),
            owner_name=device.owner_name,
            is_online=is_online,
            last_seen=last_seen,
            safety_score=score,
            safety_level=level,
            open_threats=open_threats,
            ip=ip,
            network_name=network_name,
        )

    async def get_family_alerts(
        self,
        subscription_id: str,
        db: AsyncSession,
        limit: int = 50,
    ) -> list[FamilyAlert]:
        """Get recent alerts across all family devices.

        Pulls shield findings from agents linked to family devices
        and converts them to human-friendly FamilyAlert objects.
        """
        # Get all device agent_ids for this subscription
        stmt = (
            select(FamilyDeviceDB)
            .where(FamilyDeviceDB.subscription_id == subscription_id)
            .where(FamilyDeviceDB.is_active == 1)
        )
        result = await db.execute(stmt)
        devices = result.scalars().all()

        device_map: dict[str | None, str] = {}
        agent_ids: list[str] = []
        for dev in devices:
            if dev.agent_id:
                agent_ids.append(dev.agent_id)
                device_map[dev.agent_id] = dev.name
            device_map[dev.id] = dev.name

        if not agent_ids:
            return []

        # Get findings for these agents
        findings_stmt = (
            select(ShieldFindingDB, ShieldScanDB)
            .join(ShieldScanDB, ShieldFindingDB.scan_id == ShieldScanDB.id)
            .where(ShieldScanDB.agent_id.in_(agent_ids))
            .order_by(ShieldScanDB.started_at.desc())
            .limit(limit)
        )
        findings_result = await db.execute(findings_stmt)
        rows = findings_result.all()

        alerts: list[FamilyAlert] = []
        for finding, scan in rows:
            device_name = device_map.get(scan.agent_id, "Bilinmeyen Cihaz")

            # Map severity to Turkish-friendly message
            severity_messages = {
                "critical": "Kritik tehdit tespit edildi",
                "high": "Yuksek riskli bulgu",
                "medium": "Orta riskli durum",
                "low": "Dusuk riskli bilgi",
                "info": "Bilgilendirme",
            }
            message = finding.title or severity_messages.get(
                finding.severity, "Guvenlik bulgusu"
            )

            alerts.append(
                FamilyAlert(
                    id=f"alert-{finding.id}",
                    device_id=scan.agent_id or "",
                    device_name=device_name,
                    alert_type=finding.module,
                    severity=finding.severity,
                    message=message,
                    timestamp=scan.started_at,
                    is_read=False,
                )
            )

        return alerts

    async def get_family_timeline(
        self,
        subscription_id: str,
        db: AsyncSession,
        limit: int = 30,
    ) -> list[FamilyTimelineEntry]:
        """Get activity timeline across all family devices.

        Merges scans and device additions into a chronological feed.
        """
        # Get devices
        stmt = (
            select(FamilyDeviceDB)
            .where(FamilyDeviceDB.subscription_id == subscription_id)
        )
        result = await db.execute(stmt)
        devices = result.scalars().all()

        entries: list[FamilyTimelineEntry] = []

        for dev in devices:
            # Device addition event
            entries.append(
                FamilyTimelineEntry(
                    id=f"tl-add-{dev.id}",
                    device_id=dev.id,
                    device_name=dev.name,
                    device_icon=self._device_icon(dev.device_type),
                    event_type="device_added",
                    message=f"'{dev.name}' aile grubuna eklendi",
                    timestamp=dev.added_at,
                )
            )

            # If device is deactivated, add removal event
            if dev.is_active == 0:
                entries.append(
                    FamilyTimelineEntry(
                        id=f"tl-rm-{dev.id}",
                        device_id=dev.id,
                        device_name=dev.name,
                        device_icon=self._device_icon(dev.device_type),
                        event_type="device_removed",
                        message=f"'{dev.name}' aile grubundan cikarildi",
                        timestamp=dev.added_at,  # approximate
                    )
                )

            # Scan events from linked agent
            if dev.agent_id:
                scan_stmt = (
                    select(ShieldScanDB)
                    .where(ShieldScanDB.agent_id == dev.agent_id)
                    .order_by(ShieldScanDB.started_at.desc())
                    .limit(5)
                )
                scan_result = await db.execute(scan_stmt)
                scans = scan_result.scalars().all()

                for scan in scans:
                    entries.append(
                        FamilyTimelineEntry(
                            id=f"tl-scan-{scan.id}",
                            device_id=dev.id,
                            device_name=dev.name,
                            device_icon=self._device_icon(dev.device_type),
                            event_type="scan",
                            message=f"'{dev.name}' icin guvenlik tarandi",
                            timestamp=scan.started_at,
                        )
                    )

        # Sort by timestamp (newest first) and limit
        entries.sort(key=lambda e: e.timestamp, reverse=True)
        return entries[:limit]

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #

    async def _get_subscription(
        self, subscription_id: str, db: AsyncSession
    ) -> SubscriptionDB:
        """Fetch subscription or raise."""
        result = await db.execute(
            select(SubscriptionDB).where(SubscriptionDB.id == subscription_id)
        )
        sub = result.scalar_one_or_none()
        if sub is None:
            raise ValueError(f"Abonelik bulunamadi: {subscription_id}")
        return sub

    async def _get_device(
        self, device_id: str, db: AsyncSession
    ) -> FamilyDeviceDB:
        """Fetch an active family device or raise."""
        result = await db.execute(
            select(FamilyDeviceDB)
            .where(FamilyDeviceDB.id == device_id)
            .where(FamilyDeviceDB.is_active == 1)
        )
        device = result.scalar_one_or_none()
        if device is None:
            raise ValueError(f"Cihaz bulunamadi: {device_id}")
        return device

    async def _calculate_safety_score(
        self, agent_id: str | None, db: AsyncSession
    ) -> tuple[float, str]:
        """Calculate safety score based on agent's last scan data.

        Returns (score, level) where level is "safe", "warning", or "danger".
        """
        if agent_id is None:
            # No agent linked -> unknown safety
            return 0.5, "warning"

        # Count findings by severity for the latest scan
        latest_scan_stmt = (
            select(ShieldScanDB)
            .where(ShieldScanDB.agent_id == agent_id)
            .order_by(ShieldScanDB.started_at.desc())
            .limit(1)
        )
        scan_result = await db.execute(latest_scan_stmt)
        latest_scan = scan_result.scalar_one_or_none()

        if latest_scan is None:
            # No scans yet
            return 0.5, "warning"

        findings_stmt = (
            select(ShieldFindingDB)
            .where(ShieldFindingDB.scan_id == latest_scan.id)
        )
        findings_result = await db.execute(findings_stmt)
        findings = findings_result.scalars().all()

        if not findings:
            # Scanned, no findings -> safe
            return 0.95, "safe"

        # Calculate score based on severity weights
        severity_penalties = {
            "critical": 0.30,
            "high": 0.15,
            "medium": 0.08,
            "low": 0.03,
            "info": 0.01,
        }

        total_penalty = 0.0
        for finding in findings:
            penalty = severity_penalties.get(finding.severity, 0.03)
            total_penalty += penalty

        # Score starts at 1.0 and decreases with penalties, min 0.0
        score = max(0.0, min(1.0, 1.0 - total_penalty))

        if score >= 0.8:
            level = "safe"
        elif score >= 0.5:
            level = "warning"
        else:
            level = "danger"

        return round(score, 2), level

    async def _count_open_threats(
        self, agent_id: str | None, db: AsyncSession
    ) -> int:
        """Count open threats (non-info findings) for an agent."""
        if agent_id is None:
            return 0

        # Count findings with severity > info from latest scan
        latest_scan_stmt = (
            select(ShieldScanDB)
            .where(ShieldScanDB.agent_id == agent_id)
            .order_by(ShieldScanDB.started_at.desc())
            .limit(1)
        )
        scan_result = await db.execute(latest_scan_stmt)
        latest_scan = scan_result.scalar_one_or_none()

        if latest_scan is None:
            return 0

        count_stmt = (
            select(func.count())
            .select_from(ShieldFindingDB)
            .where(ShieldFindingDB.scan_id == latest_scan.id)
            .where(ShieldFindingDB.severity != "info")
        )
        result = await db.execute(count_stmt)
        return result.scalar_one()

    def _device_icon(self, device_type: str) -> str:
        """Return icon for device type."""
        icons = {
            "phone": "\U0001f4f1",
            "laptop": "\U0001f4bb",
            "tablet": "\U0001f4df",
            "desktop": "\U0001f5a5\ufe0f",
            "other": "\U0001f4e1",
        }
        return icons.get(device_type, "\U0001f4e1")
