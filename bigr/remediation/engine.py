"""Remediation engine that generates fix actions for detected issues."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.models_db import (
    AgentCommandDB,
    AssetDB,
    RemediationActionDB,
    ScanAssetDB,
    ScanDB,
    ShieldFindingDB,
    ShieldScanDB,
)
from bigr.remediation.models import RemediationAction, RemediationPlan

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# High-risk port remediation rules (mirrors threat_analyzer._HIGH_RISK_PORTS)
# ---------------------------------------------------------------------------

_PORT_REMEDIATIONS: dict[int, dict] = {
    21: {
        "title": "Block FTP",
        "title_tr": "FTP Portunu Kapat",
        "description": "FTP transmits credentials in plain text. Switch to SFTP.",
        "description_tr": "FTP sifrelerini duz metin olarak iletir. SFTP'ye gecis yap.",
        "severity": "high",
        "action_type": "firewall_rule",
        "auto_fixable": True,
        "estimated_impact": "FTP ile dosya transferi calismayacak. SFTP (port 22) kullanin.",
    },
    23: {
        "title": "Block Telnet",
        "title_tr": "Telnet'i Kapat, SSH Kullan",
        "description": "Telnet is unencrypted. Use SSH instead.",
        "description_tr": "Telnet sifrelenmemis bir protokoldur. SSH kullan.",
        "severity": "critical",
        "action_type": "firewall_rule",
        "auto_fixable": True,
        "estimated_impact": "Telnet baglantilari kesilecek. SSH (port 22) ile erisim saglayin.",
    },
    445: {
        "title": "Restrict SMB to Local Subnet",
        "title_tr": "SMB'yi Yerel Agla Sinirla",
        "description": "SMB is a major ransomware vector (EternalBlue, WannaCry).",
        "description_tr": "SMB, fidye yazilimi saldirilarinin en yaygin vektorudur.",
        "severity": "critical",
        "action_type": "firewall_rule",
        "auto_fixable": True,
        "estimated_impact": "Dis agdan SMB erisimi engellenecek. Yerel dosya paylasimi etkilenmez.",
    },
    3389: {
        "title": "Block Direct RDP, Use VPN",
        "title_tr": "RDP'yi VPN Arkasina Al",
        "description": "RDP exposed to internet is a brute force and BlueKeep target.",
        "description_tr": "Internete acik RDP, kaba kuvvet ve BlueKeep saldirilarina maruz kalir.",
        "severity": "critical",
        "action_type": "firewall_rule",
        "auto_fixable": True,
        "estimated_impact": "Dogrudan RDP erisimi kapanacak. VPN uzerinden erisim saglayin.",
    },
    5900: {
        "title": "Secure or Disable VNC",
        "title_tr": "VNC'yi Guclendir veya Kapat",
        "description": "VNC is often unencrypted. Strengthen password or disable.",
        "description_tr": "VNC genellikle sifrelenmez. Sifreyi guclendir veya kapat.",
        "severity": "high",
        "action_type": "config_change",
        "auto_fixable": False,
        "estimated_impact": "VNC uzak masaustu erisimi etkilenebilir.",
    },
    6379: {
        "title": "Secure Redis",
        "title_tr": "Redis'e Yetkilendirme Ekle",
        "description": "Redis is often unauthenticated. Bind to localhost and set password.",
        "description_tr": "Redis genellikle yetkilendirmesiz calisir. Localhost'a bagla ve sifre koy.",
        "severity": "high",
        "action_type": "config_change",
        "auto_fixable": True,
        "estimated_impact": "Redis'e dis agdan erisim kapanacak. Uygulamalari yerel baglanti icin yapilandir.",
    },
    27017: {
        "title": "Secure MongoDB",
        "title_tr": "MongoDB Yetkilendirmesini Aktiflestir",
        "description": "MongoDB often runs without auth. Enable authentication and bind to localhost.",
        "description_tr": "MongoDB genellikle yetkilendirmesiz calisir. Yetkilendirmeyi aktiflestir.",
        "severity": "high",
        "action_type": "config_change",
        "auto_fixable": True,
        "estimated_impact": "MongoDB'ye dis agdan erisim kapanacak. Uygulama yapilandirmasi gerekebilir.",
    },
    135: {
        "title": "Block MSRPC",
        "title_tr": "MSRPC Portunu Kapat",
        "description": "Windows RPC can be used for lateral movement.",
        "description_tr": "Windows RPC, ag ici yatay hareket icin kullanilabilir.",
        "severity": "medium",
        "action_type": "firewall_rule",
        "auto_fixable": True,
        "estimated_impact": "Windows uzak yonetim islevleri etkilenebilir.",
    },
    139: {
        "title": "Block NetBIOS Session",
        "title_tr": "NetBIOS Oturumunu Kapat",
        "description": "SMB over NetBIOS is a ransomware vector.",
        "description_tr": "NetBIOS uzerinden SMB fidye yazilimi vektorudur.",
        "severity": "high",
        "action_type": "firewall_rule",
        "auto_fixable": True,
        "estimated_impact": "Eski Windows dosya paylasimi etkilenebilir. SMB2/3 kullanin.",
    },
    1433: {
        "title": "Restrict MSSQL Access",
        "title_tr": "MSSQL Erisimini Sinirla",
        "description": "MSSQL exposed to network is a SQL injection and brute force target.",
        "description_tr": "Aga acik MSSQL, SQL enjeksiyonu ve kaba kuvvet hedefidir.",
        "severity": "high",
        "action_type": "firewall_rule",
        "auto_fixable": True,
        "estimated_impact": "Dis agdan MSSQL erisimi kapanacak. Uygulama sunucusu uzerinden erisim saglayin.",
    },
    3306: {
        "title": "Restrict MySQL Access",
        "title_tr": "MySQL Erisimini Sinirla",
        "description": "MySQL exposed to network is a brute force target.",
        "description_tr": "Aga acik MySQL, kaba kuvvet saldirisi hedefidir.",
        "severity": "high",
        "action_type": "firewall_rule",
        "auto_fixable": True,
        "estimated_impact": "Dis agdan MySQL erisimi kapanacak.",
    },
    5432: {
        "title": "Restrict PostgreSQL Access",
        "title_tr": "PostgreSQL Erisimini Sinirla",
        "description": "PostgreSQL exposed to network should be restricted.",
        "description_tr": "Aga acik PostgreSQL sinirlandirilmali.",
        "severity": "medium",
        "action_type": "firewall_rule",
        "auto_fixable": True,
        "estimated_impact": "Dis agdan PostgreSQL erisimi kapanacak.",
    },
    9200: {
        "title": "Restrict Elasticsearch Access",
        "title_tr": "Elasticsearch Erisimini Sinirla",
        "description": "Elasticsearch often has no auth and exposes sensitive data.",
        "description_tr": "Elasticsearch genellikle yetkilendirmesiz calisir ve hassas verileri acigar.",
        "severity": "high",
        "action_type": "firewall_rule",
        "auto_fixable": True,
        "estimated_impact": "Dis agdan Elasticsearch erisimi kapanacak.",
    },
}


class RemediationEngine:
    """Generates remediation plans for detected issues."""

    async def generate_plan(
        self, asset_ip: str, db: AsyncSession
    ) -> RemediationPlan:
        """Generate remediation plan for a specific asset."""
        now_iso = datetime.now(timezone.utc).isoformat()
        actions: list[RemediationAction] = []

        # 1. Get asset from DB
        stmt = select(AssetDB).where(AssetDB.ip == asset_ip)
        result = await db.execute(stmt)
        asset = result.scalar_one_or_none()
        if not asset:
            return RemediationPlan(
                asset_ip=asset_ip,
                generated_at=now_iso,
            )

        # 2. Get open ports from latest scan
        port_stmt = (
            select(ScanAssetDB)
            .where(ScanAssetDB.asset_id == asset.id)
            .join(ScanDB, ScanAssetDB.scan_id == ScanDB.id)
            .order_by(ScanDB.started_at.desc())
            .limit(1)
        )
        port_result = await db.execute(port_stmt)
        scan_asset = port_result.scalar_one_or_none()

        open_ports: list[int] = []
        if scan_asset and scan_asset.open_ports:
            try:
                open_ports = json.loads(scan_asset.open_ports)
            except (json.JSONDecodeError, TypeError):
                pass

        # 3. Generate port-based remediation actions
        actions.extend(self._port_remediations(asset_ip, open_ports))

        # 4. Get shield findings for this IP
        finding_stmt = (
            select(ShieldFindingDB)
            .join(ShieldScanDB, ShieldFindingDB.scan_id == ShieldScanDB.id)
            .where(ShieldFindingDB.target_ip == asset_ip)
            .where(ShieldFindingDB.severity.in_(["critical", "high", "medium"]))
            .order_by(ShieldFindingDB.id.desc())
            .limit(20)
        )
        finding_result = await db.execute(finding_stmt)
        findings = finding_result.scalars().all()

        for finding in findings:
            actions.append(self._finding_remediation(asset_ip, finding))

        # 5. Build plan
        critical_count = sum(1 for a in actions if a.severity == "critical")
        auto_count = sum(1 for a in actions if a.auto_fixable)

        return RemediationPlan(
            asset_ip=asset_ip,
            total_actions=len(actions),
            critical_count=critical_count,
            auto_fixable_count=auto_count,
            actions=actions,
            generated_at=now_iso,
            ai_tier_used="heuristic",
        )

    async def generate_network_plan(
        self, db: AsyncSession
    ) -> RemediationPlan:
        """Generate remediation plan for the entire network."""
        now_iso = datetime.now(timezone.utc).isoformat()
        all_actions: list[RemediationAction] = []

        # Get all assets
        stmt = select(AssetDB).where(AssetDB.is_ignored == 0)
        result = await db.execute(stmt)
        assets = result.scalars().all()

        for asset in assets:
            # Get latest scan ports for this asset
            port_stmt = (
                select(ScanAssetDB)
                .where(ScanAssetDB.asset_id == asset.id)
                .join(ScanDB, ScanAssetDB.scan_id == ScanDB.id)
                .order_by(ScanDB.started_at.desc())
                .limit(1)
            )
            port_result = await db.execute(port_stmt)
            scan_asset = port_result.scalar_one_or_none()

            open_ports: list[int] = []
            if scan_asset and scan_asset.open_ports:
                try:
                    open_ports = json.loads(scan_asset.open_ports)
                except (json.JSONDecodeError, TypeError):
                    pass

            all_actions.extend(self._port_remediations(asset.ip, open_ports))

        # Deduplicate by (target_ip, target_port, action_type)
        seen: set[tuple[str | None, int | None, str]] = set()
        unique_actions: list[RemediationAction] = []
        for action in all_actions:
            key = (action.target_ip, action.target_port, action.action_type)
            if key not in seen:
                seen.add(key)
                unique_actions.append(action)

        critical_count = sum(1 for a in unique_actions if a.severity == "critical")
        auto_count = sum(1 for a in unique_actions if a.auto_fixable)

        return RemediationPlan(
            asset_ip=None,
            total_actions=len(unique_actions),
            critical_count=critical_count,
            auto_fixable_count=auto_count,
            actions=unique_actions,
            generated_at=now_iso,
            ai_tier_used="heuristic",
        )

    def _port_remediations(
        self, ip: str, ports: list[int]
    ) -> list[RemediationAction]:
        """Generate remediation actions for risky open ports."""
        actions: list[RemediationAction] = []
        for port in ports:
            if port in _PORT_REMEDIATIONS:
                info = _PORT_REMEDIATIONS[port]
                actions.append(
                    RemediationAction(
                        id=f"port-{ip}-{port}",
                        title=info["title"],
                        title_tr=info["title_tr"],
                        description=info["description"],
                        description_tr=info["description_tr"],
                        severity=info["severity"],
                        action_type=info["action_type"],
                        target_ip=ip,
                        target_port=port,
                        auto_fixable=info["auto_fixable"],
                        estimated_impact=info["estimated_impact"],
                    )
                )
        return actions

    def _finding_remediation(
        self, ip: str, finding: ShieldFindingDB
    ) -> RemediationAction:
        """Generate a remediation action from a shield finding."""
        remediation_text = finding.remediation or "Manuel inceleme gerekli."
        severity = finding.severity if finding.severity in (
            "critical", "high", "medium", "low"
        ) else "medium"

        return RemediationAction(
            id=f"finding-{ip}-{finding.id}",
            title=finding.title or "Security Finding",
            title_tr=finding.title or "Guvenlik Bulgusi",
            description=finding.detail or "A security issue was detected.",
            description_tr=finding.detail or "Bir guvenlik sorunu tespit edildi.",
            severity=severity,
            action_type="manual",
            target_ip=ip,
            target_port=None,
            auto_fixable=False,
            estimated_impact=remediation_text,
        )

    async def execute_action(
        self, action_id: str, db: AsyncSession
    ) -> dict:
        """Execute a remediation action (create agent command or log)."""
        now_iso = datetime.now(timezone.utc).isoformat()

        # Parse action_id to determine type
        # Format: "port-{ip}-{port}" or "finding-{ip}-{finding_id}"
        parts = action_id.split("-", 2)
        if len(parts) < 3:
            return {
                "status": "error",
                "message": "Gecersiz aksiyon kimliqi.",
            }

        action_type = parts[0]
        target_ip = parts[1]

        # Look up asset to find its agent_id
        stmt = select(AssetDB).where(AssetDB.ip == target_ip)
        result = await db.execute(stmt)
        asset = result.scalar_one_or_none()

        # Record the remediation action in DB
        remediation_record = RemediationActionDB(
            id=str(uuid.uuid4()),
            asset_ip=target_ip,
            action_type=action_type,
            title=action_id,
            severity="medium",
            status="executing",
            created_at=now_iso,
        )
        db.add(remediation_record)

        # If asset has an agent, create a command for it
        if asset and asset.agent_id:
            command_id = str(uuid.uuid4())
            cmd = AgentCommandDB(
                id=command_id,
                agent_id=asset.agent_id,
                command_type="remediate",
                params=json.dumps({
                    "action_id": action_id,
                    "action_type": action_type,
                    "target_ip": target_ip,
                }),
                status="pending",
                created_at=now_iso,
            )
            db.add(cmd)
            await db.commit()

            return {
                "status": "ok",
                "message": f"Onarim komutu ajana gonderildi.",
                "action_id": action_id,
                "command_id": command_id,
                "agent_id": asset.agent_id,
            }

        # No agent — mark as manual
        remediation_record.status = "pending"
        remediation_record.result = "Ajan bulunamadi. Manuel mudahale gerekli."
        await db.commit()

        return {
            "status": "manual",
            "message": "Ajan bulunamadi. Manuel mudahale gerekli.",
            "action_id": action_id,
        }

    async def get_history(
        self, db: AsyncSession, limit: int = 50
    ) -> list[dict]:
        """Get past remediation actions."""
        stmt = (
            select(RemediationActionDB)
            .order_by(RemediationActionDB.created_at.desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        records = result.scalars().all()

        return [
            {
                "id": r.id,
                "asset_ip": r.asset_ip,
                "action_type": r.action_type,
                "title": r.title,
                "severity": r.severity,
                "status": r.status,
                "executed_at": r.executed_at,
                "result": r.result,
                "created_at": r.created_at,
            }
            for r in records
        ]
