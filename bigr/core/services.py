"""Async service layer for the BİGR Discovery dashboard API.

Mirrors the query/write API of bigr/db.py using SQLAlchemy async sessions.
All functions accept an ``AsyncSession`` and return plain dicts matching
the existing API response shapes.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import delete, desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from bigr.core.models_db import (
    AssetChangeDB,
    AssetDB,
    CertificateDB,
    ScanAssetDB,
    ScanDB,
    SubnetDB,
    SwitchDB,
)
from bigr.models import BigrCategory


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _confidence_level(score: float) -> str:
    """Map a confidence score to a human-readable level."""
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    if score >= 0.3:
        return "low"
    return "unclassified"


def _bigr_label_tr(category_value: str) -> str:
    """Return the Turkish label for a BİGR category value."""
    try:
        return BigrCategory(category_value).label_tr
    except ValueError:
        return category_value


def _scan_to_dict(
    scan: ScanDB,
    *,
    include_assets: bool = False,
) -> dict:
    """Convert a ScanDB row (with optional eager-loaded scan_assets) to a dict."""
    d: dict = {
        "id": scan.id,
        "target": scan.target,
        "scan_method": scan.scan_method,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "total_assets": scan.total_assets,
        "is_root": bool(scan.is_root),
    }

    # Compute duration
    if scan.completed_at and scan.started_at:
        try:
            started = datetime.fromisoformat(scan.started_at)
            completed = datetime.fromisoformat(scan.completed_at)
            d["duration_seconds"] = (completed - started).total_seconds()
        except (ValueError, TypeError):
            d["duration_seconds"] = None
    else:
        d["duration_seconds"] = None

    if include_assets:
        assets = []
        category_summary: dict[str, int] = {}
        for sa in (scan.scan_assets or []):
            asset = sa.asset
            bigr_cat = sa.bigr_category or (asset.bigr_category if asset else "unclassified")
            category_summary[bigr_cat] = category_summary.get(bigr_cat, 0) + 1

            open_ports = json.loads(sa.open_ports or "[]")
            raw_evidence = json.loads(sa.raw_evidence or "{}")
            conf = sa.confidence_score if sa.confidence_score else (
                asset.confidence_score if asset else 0.0
            )

            assets.append({
                "ip": asset.ip if asset else "",
                "mac": asset.mac if asset else None,
                "hostname": asset.hostname if asset else None,
                "vendor": asset.vendor if asset else None,
                "open_ports": open_ports,
                "os_hint": asset.os_hint if asset else None,
                "bigr_category": bigr_cat,
                "bigr_category_tr": _bigr_label_tr(bigr_cat),
                "confidence_score": conf,
                "confidence_level": _confidence_level(conf),
                "scan_method": asset.scan_method if asset else "",
                "first_seen": asset.first_seen if asset else "",
                "last_seen": asset.last_seen if asset else "",
                "raw_evidence": raw_evidence,
            })

        d["assets"] = assets
        d["category_summary"] = category_summary

    return d


# ---------------------------------------------------------------------------
# Read operations
# ---------------------------------------------------------------------------

async def get_latest_scan(
    session: AsyncSession, target: str | None = None
) -> dict | None:
    """Return the most recent scan with nested assets."""
    stmt = (
        select(ScanDB)
        .options(
            selectinload(ScanDB.scan_assets).selectinload(ScanAssetDB.asset)
        )
        .order_by(desc(ScanDB.started_at))
        .limit(1)
    )
    if target:
        stmt = stmt.where(ScanDB.target == target)

    result = (await session.execute(stmt)).scalar_one_or_none()
    if result is None:
        return None
    return _scan_to_dict(result, include_assets=True)


async def get_all_assets(
    session: AsyncSession, *, site_name: str | None = None
) -> list[dict]:
    """Return all known assets from the living inventory.

    If *site_name* is provided, only assets from that site are returned.
    """
    stmt = select(AssetDB).order_by(desc(AssetDB.last_seen))
    if site_name:
        stmt = stmt.where(AssetDB.site_name == site_name)
    result = await session.execute(stmt)
    return [
        {
            "id": a.id,
            "ip": a.ip,
            "mac": a.mac,
            "hostname": a.hostname,
            "vendor": a.vendor,
            "os_hint": a.os_hint,
            "bigr_category": a.bigr_category,
            "confidence_score": a.confidence_score,
            "scan_method": a.scan_method,
            "first_seen": a.first_seen,
            "last_seen": a.last_seen,
            "manual_category": a.manual_category,
            "manual_note": a.manual_note,
            "is_ignored": a.is_ignored,
            "switch_host": a.switch_host,
            "switch_port": a.switch_port,
            "switch_port_index": a.switch_port_index,
            "agent_id": a.agent_id,
            "site_name": a.site_name,
        }
        for a in result.scalars().all()
    ]


async def get_scan_list(
    session: AsyncSession, limit: int = 20
) -> list[dict]:
    """Return recent scans (metadata only, no nested assets)."""
    stmt = select(ScanDB).order_by(desc(ScanDB.started_at)).limit(limit)
    result = await session.execute(stmt)
    return [_scan_to_dict(s) for s in result.scalars().all()]


async def get_asset_history(
    session: AsyncSession,
    ip: str | None = None,
    mac: str | None = None,
) -> list[dict]:
    """Return an asset's scan-by-scan history."""
    if not ip and not mac:
        return []

    stmt = (
        select(ScanAssetDB, ScanDB, AssetDB)
        .join(ScanDB, ScanDB.id == ScanAssetDB.scan_id)
        .join(AssetDB, AssetDB.id == ScanAssetDB.asset_id)
        .order_by(desc(ScanDB.started_at))
    )
    if ip:
        stmt = stmt.where(AssetDB.ip == ip)
    if mac:
        stmt = stmt.where(AssetDB.mac == mac)

    result = await session.execute(stmt)
    rows = []
    for sa, scan, asset in result.all():
        rows.append({
            "scan_id": sa.scan_id,
            "asset_id": sa.asset_id,
            "open_ports": sa.open_ports,
            "confidence_score": sa.confidence_score,
            "bigr_category": sa.bigr_category,
            "raw_evidence": sa.raw_evidence,
            "target": scan.target,
            "scan_started": scan.started_at,
            "scan_scan_method": scan.scan_method,
            "ip": asset.ip,
            "mac": asset.mac,
            "hostname": asset.hostname,
            "vendor": asset.vendor,
        })
    return rows


async def get_tags_async(session: AsyncSession) -> list[dict]:
    """Return all assets that have manual overrides."""
    stmt = select(AssetDB).where(AssetDB.manual_category.isnot(None))
    result = await session.execute(stmt)
    return [
        {
            "ip": a.ip,
            "mac": a.mac,
            "hostname": a.hostname,
            "manual_category": a.manual_category,
            "manual_note": a.manual_note,
        }
        for a in result.scalars().all()
    ]


async def get_subnets_async(session: AsyncSession) -> list[dict]:
    """Return all registered subnets."""
    stmt = select(SubnetDB).order_by(SubnetDB.cidr)
    result = await session.execute(stmt)
    return [
        {
            "cidr": s.cidr,
            "label": s.label,
            "vlan_id": s.vlan_id,
            "last_scanned": s.last_scanned,
            "asset_count": s.asset_count,
        }
        for s in result.scalars().all()
    ]


async def get_switches_async(session: AsyncSession) -> list[dict]:
    """Return all registered switches."""
    stmt = select(SwitchDB).order_by(SwitchDB.host)
    result = await session.execute(stmt)
    return [
        {
            "host": s.host,
            "community": s.community,
            "version": s.version,
            "label": s.label,
            "last_polled": s.last_polled,
            "mac_count": s.mac_count,
        }
        for s in result.scalars().all()
    ]


async def get_certificates_async(session: AsyncSession) -> list[dict]:
    """Return all stored certificates."""
    stmt = select(CertificateDB).order_by(desc(CertificateDB.last_checked))
    result = await session.execute(stmt)
    certs = []
    for c in result.scalars().all():
        try:
            san = json.loads(c.san or "[]")
        except (json.JSONDecodeError, TypeError):
            san = []
        certs.append({
            "id": c.id,
            "ip": c.ip,
            "port": c.port,
            "cn": c.cn,
            "issuer": c.issuer,
            "issuer_org": c.issuer_org,
            "valid_from": c.valid_from,
            "valid_to": c.valid_to,
            "serial": c.serial,
            "key_size": c.key_size,
            "key_algorithm": c.key_algorithm,
            "is_self_signed": bool(c.is_self_signed),
            "is_expired": bool(c.is_expired),
            "days_until_expiry": c.days_until_expiry,
            "san": san,
            "last_checked": c.last_checked,
        })
    return certs


async def get_expiring_certs_async(
    session: AsyncSession, days: int = 30
) -> list[dict]:
    """Return certificates expiring within N days."""
    stmt = (
        select(CertificateDB)
        .where(
            CertificateDB.days_until_expiry.isnot(None),
            CertificateDB.days_until_expiry <= days,
        )
        .order_by(CertificateDB.days_until_expiry)
    )
    result = await session.execute(stmt)
    certs = []
    for c in result.scalars().all():
        try:
            san = json.loads(c.san or "[]")
        except (json.JSONDecodeError, TypeError):
            san = []
        certs.append({
            "id": c.id,
            "ip": c.ip,
            "port": c.port,
            "cn": c.cn,
            "issuer": c.issuer,
            "issuer_org": c.issuer_org,
            "valid_from": c.valid_from,
            "valid_to": c.valid_to,
            "serial": c.serial,
            "key_size": c.key_size,
            "key_algorithm": c.key_algorithm,
            "is_self_signed": bool(c.is_self_signed),
            "is_expired": bool(c.is_expired),
            "days_until_expiry": c.days_until_expiry,
            "san": san,
            "last_checked": c.last_checked,
        })
    return certs


async def get_changes_async(
    session: AsyncSession, limit: int = 50, *, site_name: str | None = None
) -> list[dict]:
    """Return recent asset changes, optionally filtered by site."""
    stmt = (
        select(AssetChangeDB, AssetDB)
        .join(AssetDB, AssetDB.id == AssetChangeDB.asset_id)
        .order_by(desc(AssetChangeDB.detected_at), desc(AssetChangeDB.id))
        .limit(limit)
    )
    if site_name:
        stmt = stmt.where(AssetDB.site_name == site_name)
    result = await session.execute(stmt)
    return [
        {
            "id": change.id,
            "asset_id": change.asset_id,
            "scan_id": change.scan_id,
            "change_type": change.change_type,
            "field_name": change.field_name,
            "old_value": change.old_value,
            "new_value": change.new_value,
            "detected_at": change.detected_at,
            "ip": asset.ip,
            "mac": asset.mac,
        }
        for change, asset in result.all()
    ]


async def get_sites_summary(session: AsyncSession) -> list[dict]:
    """Return a summary of all known sites with asset counts."""
    from bigr.core.models_db import AgentDB

    # Get distinct site_names from assets
    stmt = (
        select(
            AssetDB.site_name,
            func.count(AssetDB.id).label("asset_count"),
        )
        .group_by(AssetDB.site_name)
        .order_by(AssetDB.site_name)
    )
    result = await session.execute(stmt)
    sites = []
    for row in result.all():
        site = row.site_name or "(local)"
        sites.append({
            "site_name": site,
            "asset_count": row.asset_count,
        })
    return sites


# ---------------------------------------------------------------------------
# Write operations
# ---------------------------------------------------------------------------

async def save_scan_async(
    session: AsyncSession, scan_result: dict
) -> str:
    """Save an entire scan result, upserting assets and detecting changes.

    Accepts a dict with keys: target, scan_method, started_at, completed_at,
    assets (list of asset dicts), is_root.

    Returns the generated scan_id.
    """
    scan_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    scan = ScanDB(
        id=scan_id,
        target=scan_result["target"],
        scan_method=scan_result["scan_method"],
        started_at=scan_result["started_at"],
        completed_at=scan_result.get("completed_at"),
        total_assets=len(scan_result.get("assets", [])),
        is_root=int(scan_result.get("is_root", False)),
        agent_id=scan_result.get("agent_id"),
        site_name=scan_result.get("site_name"),
    )
    session.add(scan)
    await session.flush()

    _agent_id = scan_result.get("agent_id")
    _site_name = scan_result.get("site_name")

    for asset_data in scan_result.get("assets", []):
        asset_id = await _upsert_asset_async(
            session, asset_data, scan_id, now_iso,
            agent_id=_agent_id, site_name=_site_name,
        )

        sa = ScanAssetDB(
            scan_id=scan_id,
            asset_id=asset_id,
            open_ports=json.dumps(asset_data.get("open_ports", [])),
            confidence_score=asset_data.get("confidence_score", 0.0),
            bigr_category=asset_data.get("bigr_category", "unclassified"),
            raw_evidence=json.dumps(asset_data.get("raw_evidence", {})),
        )
        session.add(sa)

    await session.commit()
    return scan_id


async def _upsert_asset_async(
    session: AsyncSession,
    asset_data: dict,
    scan_id: str,
    now_iso: str,
    *,
    agent_id: str | None = None,
    site_name: str | None = None,
) -> str:
    """Insert or update an asset. Detects and logs changes. Returns asset_id."""
    ip = asset_data["ip"]
    mac = asset_data.get("mac")

    # Look up existing
    stmt = select(AssetDB).where(AssetDB.ip == ip)
    if mac is None:
        stmt = stmt.where(AssetDB.mac.is_(None))
    else:
        stmt = stmt.where(AssetDB.mac == mac)

    existing = (await session.execute(stmt)).scalar_one_or_none()

    if existing is None:
        asset_id = str(uuid.uuid4())
        new_asset = AssetDB(
            id=asset_id,
            ip=ip,
            mac=mac,
            hostname=asset_data.get("hostname"),
            vendor=asset_data.get("vendor"),
            os_hint=asset_data.get("os_hint"),
            bigr_category=asset_data.get("bigr_category", "unclassified"),
            confidence_score=asset_data.get("confidence_score", 0.0),
            scan_method=asset_data.get("scan_method", "passive"),
            first_seen=asset_data.get("first_seen", now_iso),
            last_seen=asset_data.get("last_seen", now_iso),
            agent_id=agent_id,
            site_name=site_name,
        )
        session.add(new_asset)
        await session.flush()

        # Log new-asset change
        session.add(AssetChangeDB(
            asset_id=asset_id,
            scan_id=scan_id,
            change_type="new_asset",
            detected_at=now_iso,
        ))
        return asset_id

    # Existing asset — detect field changes
    asset_id = existing.id
    tracked_fields = {
        "hostname": asset_data.get("hostname"),
        "vendor": asset_data.get("vendor"),
        "os_hint": asset_data.get("os_hint"),
        "bigr_category": asset_data.get("bigr_category", "unclassified"),
        "confidence_score": str(asset_data.get("confidence_score", 0.0)),
        "scan_method": asset_data.get("scan_method", "passive"),
    }

    for field_name, new_value in tracked_fields.items():
        old_value = getattr(existing, field_name)
        old_str = str(old_value) if old_value is not None else None
        new_str = str(new_value) if new_value is not None else None
        if old_str != new_str:
            session.add(AssetChangeDB(
                asset_id=asset_id,
                scan_id=scan_id,
                change_type="field_changed",
                field_name=field_name,
                old_value=old_str,
                new_value=new_str,
                detected_at=now_iso,
            ))

    # Update living record
    existing.hostname = asset_data.get("hostname")
    existing.vendor = asset_data.get("vendor")
    existing.os_hint = asset_data.get("os_hint")
    existing.bigr_category = asset_data.get("bigr_category", "unclassified")
    existing.confidence_score = asset_data.get("confidence_score", 0.0)
    existing.scan_method = asset_data.get("scan_method", "passive")
    existing.last_seen = asset_data.get("last_seen", now_iso)

    return asset_id


async def tag_asset_async(
    session: AsyncSession,
    ip: str,
    category: str,
    note: str | None = None,
) -> None:
    """Apply a manual category override to an asset."""
    stmt = (
        update(AssetDB)
        .where(AssetDB.ip == ip)
        .values(manual_category=category, manual_note=note)
    )
    await session.execute(stmt)
    await session.commit()


async def untag_asset_async(session: AsyncSession, ip: str) -> None:
    """Remove manual category override."""
    stmt = (
        update(AssetDB)
        .where(AssetDB.ip == ip)
        .values(manual_category=None, manual_note=None)
    )
    await session.execute(stmt)
    await session.commit()


async def add_subnet_async(
    session: AsyncSession,
    cidr: str,
    label: str = "",
    vlan_id: int | None = None,
) -> None:
    """Register a subnet (upsert)."""
    existing = await session.get(SubnetDB, cidr)
    if existing:
        existing.label = label
        existing.vlan_id = vlan_id
    else:
        session.add(SubnetDB(cidr=cidr, label=label, vlan_id=vlan_id))
    await session.commit()


async def remove_subnet_async(session: AsyncSession, cidr: str) -> None:
    """Remove a registered subnet."""
    stmt = delete(SubnetDB).where(SubnetDB.cidr == cidr)
    await session.execute(stmt)
    await session.commit()


async def save_certificate_async(
    session: AsyncSession, cert_data: dict
) -> None:
    """Save or update a TLS certificate (upsert on ip+port)."""
    ip = cert_data["ip"]
    port = cert_data["port"]
    now_iso = datetime.now(timezone.utc).isoformat()

    stmt = select(CertificateDB).where(
        CertificateDB.ip == ip, CertificateDB.port == port
    )
    existing = (await session.execute(stmt)).scalar_one_or_none()

    if existing:
        for field in (
            "cn", "issuer", "issuer_org", "valid_from", "valid_to",
            "serial", "key_size", "key_algorithm",
        ):
            if field in cert_data:
                setattr(existing, field, cert_data[field])
        existing.is_self_signed = int(cert_data.get("is_self_signed", False))
        existing.is_expired = int(cert_data.get("is_expired", False))
        existing.days_until_expiry = cert_data.get("days_until_expiry")
        existing.san = json.dumps(cert_data.get("san", []))
        existing.last_checked = now_iso
    else:
        session.add(CertificateDB(
            ip=ip,
            port=port,
            cn=cert_data.get("cn"),
            issuer=cert_data.get("issuer"),
            issuer_org=cert_data.get("issuer_org"),
            valid_from=cert_data.get("valid_from"),
            valid_to=cert_data.get("valid_to"),
            serial=cert_data.get("serial"),
            key_size=cert_data.get("key_size"),
            key_algorithm=cert_data.get("key_algorithm"),
            is_self_signed=int(cert_data.get("is_self_signed", False)),
            is_expired=int(cert_data.get("is_expired", False)),
            days_until_expiry=cert_data.get("days_until_expiry"),
            san=json.dumps(cert_data.get("san", [])),
            last_checked=now_iso,
        ))

    await session.commit()
