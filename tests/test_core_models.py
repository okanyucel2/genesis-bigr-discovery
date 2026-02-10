"""Tests for bigr.core.models_db ORM models."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.database import Base, get_engine, get_session_factory, reset_engine
from bigr.core.models_db import (
    AssetChangeDB,
    AssetDB,
    CertificateDB,
    ScanAssetDB,
    ScanDB,
    SubnetDB,
    SwitchDB,
)


@pytest.fixture(autouse=True)
async def db_session():
    """Create a fresh in-memory database for each test."""
    reset_engine()
    engine = get_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = get_session_factory()
    async with factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    reset_engine()


class TestScanDB:
    async def test_create_scan(self, db_session: AsyncSession):
        scan = ScanDB(
            id="scan-001",
            target="192.168.1.0/24",
            scan_method="active",
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:05:00Z",
            total_assets=10,
            is_root=0,
        )
        db_session.add(scan)
        await db_session.commit()

        result = await db_session.get(ScanDB, "scan-001")
        assert result is not None
        assert result.target == "192.168.1.0/24"
        assert result.total_assets == 10

    async def test_scan_with_scan_assets(self, db_session: AsyncSession):
        scan = ScanDB(
            id="scan-002", target="10.0.0.0/8", scan_method="passive",
            started_at="2026-01-01T00:00:00Z", total_assets=1, is_root=0,
        )
        asset = AssetDB(
            id="asset-001", ip="10.0.0.1", mac="aa:bb:cc:dd:ee:ff",
            bigr_category="iot", confidence_score=0.8, scan_method="passive",
            first_seen="2026-01-01T00:00:00Z", last_seen="2026-01-01T00:00:00Z",
        )
        sa = ScanAssetDB(
            scan_id="scan-002", asset_id="asset-001",
            open_ports=json.dumps([80, 443]), confidence_score=0.8,
            bigr_category="iot", raw_evidence=json.dumps({"vendor": "Hikvision"}),
        )
        db_session.add_all([scan, asset, sa])
        await db_session.commit()

        # Load via relationship
        from sqlalchemy.orm import selectinload

        stmt = select(ScanDB).where(ScanDB.id == "scan-002").options(
            selectinload(ScanDB.scan_assets).selectinload(ScanAssetDB.asset)
        )
        result = (await db_session.execute(stmt)).scalar_one()
        assert len(result.scan_assets) == 1
        assert result.scan_assets[0].asset.ip == "10.0.0.1"


class TestAssetDB:
    async def test_create_asset_all_fields(self, db_session: AsyncSession):
        asset = AssetDB(
            id="a-001", ip="192.168.1.1", mac="11:22:33:44:55:66",
            hostname="router.local", vendor="Cisco", os_hint="IOS",
            bigr_category="ag_ve_sistemler", confidence_score=0.9,
            scan_method="active", first_seen="2026-01-01T00:00:00Z",
            last_seen="2026-01-01T00:05:00Z",
            manual_category="ag_ve_sistemler", manual_note="Core router",
            is_ignored=0, switch_host="sw1.local", switch_port="Gi0/1",
            switch_port_index=1,
        )
        db_session.add(asset)
        await db_session.commit()

        result = await db_session.get(AssetDB, "a-001")
        assert result is not None
        assert result.hostname == "router.local"
        assert result.switch_host == "sw1.local"

    async def test_unique_constraint_ip_mac(self, db_session: AsyncSession):
        a1 = AssetDB(
            id="a-100", ip="10.0.0.1", mac="aa:bb:cc:dd:ee:ff",
            first_seen="2026-01-01T00:00:00Z", last_seen="2026-01-01T00:00:00Z",
        )
        a2 = AssetDB(
            id="a-101", ip="10.0.0.1", mac="aa:bb:cc:dd:ee:ff",
            first_seen="2026-01-01T00:00:00Z", last_seen="2026-01-01T00:00:00Z",
        )
        db_session.add(a1)
        await db_session.commit()
        db_session.add(a2)
        with pytest.raises(Exception):  # IntegrityError
            await db_session.commit()

    async def test_asset_with_changes(self, db_session: AsyncSession):
        scan = ScanDB(
            id="s-100", target="10.0.0.0/24", scan_method="passive",
            started_at="2026-01-01T00:00:00Z", total_assets=1, is_root=0,
        )
        asset = AssetDB(
            id="a-200", ip="10.0.0.5", first_seen="2026-01-01T00:00:00Z",
            last_seen="2026-01-01T00:00:00Z",
        )
        change = AssetChangeDB(
            asset_id="a-200", scan_id="s-100", change_type="new_asset",
            detected_at="2026-01-01T00:00:00Z",
        )
        db_session.add_all([scan, asset, change])
        await db_session.commit()

        from sqlalchemy.orm import selectinload

        stmt = select(AssetDB).where(AssetDB.id == "a-200").options(
            selectinload(AssetDB.asset_changes)
        )
        result = (await db_session.execute(stmt)).scalar_one()
        assert len(result.asset_changes) == 1
        assert result.asset_changes[0].change_type == "new_asset"


class TestScanAssetDB:
    async def test_json_fields(self, db_session: AsyncSession):
        scan = ScanDB(
            id="s-300", target="172.16.0.0/12", scan_method="hybrid",
            started_at="2026-01-01T00:00:00Z", total_assets=1, is_root=0,
        )
        asset = AssetDB(
            id="a-300", ip="172.16.0.1", first_seen="2026-01-01T00:00:00Z",
            last_seen="2026-01-01T00:00:00Z",
        )
        ports = [22, 80, 443, 8080]
        evidence = {"oui": "Dell Inc.", "mdns": {"name": "printer"}}
        sa = ScanAssetDB(
            scan_id="s-300", asset_id="a-300",
            open_ports=json.dumps(ports),
            confidence_score=0.75,
            bigr_category="uygulamalar",
            raw_evidence=json.dumps(evidence),
        )
        db_session.add_all([scan, asset, sa])
        await db_session.commit()

        stmt = select(ScanAssetDB).where(ScanAssetDB.scan_id == "s-300")
        result = (await db_session.execute(stmt)).scalar_one()
        assert json.loads(result.open_ports) == ports
        assert json.loads(result.raw_evidence) == evidence


class TestSubnetDB:
    async def test_create_subnet(self, db_session: AsyncSession):
        subnet = SubnetDB(cidr="192.168.1.0/24", label="Office", vlan_id=10)
        db_session.add(subnet)
        await db_session.commit()

        result = await db_session.get(SubnetDB, "192.168.1.0/24")
        assert result is not None
        assert result.label == "Office"
        assert result.vlan_id == 10


class TestSwitchDB:
    async def test_create_switch(self, db_session: AsyncSession):
        switch = SwitchDB(
            host="10.0.0.254", community="private", version="3",
            label="Core Switch", mac_count=150,
        )
        db_session.add(switch)
        await db_session.commit()

        result = await db_session.get(SwitchDB, "10.0.0.254")
        assert result is not None
        assert result.community == "private"
        assert result.mac_count == 150


class TestCertificateDB:
    async def test_create_certificate(self, db_session: AsyncSession):
        cert = CertificateDB(
            ip="10.0.0.1", port=443, cn="*.example.com",
            issuer="Let's Encrypt", issuer_org="ISRG",
            valid_from="2026-01-01", valid_to="2026-04-01",
            serial="ABCDEF123", key_size=2048, key_algorithm="RSA",
            is_self_signed=0, is_expired=0, days_until_expiry=90,
            san=json.dumps(["example.com", "*.example.com"]),
            last_checked="2026-01-01T00:00:00Z",
        )
        db_session.add(cert)
        await db_session.commit()

        stmt = select(CertificateDB).where(CertificateDB.ip == "10.0.0.1")
        result = (await db_session.execute(stmt)).scalar_one()
        assert result.cn == "*.example.com"
        assert json.loads(result.san) == ["example.com", "*.example.com"]

    async def test_unique_constraint_ip_port(self, db_session: AsyncSession):
        c1 = CertificateDB(
            ip="10.0.0.1", port=443, last_checked="2026-01-01T00:00:00Z",
        )
        c2 = CertificateDB(
            ip="10.0.0.1", port=443, last_checked="2026-01-02T00:00:00Z",
        )
        db_session.add(c1)
        await db_session.commit()
        db_session.add(c2)
        with pytest.raises(Exception):  # IntegrityError
            await db_session.commit()
