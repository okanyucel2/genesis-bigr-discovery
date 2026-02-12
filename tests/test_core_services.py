"""Tests for bigr.core.services async service layer."""

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
from bigr.core import services


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


async def _seed_scan_with_assets(session: AsyncSession) -> str:
    """Helper: insert a scan with 2 assets. Returns scan_id."""
    scan = ScanDB(
        id="scan-seed",
        target="192.168.1.0/24",
        scan_method="active",
        started_at="2026-01-15T10:00:00Z",
        completed_at="2026-01-15T10:05:00Z",
        total_assets=2,
        is_root=0,
    )
    a1 = AssetDB(
        id="a-1", ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01",
        hostname="router.local", vendor="Cisco", os_hint="IOS",
        bigr_category="ag_ve_sistemler", confidence_score=0.9,
        scan_method="active",
        first_seen="2026-01-15T10:00:00Z", last_seen="2026-01-15T10:00:00Z",
    )
    a2 = AssetDB(
        id="a-2", ip="192.168.1.100", mac="aa:bb:cc:dd:ee:02",
        hostname="printer.local", vendor="HP", os_hint="JetDirect",
        bigr_category="iot", confidence_score=0.75,
        scan_method="active",
        first_seen="2026-01-15T10:00:00Z", last_seen="2026-01-15T10:00:00Z",
    )
    sa1 = ScanAssetDB(
        scan_id="scan-seed", asset_id="a-1",
        open_ports=json.dumps([22, 443]), confidence_score=0.9,
        bigr_category="ag_ve_sistemler",
        raw_evidence=json.dumps({"oui": "Cisco"}),
    )
    sa2 = ScanAssetDB(
        scan_id="scan-seed", asset_id="a-2",
        open_ports=json.dumps([9100]), confidence_score=0.75,
        bigr_category="iot",
        raw_evidence=json.dumps({"mdns": "printer"}),
    )
    change = AssetChangeDB(
        asset_id="a-1", scan_id="scan-seed",
        change_type="new_asset", detected_at="2026-01-15T10:00:00Z",
    )
    session.add_all([scan, a1, a2, sa1, sa2, change])
    await session.commit()
    return "scan-seed"


# ---------------------------------------------------------------------------
# Read operation tests
# ---------------------------------------------------------------------------

class TestGetLatestScan:
    async def test_returns_none_on_empty_db(self, db_session):
        result = await services.get_latest_scan(db_session)
        assert result is None

    async def test_returns_scan_with_assets(self, db_session):
        await _seed_scan_with_assets(db_session)
        result = await services.get_latest_scan(db_session)
        assert result is not None
        assert result["id"] == "scan-seed"
        assert result["target"] == "192.168.1.0/24"
        assert len(result["assets"]) == 2
        assert "category_summary" in result
        assert result["is_root"] is False

    async def test_filter_by_target(self, db_session):
        await _seed_scan_with_assets(db_session)
        result = await services.get_latest_scan(db_session, target="10.0.0.0/8")
        assert result is None

        result = await services.get_latest_scan(db_session, target="192.168.1.0/24")
        assert result is not None


class TestGetAllAssets:
    async def test_empty_db(self, db_session):
        result = await services.get_all_assets(db_session)
        assert result == []

    async def test_returns_all_assets(self, db_session):
        await _seed_scan_with_assets(db_session)
        result = await services.get_all_assets(db_session)
        assert len(result) == 2
        ips = {a["ip"] for a in result}
        assert "192.168.1.1" in ips
        assert "192.168.1.100" in ips

    async def test_dict_keys_match_db_py(self, db_session):
        await _seed_scan_with_assets(db_session)
        result = await services.get_all_assets(db_session)
        expected_keys = {
            "id", "ip", "mac", "hostname", "vendor", "os_hint",
            "bigr_category", "confidence_score", "scan_method",
            "first_seen", "last_seen", "sensitivity_level",
            "manual_category", "manual_note",
            "is_ignored", "switch_host", "switch_port", "switch_port_index",
            "agent_id", "site_name", "network_id",
            "friendly_name", "device_model", "device_manufacturer",
        }
        assert set(result[0].keys()) == expected_keys


class TestGetScanList:
    async def test_empty_db(self, db_session):
        result = await services.get_scan_list(db_session)
        assert result == []

    async def test_returns_metadata_only(self, db_session):
        await _seed_scan_with_assets(db_session)
        result = await services.get_scan_list(db_session)
        assert len(result) == 1
        assert "assets" not in result[0]
        assert result[0]["id"] == "scan-seed"

    async def test_respects_limit(self, db_session):
        for i in range(5):
            session = db_session
            session.add(ScanDB(
                id=f"s-{i}", target="10.0.0.0/8", scan_method="passive",
                started_at=f"2026-01-{i+10}T00:00:00Z", total_assets=0, is_root=0,
            ))
        await db_session.commit()
        result = await services.get_scan_list(db_session, limit=3)
        assert len(result) == 3


class TestGetAssetHistory:
    async def test_no_filter_returns_empty(self, db_session):
        result = await services.get_asset_history(db_session)
        assert result == []

    async def test_by_ip(self, db_session):
        await _seed_scan_with_assets(db_session)
        result = await services.get_asset_history(db_session, ip="192.168.1.1")
        assert len(result) == 1
        assert result[0]["ip"] == "192.168.1.1"
        assert result[0]["target"] == "192.168.1.0/24"

    async def test_by_ip_not_found(self, db_session):
        await _seed_scan_with_assets(db_session)
        result = await services.get_asset_history(db_session, ip="10.10.10.10")
        assert result == []


class TestGetTags:
    async def test_no_tagged_assets(self, db_session):
        await _seed_scan_with_assets(db_session)
        result = await services.get_tags_async(db_session)
        assert result == []

    async def test_tagged_asset_returned(self, db_session):
        await _seed_scan_with_assets(db_session)
        await services.tag_asset_async(db_session, "192.168.1.1", "ag_ve_sistemler", "Router")
        result = await services.get_tags_async(db_session)
        assert len(result) == 1
        assert result[0]["ip"] == "192.168.1.1"
        assert result[0]["manual_category"] == "ag_ve_sistemler"


class TestGetSubnets:
    async def test_empty(self, db_session):
        result = await services.get_subnets_async(db_session)
        assert result == []

    async def test_returns_subnets(self, db_session):
        db_session.add(SubnetDB(cidr="10.0.0.0/8", label="Corp", vlan_id=10))
        db_session.add(SubnetDB(cidr="192.168.1.0/24", label="Office"))
        await db_session.commit()
        result = await services.get_subnets_async(db_session)
        assert len(result) == 2
        assert result[0]["cidr"] == "10.0.0.0/8"  # alphabetical order


class TestGetSwitches:
    async def test_empty(self, db_session):
        result = await services.get_switches_async(db_session)
        assert result == []

    async def test_returns_switches(self, db_session):
        db_session.add(SwitchDB(host="10.0.0.254", label="Core"))
        await db_session.commit()
        result = await services.get_switches_async(db_session)
        assert len(result) == 1
        assert result[0]["host"] == "10.0.0.254"


class TestGetCertificates:
    async def test_empty(self, db_session):
        result = await services.get_certificates_async(db_session)
        assert result == []

    async def test_with_san_json(self, db_session):
        db_session.add(CertificateDB(
            ip="10.0.0.1", port=443, cn="*.example.com",
            san=json.dumps(["example.com", "*.example.com"]),
            is_self_signed=0, is_expired=0,
            last_checked="2026-01-01T00:00:00Z",
        ))
        await db_session.commit()
        result = await services.get_certificates_async(db_session)
        assert len(result) == 1
        assert result[0]["san"] == ["example.com", "*.example.com"]
        assert result[0]["is_self_signed"] is False


class TestGetExpiringCerts:
    async def test_filters_by_days(self, db_session):
        db_session.add(CertificateDB(
            ip="10.0.0.1", port=443, days_until_expiry=10,
            is_self_signed=0, is_expired=0,
            last_checked="2026-01-01T00:00:00Z",
        ))
        db_session.add(CertificateDB(
            ip="10.0.0.2", port=443, days_until_expiry=60,
            is_self_signed=0, is_expired=0,
            last_checked="2026-01-01T00:00:00Z",
        ))
        await db_session.commit()

        result = await services.get_expiring_certs_async(db_session, days=30)
        assert len(result) == 1
        assert result[0]["ip"] == "10.0.0.1"


class TestGetChanges:
    async def test_returns_changes_with_asset_info(self, db_session):
        await _seed_scan_with_assets(db_session)
        result = await services.get_changes_async(db_session)
        assert len(result) == 1
        assert result[0]["change_type"] == "new_asset"
        assert result[0]["ip"] == "192.168.1.1"


# ---------------------------------------------------------------------------
# Write operation tests
# ---------------------------------------------------------------------------

class TestSaveScan:
    async def test_creates_scan_and_assets(self, db_session):
        scan_data = {
            "target": "10.0.0.0/24",
            "scan_method": "passive",
            "started_at": "2026-02-01T12:00:00Z",
            "completed_at": "2026-02-01T12:01:00Z",
            "is_root": False,
            "assets": [
                {
                    "ip": "10.0.0.1",
                    "mac": "ff:ff:ff:00:00:01",
                    "hostname": "gw.local",
                    "vendor": "Ubiquiti",
                    "bigr_category": "ag_ve_sistemler",
                    "confidence_score": 0.85,
                    "scan_method": "passive",
                    "open_ports": [22, 80],
                    "raw_evidence": {"oui": "Ubiquiti"},
                },
            ],
        }
        scan_id = await services.save_scan_async(db_session, scan_data)
        assert scan_id is not None

        # Verify scan
        scan = await db_session.get(ScanDB, scan_id)
        assert scan.target == "10.0.0.0/24"
        assert scan.total_assets == 1

        # Verify asset
        stmt = select(AssetDB).where(AssetDB.ip == "10.0.0.1")
        asset = (await db_session.execute(stmt)).scalar_one()
        assert asset.hostname == "gw.local"

        # Verify scan_asset
        stmt = select(ScanAssetDB).where(ScanAssetDB.scan_id == scan_id)
        sa = (await db_session.execute(stmt)).scalar_one()
        assert json.loads(sa.open_ports) == [22, 80]

        # Verify new_asset change logged
        stmt = select(AssetChangeDB).where(AssetChangeDB.asset_id == asset.id)
        change = (await db_session.execute(stmt)).scalar_one()
        assert change.change_type == "new_asset"

    async def test_upsert_detects_field_changes(self, db_session):
        # First scan
        scan1 = {
            "target": "10.0.0.0/24",
            "scan_method": "passive",
            "started_at": "2026-02-01T12:00:00Z",
            "assets": [
                {
                    "ip": "10.0.0.1",
                    "mac": "ff:ff:ff:00:00:01",
                    "hostname": "old-name",
                    "bigr_category": "unclassified",
                    "confidence_score": 0.3,
                },
            ],
        }
        await services.save_scan_async(db_session, scan1)

        # Second scan with changed hostname
        scan2 = {
            "target": "10.0.0.0/24",
            "scan_method": "active",
            "started_at": "2026-02-01T13:00:00Z",
            "assets": [
                {
                    "ip": "10.0.0.1",
                    "mac": "ff:ff:ff:00:00:01",
                    "hostname": "new-name",
                    "bigr_category": "ag_ve_sistemler",
                    "confidence_score": 0.9,
                },
            ],
        }
        await services.save_scan_async(db_session, scan2)

        # Verify hostname updated
        stmt = select(AssetDB).where(AssetDB.ip == "10.0.0.1")
        asset = (await db_session.execute(stmt)).scalar_one()
        assert asset.hostname == "new-name"

        # Verify field_changed logged (hostname + bigr_category + confidence + scan_method)
        stmt = (
            select(AssetChangeDB)
            .where(
                AssetChangeDB.asset_id == asset.id,
                AssetChangeDB.change_type == "field_changed",
            )
        )
        changes = (await db_session.execute(stmt)).scalars().all()
        changed_fields = {c.field_name for c in changes}
        assert "hostname" in changed_fields
        assert "bigr_category" in changed_fields


class TestTagUntag:
    async def test_tag_and_untag(self, db_session):
        await _seed_scan_with_assets(db_session)

        await services.tag_asset_async(db_session, "192.168.1.1", "ag_ve_sistemler", "Core router")

        stmt = select(AssetDB).where(AssetDB.ip == "192.168.1.1")
        asset = (await db_session.execute(stmt)).scalar_one()
        assert asset.manual_category == "ag_ve_sistemler"
        assert asset.manual_note == "Core router"

        await services.untag_asset_async(db_session, "192.168.1.1")

        await db_session.refresh(asset)
        assert asset.manual_category is None
        assert asset.manual_note is None


class TestUpdateSensitivity:
    async def test_update_existing_asset(self, db_session):
        await _seed_scan_with_assets(db_session)

        updated = await services.update_asset_sensitivity(db_session, "192.168.1.1", "fragile")
        assert updated is True

        stmt = select(AssetDB).where(AssetDB.ip == "192.168.1.1")
        asset = (await db_session.execute(stmt)).scalar_one()
        assert asset.sensitivity_level == "fragile"

    async def test_update_nonexistent_returns_false(self, db_session):
        updated = await services.update_asset_sensitivity(db_session, "10.10.10.10", "safe")
        assert updated is False


class TestSubnetOps:
    async def test_add_and_remove(self, db_session):
        await services.add_subnet_async(db_session, "10.0.0.0/8", "Corp", 100)

        result = await services.get_subnets_async(db_session)
        assert len(result) == 1
        assert result[0]["label"] == "Corp"
        assert result[0]["vlan_id"] == 100

        # Upsert
        await services.add_subnet_async(db_session, "10.0.0.0/8", "Corporate", 200)
        result = await services.get_subnets_async(db_session)
        assert len(result) == 1
        assert result[0]["label"] == "Corporate"
        assert result[0]["vlan_id"] == 200

        # Remove
        await services.remove_subnet_async(db_session, "10.0.0.0/8")
        result = await services.get_subnets_async(db_session)
        assert len(result) == 0


class TestCertificateOps:
    async def test_save_and_upsert(self, db_session):
        cert = {
            "ip": "10.0.0.1",
            "port": 443,
            "cn": "old.example.com",
            "issuer": "Let's Encrypt",
            "san": ["old.example.com"],
            "is_self_signed": False,
            "is_expired": False,
            "days_until_expiry": 90,
        }
        await services.save_certificate_async(db_session, cert)

        result = await services.get_certificates_async(db_session)
        assert len(result) == 1
        assert result[0]["cn"] == "old.example.com"

        # Upsert on same ip+port
        cert["cn"] = "new.example.com"
        cert["san"] = ["new.example.com"]
        await services.save_certificate_async(db_session, cert)

        result = await services.get_certificates_async(db_session)
        assert len(result) == 1
        assert result[0]["cn"] == "new.example.com"
