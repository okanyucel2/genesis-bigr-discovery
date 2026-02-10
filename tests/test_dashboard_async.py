"""Tests for the async dashboard API routes."""

from __future__ import annotations

import json

import pytest
from httpx import ASGITransport, AsyncClient

from bigr.core.database import Base, get_db, get_engine, get_session_factory, reset_engine
from bigr.core.models_db import (
    AssetChangeDB,
    AssetDB,
    CertificateDB,
    ScanAssetDB,
    ScanDB,
    SubnetDB,
    SwitchDB,
)
from bigr.dashboard.app import create_app


@pytest.fixture(autouse=True)
async def setup_db():
    """Create a fresh in-memory database and override get_db for the app."""
    reset_engine()
    engine = get_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    reset_engine()


@pytest.fixture
async def seeded_db(setup_db):
    """Seed test data into the database."""
    factory = get_session_factory()
    async with factory() as session:
        scan = ScanDB(
            id="scan-t1", target="10.0.0.0/24", scan_method="active",
            started_at="2026-01-15T10:00:00Z",
            completed_at="2026-01-15T10:05:00Z",
            total_assets=2, is_root=0,
        )
        a1 = AssetDB(
            id="a-t1", ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01",
            hostname="gw.local", vendor="Cisco", os_hint="IOS",
            bigr_category="ag_ve_sistemler", confidence_score=0.9,
            scan_method="active",
            first_seen="2026-01-15T10:00:00Z", last_seen="2026-01-15T10:00:00Z",
        )
        a2 = AssetDB(
            id="a-t2", ip="10.0.0.100", mac="aa:bb:cc:dd:ee:02",
            hostname="cam.local", vendor="Hikvision",
            bigr_category="iot", confidence_score=0.75,
            scan_method="active",
            first_seen="2026-01-15T10:00:00Z", last_seen="2026-01-15T10:00:00Z",
        )
        sa1 = ScanAssetDB(
            scan_id="scan-t1", asset_id="a-t1",
            open_ports=json.dumps([22, 443]), confidence_score=0.9,
            bigr_category="ag_ve_sistemler",
        )
        sa2 = ScanAssetDB(
            scan_id="scan-t1", asset_id="a-t2",
            open_ports=json.dumps([80]), confidence_score=0.75,
            bigr_category="iot",
        )
        change = AssetChangeDB(
            asset_id="a-t1", scan_id="scan-t1",
            change_type="new_asset", detected_at="2026-01-15T10:00:00Z",
        )
        subnet = SubnetDB(cidr="10.0.0.0/24", label="Office", vlan_id=10)
        switch = SwitchDB(host="10.0.0.254", label="Core")
        cert = CertificateDB(
            ip="10.0.0.1", port=443, cn="gw.local",
            is_self_signed=1, is_expired=0, days_until_expiry=90,
            san=json.dumps(["gw.local"]),
            last_checked="2026-01-15T10:00:00Z",
        )
        session.add_all([scan, a1, a2, sa1, sa2, change, subnet, switch, cert])
        await session.commit()


@pytest.fixture
def app():
    """Create the dashboard app pointing at a non-existent data file."""
    return create_app(data_path="/tmp/__nonexistent_bigr_test__.json")


@pytest.fixture
async def client(app):
    """Async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestHealthEndpoint:
    async def test_health_returns_200(self, client: AsyncClient, setup_db):
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["database"]["status"] == "connected"
        assert data["database"]["type"] == "sqlite"


class TestDataEndpoint:
    async def test_empty_db_returns_empty(self, client: AsyncClient, setup_db):
        resp = await client.get("/api/data")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("assets") is not None

    async def test_with_seeded_data(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/data")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data.get("assets", [])) == 2

    async def test_subnet_filter(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/data?subnet=10.0.0.0/24")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data.get("assets", [])) == 2

        # Non-matching subnet
        resp = await client.get("/api/data?subnet=192.168.1.0/24")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data.get("assets", [])) == 0


class TestScansEndpoint:
    async def test_scans_empty(self, client: AsyncClient, setup_db):
        resp = await client.get("/api/scans")
        assert resp.status_code == 200
        assert resp.json()["scans"] == []

    async def test_scans_with_data(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/scans")
        assert resp.status_code == 200
        scans = resp.json()["scans"]
        assert len(scans) == 1
        assert scans[0]["id"] == "scan-t1"


class TestAssetDetailEndpoint:
    async def test_asset_found(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/assets/10.0.0.1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["asset"]["ip"] == "10.0.0.1"
        assert len(data["history"]) == 1

    async def test_asset_not_found(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/assets/99.99.99.99")
        assert resp.status_code == 404


class TestChangesEndpoint:
    async def test_changes_with_data(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/changes")
        assert resp.status_code == 200
        changes = resp.json()["changes"]
        assert len(changes) >= 1
        assert changes[0]["change_type"] == "new_asset"


class TestSubnetsEndpoint:
    async def test_subnets_with_data(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/subnets")
        assert resp.status_code == 200
        subnets = resp.json()["subnets"]
        assert len(subnets) == 1
        assert subnets[0]["cidr"] == "10.0.0.0/24"


class TestSwitchesEndpoint:
    async def test_switches_with_data(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/switches")
        assert resp.status_code == 200
        switches = resp.json()["switches"]
        assert len(switches) == 1


class TestCertificatesEndpoint:
    async def test_certificates_with_data(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/certificates")
        assert resp.status_code == 200
        certs = resp.json()["certificates"]
        assert len(certs) == 1
        assert certs[0]["cn"] == "gw.local"
        assert certs[0]["san"] == ["gw.local"]


class TestDashboardPage:
    async def test_dashboard_html(self, client: AsyncClient, seeded_db):
        resp = await client.get("/")
        assert resp.status_code == 200
        assert "BIGR Discovery Dashboard" in resp.text
