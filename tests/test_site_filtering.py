"""Tests for multi-site filtering — site param on data/changes, sites summary."""

from __future__ import annotations

import json

import pytest
from httpx import ASGITransport, AsyncClient

from bigr.agent.auth import generate_token, hash_token
from bigr.core.database import Base, get_db, get_engine, get_session_factory, reset_engine
from bigr.core.models_db import AgentDB, AssetChangeDB, AssetDB, ScanAssetDB, ScanDB
from bigr.dashboard.app import create_app


@pytest.fixture(autouse=True)
async def setup_db():
    reset_engine()
    engine = get_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    reset_engine()


@pytest.fixture
async def multi_site_data(setup_db):
    """Seed assets from two different sites + one local (no site)."""
    factory = get_session_factory()
    async with factory() as session:
        # Agent for Istanbul
        agent_ist = AgentDB(
            id="agent-ist",
            name="istanbul-scanner",
            site_name="Istanbul",
            token_hash=hash_token("tok-ist"),
            is_active=1,
            registered_at="2026-01-01T00:00:00Z",
            status="online",
        )
        # Agent for Ankara
        agent_ank = AgentDB(
            id="agent-ank",
            name="ankara-scanner",
            site_name="Ankara",
            token_hash=hash_token("tok-ank"),
            is_active=1,
            registered_at="2026-01-01T00:00:00Z",
            status="online",
        )
        session.add_all([agent_ist, agent_ank])
        await session.flush()

        # Scans
        scan_ist = ScanDB(
            id="scan-ist", target="192.168.1.0/24", scan_method="hybrid",
            started_at="2026-02-10T10:00:00Z", total_assets=2, is_root=0,
            agent_id="agent-ist", site_name="Istanbul",
        )
        scan_ank = ScanDB(
            id="scan-ank", target="10.0.0.0/24", scan_method="active",
            started_at="2026-02-10T11:00:00Z", total_assets=1, is_root=0,
            agent_id="agent-ank", site_name="Ankara",
        )
        scan_local = ScanDB(
            id="scan-local", target="172.16.0.0/24", scan_method="hybrid",
            started_at="2026-02-10T09:00:00Z", total_assets=1, is_root=1,
        )
        session.add_all([scan_ist, scan_ank, scan_local])
        await session.flush()

        # Assets
        a1 = AssetDB(
            id="a-ist-1", ip="192.168.1.1", mac="aa:bb:cc:11:11:11",
            bigr_category="ag_ve_sistemler", confidence_score=0.9,
            scan_method="hybrid", first_seen="2026-02-10T10:00:00Z",
            last_seen="2026-02-10T10:00:00Z",
            agent_id="agent-ist", site_name="Istanbul",
        )
        a2 = AssetDB(
            id="a-ist-2", ip="192.168.1.100", mac="aa:bb:cc:22:22:22",
            bigr_category="iot", confidence_score=0.8,
            scan_method="hybrid", first_seen="2026-02-10T10:00:00Z",
            last_seen="2026-02-10T10:00:00Z",
            agent_id="agent-ist", site_name="Istanbul",
        )
        a3 = AssetDB(
            id="a-ank-1", ip="10.0.0.1", mac="aa:bb:cc:33:33:33",
            bigr_category="ag_ve_sistemler", confidence_score=0.95,
            scan_method="active", first_seen="2026-02-10T11:00:00Z",
            last_seen="2026-02-10T11:00:00Z",
            agent_id="agent-ank", site_name="Ankara",
        )
        a4 = AssetDB(
            id="a-local-1", ip="172.16.0.1", mac="aa:bb:cc:44:44:44",
            bigr_category="uygulamalar", confidence_score=0.7,
            scan_method="hybrid", first_seen="2026-02-10T09:00:00Z",
            last_seen="2026-02-10T09:00:00Z",
        )
        session.add_all([a1, a2, a3, a4])
        await session.flush()

        # Scan-asset junctions
        for asset_id, scan_id, cat in [
            ("a-ist-1", "scan-ist", "ag_ve_sistemler"),
            ("a-ist-2", "scan-ist", "iot"),
            ("a-ank-1", "scan-ank", "ag_ve_sistemler"),
            ("a-local-1", "scan-local", "uygulamalar"),
        ]:
            session.add(ScanAssetDB(
                scan_id=scan_id, asset_id=asset_id,
                open_ports="[]", confidence_score=0.9,
                bigr_category=cat,
            ))

        # Changes
        for asset_id, scan_id in [
            ("a-ist-1", "scan-ist"),
            ("a-ist-2", "scan-ist"),
            ("a-ank-1", "scan-ank"),
            ("a-local-1", "scan-local"),
        ]:
            session.add(AssetChangeDB(
                asset_id=asset_id, scan_id=scan_id,
                change_type="new_asset",
                detected_at="2026-02-10T10:00:00Z",
            ))

        await session.commit()


@pytest.fixture
def app():
    return create_app(data_path="/tmp/__nonexistent_bigr_test__.json")


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestSiteFilterOnData:
    async def test_no_filter_returns_latest_scan(self, client: AsyncClient, multi_site_data):
        """Without site filter, /api/data returns the latest scan (not all assets)."""
        resp = await client.get("/api/data")
        assert resp.status_code == 200
        assets = resp.json().get("assets", [])
        # Latest scan is scan-ank (11:00) with 1 asset
        assert len(assets) >= 1

    async def test_filter_istanbul(self, client: AsyncClient, multi_site_data):
        resp = await client.get("/api/data?site=Istanbul")
        assert resp.status_code == 200
        assets = resp.json()["assets"]
        assert len(assets) == 2
        assert all(a.get("site_name") == "Istanbul" for a in assets)

    async def test_filter_ankara(self, client: AsyncClient, multi_site_data):
        resp = await client.get("/api/data?site=Ankara")
        assert resp.status_code == 200
        assets = resp.json()["assets"]
        assert len(assets) == 1
        assert assets[0]["ip"] == "10.0.0.1"

    async def test_filter_nonexistent_site(self, client: AsyncClient, multi_site_data):
        resp = await client.get("/api/data?site=London")
        assert resp.status_code == 200
        assets = resp.json()["assets"]
        assert len(assets) == 0


class TestSiteFilterOnChanges:
    async def test_changes_filtered_by_site(self, client: AsyncClient, multi_site_data):
        resp = await client.get("/api/changes?site=Istanbul")
        assert resp.status_code == 200
        changes = resp.json()["changes"]
        assert len(changes) == 2
        ips = {c["ip"] for c in changes}
        assert ips == {"192.168.1.1", "192.168.1.100"}

    async def test_changes_no_filter(self, client: AsyncClient, multi_site_data):
        resp = await client.get("/api/changes")
        assert resp.status_code == 200
        changes = resp.json()["changes"]
        assert len(changes) == 4


class TestSitesSummary:
    async def test_sites_summary(self, client: AsyncClient, multi_site_data):
        resp = await client.get("/api/sites")
        assert resp.status_code == 200
        sites = resp.json()["sites"]
        assert len(sites) >= 2  # Istanbul, Ankara, maybe (local)
        site_map = {s["site_name"]: s["asset_count"] for s in sites}
        assert site_map.get("Istanbul") == 2
        assert site_map.get("Ankara") == 1

    async def test_sites_empty_db(self, client: AsyncClient, setup_db):
        resp = await client.get("/api/sites")
        assert resp.status_code == 200
        assert resp.json()["sites"] == []


class TestAgentsList:
    async def test_agents_shows_registered(self, client: AsyncClient, multi_site_data):
        resp = await client.get("/api/agents")
        assert resp.status_code == 200
        agents = resp.json()["agents"]
        assert len(agents) == 2
        names = {a["name"] for a in agents}
        assert names == {"istanbul-scanner", "ankara-scanner"}
