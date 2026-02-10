"""Tests for shield ingest persistence — ShieldScanDB + ShieldFindingDB."""

from __future__ import annotations

import json

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from bigr.agent.auth import generate_token, hash_token
from bigr.core.database import Base, get_db, get_engine, get_session_factory, reset_engine
from bigr.core.models_db import AgentDB, ShieldFindingDB, ShieldScanDB
from bigr.dashboard.app import create_app


@pytest.fixture(autouse=True)
async def setup_db():
    """Create a fresh in-memory database."""
    reset_engine()
    engine = get_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    reset_engine()


@pytest.fixture
def app():
    return create_app(data_path="/tmp/__nonexistent_bigr_test__.json")


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _register_agent(client: AsyncClient) -> tuple[str, str]:
    """Helper: register an agent and return (agent_id, token)."""
    body = {"name": "shield-test-agent", "site_name": "TestSite"}
    resp = await client.post("/api/agents/register", json=body)
    assert resp.status_code == 200
    data = resp.json()
    return data["agent_id"], data["token"]


@pytest.mark.asyncio
async def test_shield_ingest_persists_scan(client):
    """Shield ingest should create a ShieldScanDB row."""
    agent_id, token = await _register_agent(client)
    payload = {
        "target": "192.168.1.0/24",
        "started_at": "2026-02-10T14:00:00+00:00",
        "completed_at": "2026-02-10T14:05:00+00:00",
        "modules_run": ["port_scan", "cert_check"],
        "findings": [],
    }
    resp = await client.post(
        "/api/ingest/shield",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "scan_id" in body

    # Verify DB persistence
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(select(ShieldScanDB))
        scans = result.scalars().all()
        assert len(scans) == 1
        assert scans[0].target == "192.168.1.0/24"
        assert scans[0].agent_id == agent_id
        assert scans[0].site_name == "TestSite"
        modules = json.loads(scans[0].modules_run)
        assert modules == ["port_scan", "cert_check"]


@pytest.mark.asyncio
async def test_shield_ingest_persists_findings(client):
    """Shield ingest should create ShieldFindingDB rows for each finding."""
    _, token = await _register_agent(client)
    payload = {
        "target": "10.0.0.0/24",
        "started_at": "2026-02-10T14:00:00+00:00",
        "modules_run": ["port_scan"],
        "findings": [
            {
                "module": "port_scan",
                "severity": "high",
                "title": "Open SSH on non-standard port",
                "detail": "Port 2222 open with SSH",
                "target_ip": "10.0.0.5",
                "remediation": "Close port or restrict access",
            },
            {
                "module": "port_scan",
                "severity": "info",
                "title": "HTTP server detected",
                "target_ip": "10.0.0.10",
            },
        ],
    }
    resp = await client.post(
        "/api/ingest/shield",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["findings_count"] == 2

    # Verify findings in DB
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(select(ShieldFindingDB))
        findings = result.scalars().all()
        assert len(findings) == 2

        high = [f for f in findings if f.severity == "high"][0]
        assert high.module == "port_scan"
        assert high.title == "Open SSH on non-standard port"
        assert high.target_ip == "10.0.0.5"
        assert high.remediation == "Close port or restrict access"
        assert high.raw_data is not None  # JSON-encoded finding

        info = [f for f in findings if f.severity == "info"][0]
        assert info.title == "HTTP server detected"


@pytest.mark.asyncio
async def test_shield_ingest_no_findings(client):
    """Shield ingest with empty findings should still create scan row."""
    _, token = await _register_agent(client)
    payload = {
        "target": "172.16.0.0/16",
        "started_at": "2026-02-10T14:00:00+00:00",
        "modules_run": ["cert_check"],
        "findings": [],
    }
    resp = await client.post(
        "/api/ingest/shield",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["findings_count"] == 0

    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(select(ShieldScanDB))
        assert len(result.scalars().all()) == 1
        result = await session.execute(select(ShieldFindingDB))
        assert len(result.scalars().all()) == 0


@pytest.mark.asyncio
async def test_shield_ingest_requires_auth(client):
    """Shield ingest without token should be rejected."""
    payload = {
        "target": "10.0.0.0/24",
        "started_at": "2026-02-10T14:00:00+00:00",
        "modules_run": [],
        "findings": [],
    }
    resp = await client.post("/api/ingest/shield", json=payload)
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_shield_scan_links_to_agent(client):
    """Shield scan should be linked to the agent via foreign key."""
    agent_id, token = await _register_agent(client)
    payload = {
        "target": "192.168.5.0/24",
        "started_at": "2026-02-10T15:00:00+00:00",
        "modules_run": ["ssl_check"],
        "findings": [
            {"module": "ssl_check", "severity": "critical", "title": "Expired cert"},
        ],
    }
    resp = await client.post(
        "/api/ingest/shield",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    scan_id = resp.json()["scan_id"]

    # Verify scan-agent link and finding-scan link
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(ShieldScanDB).where(ShieldScanDB.id == scan_id)
        )
        scan = result.scalar_one()
        assert scan.agent_id == agent_id

        result = await session.execute(
            select(ShieldFindingDB).where(ShieldFindingDB.scan_id == scan_id)
        )
        finding = result.scalar_one()
        assert finding.severity == "critical"
        assert finding.title == "Expired cert"
