"""Tests for agent API routes — registration, heartbeat, ingest, list."""

from __future__ import annotations

import json
import os

import pytest
from httpx import ASGITransport, AsyncClient

from bigr.agent.auth import generate_token, hash_token
from bigr.core.database import Base, get_db, get_engine, get_session_factory, reset_engine
from bigr.core.models_db import AgentDB, AssetDB, ScanDB
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


async def _register_agent(
    client: AsyncClient,
    name: str = "test-scanner",
    site_name: str = "HQ",
    secret: str | None = None,
) -> tuple[str, str]:
    """Helper: register an agent and return (agent_id, token)."""
    body: dict = {"name": name, "site_name": site_name}
    if secret is not None:
        body["secret"] = secret
    resp = await client.post("/api/agents/register", json=body)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return data["agent_id"], data["token"]


class TestAgentRegistration:
    async def test_register_returns_agent_id_and_token(self, client: AsyncClient):
        agent_id, token = await _register_agent(client)
        assert agent_id  # non-empty UUID
        assert len(token) == 64  # hex token

    async def test_register_with_subnets(self, client: AsyncClient):
        resp = await client.post("/api/agents/register", json={
            "name": "multi-site",
            "site_name": "Branch",
            "subnets": ["192.168.1.0/24", "10.0.0.0/16"],
        })
        assert resp.status_code == 200

    async def test_register_requires_name(self, client: AsyncClient):
        resp = await client.post("/api/agents/register", json={
            "site_name": "HQ",
        })
        assert resp.status_code == 422  # validation error

    async def test_register_with_correct_secret(self, client: AsyncClient, monkeypatch):
        monkeypatch.setenv("AGENT_REGISTRATION_SECRET", "my-secret-key")
        # Re-create settings to pick up env var
        from bigr.core.settings import Settings
        new_settings = Settings()
        monkeypatch.setattr("bigr.agent.routes.settings", new_settings)

        agent_id, token = await _register_agent(client, secret="my-secret-key")
        assert agent_id

    async def test_register_with_wrong_secret_returns_403(self, client: AsyncClient, monkeypatch):
        monkeypatch.setenv("AGENT_REGISTRATION_SECRET", "my-secret-key")
        from bigr.core.settings import Settings
        new_settings = Settings()
        monkeypatch.setattr("bigr.agent.routes.settings", new_settings)

        resp = await client.post("/api/agents/register", json={
            "name": "bad-agent",
            "secret": "wrong-secret",
        })
        assert resp.status_code == 403


class TestTokenRotation:
    async def test_rotate_returns_new_token(self, client: AsyncClient):
        _, old_token = await _register_agent(client)
        resp = await client.post(
            "/api/agents/rotate-token",
            headers={"Authorization": f"Bearer {old_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data
        assert data["token"] != old_token
        assert len(data["token"]) == 64

    async def test_old_token_invalid_after_rotation(self, client: AsyncClient):
        _, old_token = await _register_agent(client)
        resp = await client.post(
            "/api/agents/rotate-token",
            headers={"Authorization": f"Bearer {old_token}"},
        )
        new_token = resp.json()["token"]
        # Old token should no longer work
        resp2 = await client.post(
            "/api/agents/heartbeat",
            json={"status": "online"},
            headers={"Authorization": f"Bearer {old_token}"},
        )
        assert resp2.status_code in (401, 403)
        # New token should work
        resp3 = await client.post(
            "/api/agents/heartbeat",
            json={"status": "online"},
            headers={"Authorization": f"Bearer {new_token}"},
        )
        assert resp3.status_code == 200

    async def test_rotate_requires_auth(self, client: AsyncClient):
        resp = await client.post("/api/agents/rotate-token")
        assert resp.status_code in (401, 403)


class TestAgentHeartbeat:
    async def test_heartbeat_updates_last_seen(self, client: AsyncClient):
        agent_id, token = await _register_agent(client)
        resp = await client.post(
            "/api/agents/heartbeat",
            json={"status": "online", "version": "0.1.0"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_id"] == agent_id
        assert data["last_seen"]

    async def test_heartbeat_with_subnets(self, client: AsyncClient):
        _, token = await _register_agent(client)
        resp = await client.post(
            "/api/agents/heartbeat",
            json={"status": "scanning", "subnets": ["10.0.0.0/24"]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200


class TestAgentList:
    async def test_list_empty(self, client: AsyncClient):
        resp = await client.get("/api/agents")
        assert resp.status_code == 200
        assert resp.json()["agents"] == []

    async def test_list_shows_registered_agents(self, client: AsyncClient):
        await _register_agent(client, name="scanner-1", site_name="Istanbul")
        await _register_agent(client, name="scanner-2", site_name="Ankara")

        resp = await client.get("/api/agents")
        assert resp.status_code == 200
        agents = resp.json()["agents"]
        assert len(agents) == 2
        names = {a["name"] for a in agents}
        assert names == {"scanner-1", "scanner-2"}

    async def test_list_shows_site_info(self, client: AsyncClient):
        await _register_agent(client, name="hq-agent", site_name="HQ Office")
        resp = await client.get("/api/agents")
        agents = resp.json()["agents"]
        assert agents[0]["site_name"] == "HQ Office"


class TestIngestDiscovery:
    async def test_ingest_creates_scan_and_assets(self, client: AsyncClient):
        agent_id, token = await _register_agent(client)
        payload = {
            "target": "192.168.1.0/24",
            "scan_method": "hybrid",
            "started_at": "2026-02-10T12:00:00Z",
            "completed_at": "2026-02-10T12:05:00Z",
            "is_root": True,
            "assets": [
                {
                    "ip": "192.168.1.1",
                    "mac": "aa:bb:cc:dd:ee:01",
                    "hostname": "router.local",
                    "vendor": "Cisco",
                    "bigr_category": "ag_ve_sistemler",
                    "confidence_score": 0.95,
                    "scan_method": "active",
                    "open_ports": [22, 80, 443],
                },
                {
                    "ip": "192.168.1.100",
                    "mac": "aa:bb:cc:dd:ee:02",
                    "hostname": "cam.local",
                    "vendor": "Hikvision",
                    "bigr_category": "iot",
                    "confidence_score": 0.8,
                    "scan_method": "active",
                    "open_ports": [80, 554],
                },
            ],
        }
        resp = await client.post(
            "/api/ingest/discovery",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["scan_id"]
        assert data["assets_ingested"] == 2

    async def test_ingest_tags_scan_with_agent_and_site(self, client: AsyncClient):
        """Verify that ingested scans have agent_id and site_name set."""
        agent_id, token = await _register_agent(client, site_name="Istanbul")
        payload = {
            "target": "10.0.0.0/24",
            "scan_method": "active",
            "started_at": "2026-02-10T13:00:00Z",
            "assets": [
                {"ip": "10.0.0.1", "mac": "11:22:33:44:55:66"},
            ],
        }
        resp = await client.post(
            "/api/ingest/discovery",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        scan_id = resp.json()["scan_id"]

        # Verify in DB
        factory = get_session_factory()
        async with factory() as session:
            from sqlalchemy import select
            scan = (await session.execute(
                select(ScanDB).where(ScanDB.id == scan_id)
            )).scalar_one()
            assert scan.agent_id == agent_id
            assert scan.site_name == "Istanbul"

            asset = (await session.execute(
                select(AssetDB).where(AssetDB.ip == "10.0.0.1")
            )).scalar_one()
            assert asset.agent_id == agent_id
            assert asset.site_name == "Istanbul"

    async def test_ingest_without_token_returns_401(self, client: AsyncClient):
        resp = await client.post("/api/ingest/discovery", json={
            "target": "10.0.0.0/24",
            "started_at": "2026-02-10T12:00:00Z",
        })
        assert resp.status_code in (401, 403)

    async def test_ingest_empty_assets(self, client: AsyncClient):
        _, token = await _register_agent(client)
        resp = await client.post(
            "/api/ingest/discovery",
            json={
                "target": "10.0.0.0/24",
                "started_at": "2026-02-10T12:00:00Z",
                "assets": [],
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["assets_ingested"] == 0


class TestIngestShield:
    async def test_ingest_shield_accepted(self, client: AsyncClient):
        _, token = await _register_agent(client)
        payload = {
            "target": "192.168.1.0/24",
            "started_at": "2026-02-10T14:00:00Z",
            "modules_run": ["port_scan", "ssl_check"],
            "findings": [
                {"module": "port_scan", "severity": "medium", "detail": "Port 23 open"},
                {"module": "ssl_check", "severity": "high", "detail": "Expired cert"},
            ],
        }
        resp = await client.post(
            "/api/ingest/shield",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["findings_count"] == 2
        assert data["modules_received"] == ["port_scan", "ssl_check"]

    async def test_ingest_shield_without_token_returns_401(self, client: AsyncClient):
        resp = await client.post("/api/ingest/shield", json={
            "target": "10.0.0.0/24",
            "started_at": "2026-02-10T14:00:00Z",
        })
        assert resp.status_code in (401, 403)
