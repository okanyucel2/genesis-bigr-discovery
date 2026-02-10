"""Tests for agent remote command queue — create, poll, status updates."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from bigr.core.database import Base, get_engine, reset_engine
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
    subnets: list[str] | None = None,
) -> tuple[str, str]:
    """Helper: register an agent and return (agent_id, token)."""
    body: dict = {"name": name, "site_name": site_name}
    if subnets:
        body["subnets"] = subnets
    resp = await client.post("/api/agents/register", json=body)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return data["agent_id"], data["token"]


class TestCreateCommand:
    async def test_create_scan_command(self, client: AsyncClient):
        agent_id, _ = await _register_agent(
            client, subnets=["192.168.1.0/24"],
        )
        resp = await client.post(f"/api/agents/{agent_id}/commands", json={
            "command_type": "scan_now",
            "shield": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["command_id"]
        assert data["agent_id"] == agent_id
        assert data["targets"] == ["192.168.1.0/24"]  # uses agent subnets
        assert data["shield"] is True

    async def test_create_command_with_explicit_targets(self, client: AsyncClient):
        agent_id, _ = await _register_agent(client)
        resp = await client.post(f"/api/agents/{agent_id}/commands", json={
            "targets": ["10.0.0.0/24", "172.16.0.0/16"],
            "shield": False,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["targets"] == ["10.0.0.0/24", "172.16.0.0/16"]
        assert data["shield"] is False

    async def test_create_command_no_targets_no_subnets_returns_400(self, client: AsyncClient):
        agent_id, _ = await _register_agent(client)  # no subnets
        resp = await client.post(f"/api/agents/{agent_id}/commands", json={
            "command_type": "scan_now",
        })
        assert resp.status_code == 400

    async def test_create_command_nonexistent_agent_returns_404(self, client: AsyncClient):
        resp = await client.post("/api/agents/nonexistent-id/commands", json={
            "targets": ["10.0.0.0/24"],
        })
        assert resp.status_code == 404


class TestGetPendingCommands:
    async def test_no_pending_commands(self, client: AsyncClient):
        _, token = await _register_agent(client)
        resp = await client.get(
            "/api/agents/commands",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["commands"] == []
        assert data["count"] == 0

    async def test_returns_pending_commands(self, client: AsyncClient):
        agent_id, token = await _register_agent(
            client, subnets=["192.168.1.0/24"],
        )
        # Create a command
        await client.post(f"/api/agents/{agent_id}/commands", json={
            "command_type": "scan_now",
        })

        resp = await client.get(
            "/api/agents/commands",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        cmd = data["commands"][0]
        assert cmd["command_type"] == "scan_now"
        assert cmd["params"]["targets"] == ["192.168.1.0/24"]

    async def test_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/agents/commands")
        assert resp.status_code in (401, 403)


class TestUpdateCommandStatus:
    async def test_ack_command(self, client: AsyncClient):
        agent_id, token = await _register_agent(
            client, subnets=["192.168.1.0/24"],
        )
        # Create command
        create_resp = await client.post(f"/api/agents/{agent_id}/commands", json={
            "command_type": "scan_now",
        })
        cmd_id = create_resp.json()["command_id"]

        # ACK
        resp = await client.patch(
            f"/api/agents/commands/{cmd_id}",
            json={"status": "ack"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["command_status"] == "ack"

    async def test_complete_command_with_result(self, client: AsyncClient):
        agent_id, token = await _register_agent(
            client, subnets=["192.168.1.0/24"],
        )
        create_resp = await client.post(f"/api/agents/{agent_id}/commands", json={
            "command_type": "scan_now",
        })
        cmd_id = create_resp.json()["command_id"]

        # Complete with result
        resp = await client.patch(
            f"/api/agents/commands/{cmd_id}",
            json={
                "status": "completed",
                "result": {"assets_discovered": 15, "targets_scanned": 1},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["command_status"] == "completed"

    async def test_completed_command_not_in_pending(self, client: AsyncClient):
        agent_id, token = await _register_agent(
            client, subnets=["192.168.1.0/24"],
        )
        create_resp = await client.post(f"/api/agents/{agent_id}/commands", json={
            "command_type": "scan_now",
        })
        cmd_id = create_resp.json()["command_id"]

        # Complete it
        await client.patch(
            f"/api/agents/commands/{cmd_id}",
            json={"status": "completed"},
            headers={"Authorization": f"Bearer {token}"},
        )

        # Should no longer appear in pending
        resp = await client.get(
            "/api/agents/commands",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.json()["count"] == 0

    async def test_cannot_update_other_agents_command(self, client: AsyncClient):
        agent1_id, token1 = await _register_agent(
            client, name="agent-1", subnets=["10.0.0.0/24"],
        )
        _, token2 = await _register_agent(client, name="agent-2")

        create_resp = await client.post(f"/api/agents/{agent1_id}/commands", json={
            "command_type": "scan_now",
        })
        cmd_id = create_resp.json()["command_id"]

        # Agent 2 tries to update agent 1's command
        resp = await client.patch(
            f"/api/agents/commands/{cmd_id}",
            json={"status": "ack"},
            headers={"Authorization": f"Bearer {token2}"},
        )
        assert resp.status_code == 403

    async def test_update_nonexistent_command_returns_404(self, client: AsyncClient):
        _, token = await _register_agent(client)
        resp = await client.patch(
            "/api/agents/commands/nonexistent-id",
            json={"status": "ack"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404


class TestHeartbeatPendingCommands:
    async def test_heartbeat_returns_pending_count(self, client: AsyncClient):
        agent_id, token = await _register_agent(
            client, subnets=["192.168.1.0/24"],
        )
        # No commands yet
        resp = await client.post(
            "/api/agents/heartbeat",
            json={"status": "online"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.json()["pending_commands"] == 0

        # Create a command
        await client.post(f"/api/agents/{agent_id}/commands", json={
            "command_type": "scan_now",
        })

        resp = await client.post(
            "/api/agents/heartbeat",
            json={"status": "online"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.json()["pending_commands"] == 1


class TestListAgentCommands:
    async def test_list_command_history(self, client: AsyncClient):
        agent_id, token = await _register_agent(
            client, subnets=["192.168.1.0/24"],
        )
        # Create 2 commands
        await client.post(f"/api/agents/{agent_id}/commands", json={
            "command_type": "scan_now",
        })
        await client.post(f"/api/agents/{agent_id}/commands", json={
            "command_type": "scan_now",
            "targets": ["10.0.0.0/24"],
        })

        resp = await client.get(f"/api/agents/{agent_id}/commands")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2

    async def test_filter_by_status(self, client: AsyncClient):
        agent_id, token = await _register_agent(
            client, subnets=["192.168.1.0/24"],
        )
        create_resp = await client.post(f"/api/agents/{agent_id}/commands", json={
            "command_type": "scan_now",
        })
        cmd_id = create_resp.json()["command_id"]

        # Complete one
        await client.patch(
            f"/api/agents/commands/{cmd_id}",
            json={"status": "completed"},
            headers={"Authorization": f"Bearer {token}"},
        )

        # Create another (stays pending)
        await client.post(f"/api/agents/{agent_id}/commands", json={
            "command_type": "scan_now",
        })

        # Filter: only pending
        resp = await client.get(
            f"/api/agents/{agent_id}/commands",
            params={"status": "pending"},
        )
        assert resp.json()["count"] == 1

        # Filter: only completed
        resp = await client.get(
            f"/api/agents/{agent_id}/commands",
            params={"status": "completed"},
        )
        assert resp.json()["count"] == 1
