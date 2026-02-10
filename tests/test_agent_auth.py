"""Tests for agent authentication — token generation, hashing, verification."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from bigr.agent.auth import generate_token, hash_token, verify_agent_token
from bigr.core.database import Base, get_db, get_engine, get_session_factory, reset_engine
from bigr.core.models_db import AgentDB
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


class TestTokenGeneration:
    def test_generate_token_length(self):
        token = generate_token()
        # 32 bytes hex = 64 characters
        assert len(token) == 64

    def test_generate_token_unique(self):
        t1 = generate_token()
        t2 = generate_token()
        assert t1 != t2

    def test_generate_token_is_hex(self):
        token = generate_token()
        int(token, 16)  # Should not raise


class TestTokenHashing:
    def test_hash_is_deterministic(self):
        token = "test-token-12345"
        h1 = hash_token(token)
        h2 = hash_token(token)
        assert h1 == h2

    def test_hash_is_sha256_length(self):
        h = hash_token("anything")
        assert len(h) == 64  # SHA-256 hex digest

    def test_different_tokens_different_hashes(self):
        h1 = hash_token("token-a")
        h2 = hash_token("token-b")
        assert h1 != h2


class TestVerifyAgentToken:
    @pytest.fixture
    async def registered_agent(self, setup_db):
        """Insert a test agent and return (agent_id, plaintext_token)."""
        token = generate_token()
        factory = get_session_factory()
        async with factory() as session:
            agent = AgentDB(
                id="agent-test-1",
                name="test-scanner",
                site_name="HQ",
                token_hash=hash_token(token),
                is_active=1,
                registered_at="2026-01-01T00:00:00Z",
                status="online",
            )
            session.add(agent)
            await session.commit()
        return "agent-test-1", token

    @pytest.fixture
    def app(self):
        return create_app(data_path="/tmp/__nonexistent_bigr_test__.json")

    @pytest.fixture
    async def client(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    async def test_valid_token_passes(self, client: AsyncClient, registered_agent):
        _, token = registered_agent
        resp = await client.post(
            "/api/agents/heartbeat",
            json={"status": "online"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    async def test_invalid_token_returns_401(self, client: AsyncClient, registered_agent):
        resp = await client.post(
            "/api/agents/heartbeat",
            json={"status": "online"},
            headers={"Authorization": "Bearer invalid-token-garbage"},
        )
        assert resp.status_code == 401

    async def test_missing_token_returns_401(self, client: AsyncClient, setup_db):
        resp = await client.post(
            "/api/agents/heartbeat",
            json={"status": "online"},
        )
        assert resp.status_code in (401, 403)

    async def test_deactivated_agent_returns_401(self, client: AsyncClient, setup_db):
        """Deactivated agents should be rejected even with valid token."""
        token = generate_token()
        factory = get_session_factory()
        async with factory() as session:
            agent = AgentDB(
                id="agent-deactivated",
                name="dead-scanner",
                site_name="old-site",
                token_hash=hash_token(token),
                is_active=0,  # deactivated
                registered_at="2026-01-01T00:00:00Z",
                status="offline",
            )
            session.add(agent)
            await session.commit()

        resp = await client.post(
            "/api/agents/heartbeat",
            json={"status": "online"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401
