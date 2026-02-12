"""Tests for Guardian API endpoints."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from bigr.core.database import Base
from bigr.guardian.api.routes import router, set_components
from bigr.guardian.config import GuardianConfig
from bigr.guardian.dns.blocklist import BlocklistManager
from bigr.guardian.dns.rules import CustomRulesManager
from bigr.guardian.stats import StatsTracker


@pytest.fixture
async def db_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
def app(db_engine):
    """Create a test FastAPI app with Guardian router."""
    from bigr.core import database as db_module

    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    # Override get_db dependency
    async def _override_get_db():
        async with factory() as session:
            yield session

    test_app = FastAPI()
    test_app.include_router(router)
    test_app.dependency_overrides[db_module.get_db] = _override_get_db

    # Set up test components
    config = GuardianConfig()
    blocklist = BlocklistManager(config)
    blocklist._blocked_domains = {"malware.com"}
    blocklist._domain_categories = {"malware.com": "malware"}

    rules = CustomRulesManager()
    stats = StatsTracker()
    stats.record_query("a.com", "allow", "default")
    stats.record_query("malware.com", "block", "blocklist")

    set_components(
        blocklist=blocklist,
        rules=rules,
        stats=stats,
        dns_server=None,
        health=None,
    )

    return test_app


@pytest.fixture
def client(app):
    return TestClient(app)


class TestGuardianStatusEndpoint:
    def test_status_returns_data(self, client: TestClient):
        resp = client.get("/api/guardian/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "guardian_active" in data
        assert "blocked_domains_count" in data
        assert data["blocked_domains_count"] == 1


class TestGuardianStatsEndpoint:
    def test_stats_returns_data(self, client: TestClient):
        resp = client.get("/api/guardian/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "current_period" in data
        assert data["current_period"]["total_queries"] == 2


class TestGuardianRulesEndpoint:
    def test_list_rules_empty(self, client: TestClient):
        resp = client.get("/api/guardian/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert data["rules"] == []
        assert data["total"] == 0

    def test_add_rule(self, client: TestClient):
        resp = client.post(
            "/api/guardian/rules",
            json={
                "action": "block",
                "domain": "evil.test.com",
                "reason": "Testing",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["action"] == "block"
        assert data["domain"] == "evil.test.com"
        assert "id" in data

    def test_add_and_list_rule(self, client: TestClient):
        client.post(
            "/api/guardian/rules",
            json={"action": "block", "domain": "listed.com"},
        )
        resp = client.get("/api/guardian/rules")
        data = resp.json()
        assert data["total"] >= 1

    def test_add_invalid_action(self, client: TestClient):
        resp = client.post(
            "/api/guardian/rules",
            json={"action": "invalid", "domain": "test.com"},
        )
        assert resp.status_code == 400

    def test_delete_rule(self, client: TestClient):
        # Add rule
        resp = client.post(
            "/api/guardian/rules",
            json={"action": "block", "domain": "todelete.com"},
        )
        rule_id = resp.json()["id"]

        # Delete it
        resp = client.delete(f"/api/guardian/rules/{rule_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"

    def test_delete_nonexistent(self, client: TestClient):
        resp = client.delete("/api/guardian/rules/nonexistent")
        assert resp.status_code == 404


class TestGuardianBlocklistsEndpoint:
    def test_list_blocklists(self, client: TestClient):
        resp = client.get("/api/guardian/blocklists")
        assert resp.status_code == 200
        data = resp.json()
        assert "blocklists" in data


class TestGuardianHealthEndpoint:
    def test_health_offline(self, client: TestClient):
        resp = client.get("/api/guardian/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "offline"
