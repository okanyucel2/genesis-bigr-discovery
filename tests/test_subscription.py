"""Tests for the BİGR Subscription & Pricing module.

Tests cover:
    - Plan definitions (3 plans, correct pricing, features)
    - SubscriptionService (default plan, activation, device limits, tier access)
    - API endpoints (GET /plans, GET /current, POST /activate, GET /tier-access)
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from bigr.core.database import Base
from bigr.subscription.plans import PLANS, PlanDefinition, get_all_plans, get_plan
from bigr.subscription.service import DEFAULT_DEVICE_ID, SubscriptionService


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest_asyncio.fixture
async def db_session():
    """Create a fresh in-memory SQLite database for each test."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", echo=False
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def service():
    """Create a fresh SubscriptionService."""
    return SubscriptionService()


# ===========================================================================
# Plan definition tests
# ===========================================================================


class TestPlanDefinitions:
    """Tests for plan definitions in plans.py."""

    def test_three_plans_exist(self):
        assert len(PLANS) == 3
        assert set(PLANS.keys()) == {"free", "nomad", "family"}

    def test_free_plan(self):
        plan = PLANS["free"]
        assert plan.id == "free"
        assert plan.price_usd == 0.0
        assert plan.max_devices == 1
        assert plan.ai_tiers == ["L0"]
        assert len(plan.features) > 0
        assert len(plan.features_tr) > 0
        assert len(plan.features) == len(plan.features_tr)

    def test_nomad_plan(self):
        plan = PLANS["nomad"]
        assert plan.id == "nomad"
        assert plan.price_usd == 4.99
        assert plan.max_devices == 3
        assert plan.ai_tiers == ["L0", "L1"]

    def test_family_plan(self):
        plan = PLANS["family"]
        assert plan.id == "family"
        assert plan.price_usd == 9.99
        assert plan.max_devices == 5
        assert plan.ai_tiers == ["L0", "L1", "L2"]

    def test_get_plan_valid(self):
        assert get_plan("free") is not None
        assert get_plan("nomad") is not None
        assert get_plan("family") is not None

    def test_get_plan_invalid(self):
        assert get_plan("enterprise") is None
        assert get_plan("") is None

    def test_get_all_plans_order(self):
        plans = get_all_plans()
        assert len(plans) == 3
        assert plans[0].id == "free"
        assert plans[1].id == "nomad"
        assert plans[2].id == "family"

    def test_plans_are_frozen(self):
        plan = PLANS["free"]
        with pytest.raises(AttributeError):
            plan.price_usd = 99.99  # type: ignore[misc]

    def test_price_ordering(self):
        plans = get_all_plans()
        prices = [p.price_usd for p in plans]
        assert prices == sorted(prices), "Plans should be ordered by price"

    def test_device_limits_ascending(self):
        plans = get_all_plans()
        limits = [p.max_devices for p in plans]
        assert limits == sorted(limits), "Device limits should be ascending"


# ===========================================================================
# Service tests
# ===========================================================================


class TestSubscriptionService:
    """Tests for SubscriptionService with in-memory database."""

    @pytest.mark.asyncio
    async def test_default_plan_is_free(self, db_session, service):
        plan, sub = await service.get_current_plan(db_session)
        assert plan.id == "free"
        assert sub is None

    @pytest.mark.asyncio
    async def test_activate_plan_changes_plan(self, db_session, service):
        # Initially free
        plan, _ = await service.get_current_plan(db_session)
        assert plan.id == "free"

        # Activate nomad
        sub = await service.activate_plan(db_session, "nomad")
        assert sub.plan_id == "nomad"
        assert sub.is_active == 1
        assert sub.device_id == DEFAULT_DEVICE_ID

        # Verify
        plan, sub = await service.get_current_plan(db_session)
        assert plan.id == "nomad"
        assert sub is not None
        assert sub.plan_id == "nomad"

    @pytest.mark.asyncio
    async def test_activate_plan_replaces_previous(self, db_session, service):
        # Activate nomad, then family
        await service.activate_plan(db_session, "nomad")
        await service.activate_plan(db_session, "family")

        plan, sub = await service.get_current_plan(db_session)
        assert plan.id == "family"

    @pytest.mark.asyncio
    async def test_activate_invalid_plan_raises(self, db_session, service):
        with pytest.raises(ValueError, match="Unknown plan"):
            await service.activate_plan(db_session, "enterprise")

    @pytest.mark.asyncio
    async def test_activate_free_has_no_expiry(self, db_session, service):
        sub = await service.activate_plan(db_session, "free")
        assert sub.expires_at is None

    @pytest.mark.asyncio
    async def test_activate_paid_has_expiry(self, db_session, service):
        sub = await service.activate_plan(db_session, "nomad")
        assert sub.expires_at is not None

    @pytest.mark.asyncio
    async def test_device_limit_check(self, db_session, service):
        result = await service.check_device_limit(db_session)
        assert result is True

    def test_tier_access_free(self, service):
        assert service.get_max_tier("free") == "L0"
        assert service.get_allowed_tiers("free") == ["L0"]

    def test_tier_access_nomad(self, service):
        assert service.get_max_tier("nomad") == "L1"
        assert service.get_allowed_tiers("nomad") == ["L0", "L1"]

    def test_tier_access_family(self, service):
        assert service.get_max_tier("family") == "L2"
        assert service.get_allowed_tiers("family") == ["L0", "L1", "L2"]

    def test_tier_access_unknown_plan(self, service):
        assert service.get_max_tier("unknown") == "L0"
        assert service.get_allowed_tiers("unknown") == ["L0"]

    @pytest.mark.asyncio
    async def test_usage_returns_plan_info(self, db_session, service):
        usage = await service.get_usage(db_session)
        assert usage["plan_id"] == "free"
        assert usage["devices_max"] == 1
        assert "period_start" in usage
        assert "period_end" in usage

    @pytest.mark.asyncio
    async def test_usage_reflects_plan_change(self, db_session, service):
        await service.activate_plan(db_session, "family")
        usage = await service.get_usage(db_session)
        assert usage["plan_id"] == "family"
        assert usage["devices_max"] == 5


# ===========================================================================
# API endpoint tests
# ===========================================================================


@pytest_asyncio.fixture
async def test_app(db_session):
    """Create a FastAPI test app with subscription routes and test DB."""
    from fastapi import FastAPI

    from bigr.subscription.api import router, _get_service

    app = FastAPI()
    app.include_router(router)

    # Override DB dependency
    async def override_get_db():
        yield db_session

    from bigr.core.database import get_db

    app.dependency_overrides[get_db] = override_get_db

    return app


@pytest_asyncio.fixture
async def client(test_app):
    """Create an async test client."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestSubscriptionAPI:
    """Tests for subscription API endpoints."""

    @pytest.mark.asyncio
    async def test_get_plans(self, client):
        resp = await client.get("/api/subscription/plans")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        plan_ids = [p["id"] for p in data["plans"]]
        assert "free" in plan_ids
        assert "nomad" in plan_ids
        assert "family" in plan_ids

    @pytest.mark.asyncio
    async def test_get_plans_structure(self, client):
        resp = await client.get("/api/subscription/plans")
        data = resp.json()
        for plan in data["plans"]:
            assert "id" in plan
            assert "name" in plan
            assert "name_tr" in plan
            assert "price_usd" in plan
            assert "max_devices" in plan
            assert "ai_tiers" in plan
            assert "features" in plan
            assert "features_tr" in plan

    @pytest.mark.asyncio
    async def test_get_current_free_by_default(self, client):
        resp = await client.get("/api/subscription/current")
        assert resp.status_code == 200
        data = resp.json()
        assert data["plan_id"] == "free"
        assert data["plan"]["id"] == "free"
        assert data["is_active"] is True

    @pytest.mark.asyncio
    async def test_activate_nomad(self, client):
        resp = await client.post(
            "/api/subscription/activate",
            json={"plan_id": "nomad"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["subscription"]["plan_id"] == "nomad"

    @pytest.mark.asyncio
    async def test_activate_family(self, client):
        resp = await client.post(
            "/api/subscription/activate",
            json={"plan_id": "family"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["subscription"]["plan_id"] == "family"

    @pytest.mark.asyncio
    async def test_activate_invalid_plan(self, client):
        resp = await client.post(
            "/api/subscription/activate",
            json={"plan_id": "enterprise"},
        )
        assert resp.status_code == 422  # Pydantic validation (pattern mismatch)

    @pytest.mark.asyncio
    async def test_current_changes_after_activate(self, client):
        # Activate nomad
        await client.post(
            "/api/subscription/activate",
            json={"plan_id": "nomad"},
        )
        # Check current
        resp = await client.get("/api/subscription/current")
        assert resp.json()["plan_id"] == "nomad"

    @pytest.mark.asyncio
    async def test_tier_access_free(self, client):
        resp = await client.get("/api/subscription/tier-access")
        assert resp.status_code == 200
        data = resp.json()
        assert data["plan_id"] == "free"
        assert data["allowed_tiers"] == ["L0"]
        assert data["can_use_l1"] is False
        assert data["can_use_l2"] is False

    @pytest.mark.asyncio
    async def test_tier_access_after_upgrade(self, client):
        await client.post(
            "/api/subscription/activate",
            json={"plan_id": "family"},
        )
        resp = await client.get("/api/subscription/tier-access")
        data = resp.json()
        assert data["plan_id"] == "family"
        assert data["can_use_l1"] is True
        assert data["can_use_l2"] is True
        assert "L2" in data["allowed_tiers"]

    @pytest.mark.asyncio
    async def test_usage_endpoint(self, client):
        resp = await client.get("/api/subscription/usage")
        assert resp.status_code == 200
        data = resp.json()
        assert data["plan_id"] == "free"
        assert "period_start" in data
        assert "period_end" in data
        assert data["devices_max"] == 1
