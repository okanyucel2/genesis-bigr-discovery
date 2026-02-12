"""Tests for the Family Shield dashboard — service + API.

Covers:
    - FamilyService: add/remove/update device, get overview, safety score
    - Device limit enforcement (5 for Family Shield)
    - API: GET /overview, POST /devices, PUT /devices, DELETE /devices, GET /alerts
    - Safety score calculation (safe/warning/danger)
    - Device icon mapping
"""

from __future__ import annotations

import json
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from bigr.core.database import Base, get_db, get_engine, get_session_factory, reset_engine
from bigr.core.models_db import (
    AgentDB,
    FamilyDeviceDB,
    ShieldFindingDB,
    ShieldScanDB,
    SubscriptionDB,
)
from bigr.dashboard.app import create_app
from bigr.family.models import AddDeviceRequest, UpdateDeviceRequest
from bigr.family.service import FamilyService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
async def setup_db():
    """Create a fresh in-memory database for each test."""
    reset_engine()
    engine = get_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    reset_engine()


@pytest.fixture
def service() -> FamilyService:
    """Return a FamilyService instance."""
    return FamilyService()


@pytest.fixture
async def db_session(setup_db):
    """Provide an async session for service tests."""
    factory = get_session_factory()
    async with factory() as session:
        yield session


@pytest.fixture
async def family_subscription(db_session) -> str:
    """Create a Family Shield subscription and return its ID."""
    sub_id = str(uuid.uuid4())
    sub = SubscriptionDB(
        id=sub_id,
        device_id="local-device-001",
        plan_id="family",
        activated_at="2026-02-10T10:00:00Z",
        expires_at="2026-03-10T10:00:00Z",
        is_active=1,
    )
    db_session.add(sub)
    await db_session.commit()
    return sub_id


@pytest.fixture
async def free_subscription(db_session) -> str:
    """Create a free subscription and return its ID."""
    sub_id = str(uuid.uuid4())
    sub = SubscriptionDB(
        id=sub_id,
        device_id="local-device-002",
        plan_id="free",
        activated_at="2026-02-10T10:00:00Z",
        is_active=1,
    )
    db_session.add(sub)
    await db_session.commit()
    return sub_id


@pytest.fixture
async def agent_with_scans(db_session) -> str:
    """Create an agent with shield scan data and return agent ID."""
    agent_id = str(uuid.uuid4())
    agent = AgentDB(
        id=agent_id,
        name="okan-iphone",
        site_name="home",
        token_hash="test-hash-123",
        is_active=1,
        registered_at="2026-02-10T10:00:00Z",
        last_seen="2026-02-10T12:00:00Z",
        status="online",
        version="1.0.0",
    )
    db_session.add(agent)

    scan_id = str(uuid.uuid4())
    scan = ShieldScanDB(
        id=scan_id,
        agent_id=agent_id,
        target="192.168.1.0/24",
        started_at="2026-02-10T11:00:00Z",
        completed_at="2026-02-10T11:05:00Z",
    )
    db_session.add(scan)

    # Add some findings
    finding1 = ShieldFindingDB(
        scan_id=scan_id,
        module="port_scan",
        severity="medium",
        title="Acik port tespit edildi: 22/SSH",
    )
    finding2 = ShieldFindingDB(
        scan_id=scan_id,
        module="headers",
        severity="info",
        title="HTTP header eksik",
    )
    db_session.add_all([finding1, finding2])
    await db_session.commit()
    return agent_id


@pytest.fixture
def app():
    """Create the dashboard app."""
    return create_app(data_path="/tmp/__nonexistent_bigr_test__.json")


@pytest.fixture
async def client(app):
    """Async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Service tests
# ---------------------------------------------------------------------------


class TestFamilyServiceAddDevice:
    """Tests for adding devices to family group."""

    @pytest.mark.asyncio
    async def test_add_device_creates_record(
        self, service, db_session, family_subscription
    ):
        """Adding a device should create a FamilyDeviceDB record."""
        request = AddDeviceRequest(
            device_name="Okan'in iPhone",
            device_type="phone",
            owner_name="Okan",
        )
        device = await service.add_device(family_subscription, request, db_session)

        assert device.name == "Okan'in iPhone"
        assert device.device_type == "phone"
        assert device.owner_name == "Okan"
        assert device.id  # UUID assigned

    @pytest.mark.asyncio
    async def test_add_device_default_type(
        self, service, db_session, family_subscription
    ):
        """Default device type should be 'other'."""
        request = AddDeviceRequest(device_name="Bilinmeyen Cihaz")
        device = await service.add_device(family_subscription, request, db_session)

        assert device.device_type == "other"

    @pytest.mark.asyncio
    async def test_add_device_respects_limit(
        self, service, db_session, family_subscription
    ):
        """Family Shield allows max 5 devices."""
        # Add 5 devices (at limit)
        for i in range(5):
            request = AddDeviceRequest(device_name=f"Cihaz {i+1}")
            await service.add_device(family_subscription, request, db_session)

        # 6th device should fail
        request = AddDeviceRequest(device_name="Cihaz 6")
        with pytest.raises(ValueError, match="limiti"):
            await service.add_device(family_subscription, request, db_session)

    @pytest.mark.asyncio
    async def test_add_device_free_plan_limit(
        self, service, db_session, free_subscription
    ):
        """Free plan allows only 1 device."""
        request = AddDeviceRequest(device_name="Tek Cihaz")
        await service.add_device(free_subscription, request, db_session)

        request2 = AddDeviceRequest(device_name="Ikinci Cihaz")
        with pytest.raises(ValueError, match="limiti"):
            await service.add_device(free_subscription, request2, db_session)

    @pytest.mark.asyncio
    async def test_add_device_invalid_subscription(self, service, db_session):
        """Adding device with non-existent subscription should fail."""
        request = AddDeviceRequest(device_name="Test")
        with pytest.raises(ValueError, match="Abonelik bulunamadi"):
            await service.add_device("nonexistent-id", request, db_session)


class TestFamilyServiceRemoveDevice:
    """Tests for removing devices from family group."""

    @pytest.mark.asyncio
    async def test_remove_device_deactivates(
        self, service, db_session, family_subscription
    ):
        """Removing a device should set is_active=0."""
        request = AddDeviceRequest(device_name="Remove Me")
        device = await service.add_device(family_subscription, request, db_session)

        result = await service.remove_device(device.id, db_session)
        assert result["status"] == "ok"
        assert "cikarildi" in result["message"]

    @pytest.mark.asyncio
    async def test_remove_nonexistent_device(self, service, db_session):
        """Removing a non-existent device should raise."""
        with pytest.raises(ValueError, match="Cihaz bulunamadi"):
            await service.remove_device("nonexistent-device", db_session)

    @pytest.mark.asyncio
    async def test_remove_device_frees_slot(
        self, service, db_session, family_subscription
    ):
        """Removing a device should free a slot for a new one."""
        # Fill up to 5 devices
        devices = []
        for i in range(5):
            request = AddDeviceRequest(device_name=f"Cihaz {i+1}")
            d = await service.add_device(family_subscription, request, db_session)
            devices.append(d)

        # Remove one
        await service.remove_device(devices[0].id, db_session)

        # Should be able to add another
        request = AddDeviceRequest(device_name="Yeni Cihaz")
        new_device = await service.add_device(family_subscription, request, db_session)
        assert new_device.name == "Yeni Cihaz"


class TestFamilyServiceUpdateDevice:
    """Tests for updating family device info."""

    @pytest.mark.asyncio
    async def test_update_device_changes_fields(
        self, service, db_session, family_subscription
    ):
        """Updating a device should change its name/type/owner."""
        request = AddDeviceRequest(
            device_name="Old Name", device_type="phone", owner_name="Alice"
        )
        device = await service.add_device(family_subscription, request, db_session)

        updated = await service.update_device(
            device.id,
            UpdateDeviceRequest(name="New Name", device_type="laptop", owner_name="Bob"),
            db_session,
        )

        assert updated.name == "New Name"
        assert updated.device_type == "laptop"
        assert updated.owner_name == "Bob"

    @pytest.mark.asyncio
    async def test_update_device_partial(
        self, service, db_session, family_subscription
    ):
        """Updating only name should not change other fields."""
        request = AddDeviceRequest(
            device_name="Original", device_type="tablet", owner_name="Charlie"
        )
        device = await service.add_device(family_subscription, request, db_session)

        updated = await service.update_device(
            device.id,
            UpdateDeviceRequest(name="Renamed"),
            db_session,
        )

        assert updated.name == "Renamed"
        assert updated.device_type == "tablet"
        assert updated.owner_name == "Charlie"


class TestFamilyServiceOverview:
    """Tests for the overview dashboard data."""

    @pytest.mark.asyncio
    async def test_get_overview_empty(
        self, service, db_session, family_subscription
    ):
        """Overview with no devices should return zero counts."""
        overview = await service.get_overview(family_subscription, db_session)

        assert overview.family_name == "Ailem"
        assert overview.plan_id == "family"
        assert overview.max_devices == 5
        assert len(overview.devices) == 0
        assert overview.total_threats == 0
        assert overview.avg_safety_score == 0.0
        assert overview.devices_online == 0

    @pytest.mark.asyncio
    async def test_get_overview_with_devices(
        self, service, db_session, family_subscription
    ):
        """Overview should include all active devices."""
        for i in range(3):
            request = AddDeviceRequest(device_name=f"Cihaz {i+1}")
            await service.add_device(family_subscription, request, db_session)

        overview = await service.get_overview(family_subscription, db_session)
        assert len(overview.devices) == 3
        assert overview.avg_safety_score > 0  # Each unlinked device gets 0.5

    @pytest.mark.asyncio
    async def test_get_overview_avg_safety(
        self, service, db_session, family_subscription
    ):
        """Average safety should be mean of all device scores."""
        # Add two devices (no agents -> safety 0.5 each)
        for i in range(2):
            request = AddDeviceRequest(device_name=f"Device {i}")
            await service.add_device(family_subscription, request, db_session)

        overview = await service.get_overview(family_subscription, db_session)
        assert overview.avg_safety_score == 0.5  # (0.5+0.5)/2

    @pytest.mark.asyncio
    async def test_get_overview_with_linked_agent(
        self, service, db_session, family_subscription, agent_with_scans
    ):
        """Overview should calculate real safety when agent is linked."""
        # Add a device and link it to the agent
        request = AddDeviceRequest(device_name="Linked Device", device_type="phone")
        device = await service.add_device(family_subscription, request, db_session)

        # Manually link agent to the device
        from sqlalchemy import select
        result = await db_session.execute(
            select(FamilyDeviceDB).where(FamilyDeviceDB.id == device.id)
        )
        dev_row = result.scalar_one()
        dev_row.agent_id = agent_with_scans
        await db_session.commit()

        overview = await service.get_overview(family_subscription, db_session)
        assert len(overview.devices) == 1

        linked_device = overview.devices[0]
        assert linked_device.is_online is True
        # Agent has 1 medium + 1 info finding -> score < 0.95
        assert linked_device.safety_score < 0.95


class TestFamilyServiceAlerts:
    """Tests for family-wide alerts."""

    @pytest.mark.asyncio
    async def test_get_alerts_empty(
        self, service, db_session, family_subscription
    ):
        """No devices = no alerts."""
        alerts = await service.get_family_alerts(family_subscription, db_session)
        assert alerts == []

    @pytest.mark.asyncio
    async def test_get_alerts_with_findings(
        self, service, db_session, family_subscription, agent_with_scans
    ):
        """Alerts should include findings from linked agent."""
        request = AddDeviceRequest(device_name="Alert Device")
        device = await service.add_device(family_subscription, request, db_session)

        # Link agent
        from sqlalchemy import select
        result = await db_session.execute(
            select(FamilyDeviceDB).where(FamilyDeviceDB.id == device.id)
        )
        dev_row = result.scalar_one()
        dev_row.agent_id = agent_with_scans
        await db_session.commit()

        alerts = await service.get_family_alerts(family_subscription, db_session)
        assert len(alerts) == 2  # 1 medium + 1 info finding


class TestSafetyScoreCalculation:
    """Tests for the safety score logic."""

    @pytest.mark.asyncio
    async def test_no_agent_returns_warning(self, service, db_session):
        """No agent linked should return 0.5 / warning."""
        score, level = await service._calculate_safety_score(None, db_session)
        assert score == 0.5
        assert level == "warning"

    @pytest.mark.asyncio
    async def test_no_scans_returns_warning(self, service, db_session):
        """Agent with no scans should return 0.5 / warning."""
        agent = AgentDB(
            id="no-scan-agent",
            name="NoScan",
            site_name="test",
            token_hash="h",
            registered_at="2026-01-01T00:00:00Z",
            status="online",
        )
        db_session.add(agent)
        await db_session.commit()

        score, level = await service._calculate_safety_score("no-scan-agent", db_session)
        assert score == 0.5
        assert level == "warning"

    @pytest.mark.asyncio
    async def test_clean_scan_returns_safe(self, service, db_session):
        """Agent with scan but no findings should be safe."""
        agent = AgentDB(
            id="clean-agent",
            name="Clean",
            site_name="test",
            token_hash="h",
            registered_at="2026-01-01T00:00:00Z",
            status="online",
        )
        scan = ShieldScanDB(
            id="clean-scan",
            agent_id="clean-agent",
            target="192.168.1.0/24",
            started_at="2026-02-10T11:00:00Z",
        )
        db_session.add_all([agent, scan])
        await db_session.commit()

        score, level = await service._calculate_safety_score("clean-agent", db_session)
        assert score == 0.95
        assert level == "safe"

    @pytest.mark.asyncio
    async def test_critical_finding_returns_danger(self, service, db_session):
        """Agent with critical finding should be in danger."""
        agent = AgentDB(
            id="danger-agent",
            name="Danger",
            site_name="test",
            token_hash="h",
            registered_at="2026-01-01T00:00:00Z",
            status="online",
        )
        scan = ShieldScanDB(
            id="danger-scan",
            agent_id="danger-agent",
            target="192.168.1.0/24",
            started_at="2026-02-10T11:00:00Z",
        )
        finding = ShieldFindingDB(
            scan_id="danger-scan",
            module="cve",
            severity="critical",
            title="CVE-2024-XXXX Kritik Zafiyet",
        )
        finding2 = ShieldFindingDB(
            scan_id="danger-scan",
            module="cve",
            severity="critical",
            title="CVE-2024-YYYY Kritik Zafiyet",
        )
        db_session.add_all([agent, scan, finding, finding2])
        await db_session.commit()

        score, level = await service._calculate_safety_score("danger-agent", db_session)
        assert score < 0.5
        assert level == "danger"

    @pytest.mark.asyncio
    async def test_mixed_findings_returns_warning(self, service, db_session, agent_with_scans):
        """Agent with medium + info findings should be warning."""
        score, level = await service._calculate_safety_score(agent_with_scans, db_session)
        # medium=0.08 + info=0.01 = penalty 0.09, score = 0.91 -> safe actually
        assert score > 0.5
        assert level == "safe"  # 0.91 is safe territory


class TestDeviceIcon:
    """Tests for device icon mapping."""

    def test_phone_icon(self, service):
        assert service._device_icon("phone") == "\U0001f4f1"

    def test_laptop_icon(self, service):
        assert service._device_icon("laptop") == "\U0001f4bb"

    def test_tablet_icon(self, service):
        assert service._device_icon("tablet") == "\U0001f4df"

    def test_desktop_icon(self, service):
        assert service._device_icon("desktop") == "\U0001f5a5\ufe0f"

    def test_other_icon(self, service):
        assert service._device_icon("other") == "\U0001f4e1"

    def test_unknown_icon_defaults(self, service):
        assert service._device_icon("smartwatch") == "\U0001f4e1"


# ---------------------------------------------------------------------------
# API tests
# ---------------------------------------------------------------------------


class TestFamilyAPI:
    """Tests for the Family Shield HTTP endpoints."""

    @pytest.mark.asyncio
    async def test_overview_requires_subscription_id(self, client):
        """GET /overview without subscription_id should fail."""
        resp = await client.get("/api/family/overview")
        assert resp.status_code == 422  # Missing required query param

    @pytest.mark.asyncio
    async def test_overview_invalid_subscription(self, client):
        """GET /overview with non-existent subscription returns empty data."""
        resp = await client.get(
            "/api/family/overview", params={"subscription_id": "fake-id"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["devices"] == []
        assert data["total_threats"] == 0

    @pytest.mark.asyncio
    async def test_add_device_endpoint(self, client, family_subscription):
        """POST /devices should create a new device."""
        resp = await client.post(
            "/api/family/devices",
            params={"subscription_id": family_subscription},
            json={"device_name": "API Test Cihaz", "device_type": "laptop"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "API Test Cihaz"
        assert data["device_type"] == "laptop"
        assert data["id"]

    @pytest.mark.asyncio
    async def test_add_device_over_limit_returns_400(self, client, family_subscription):
        """POST /devices beyond limit should return 400."""
        for i in range(5):
            resp = await client.post(
                "/api/family/devices",
                params={"subscription_id": family_subscription},
                json={"device_name": f"Cihaz {i+1}"},
            )
            assert resp.status_code == 201

        # 6th should fail
        resp = await client.post(
            "/api/family/devices",
            params={"subscription_id": family_subscription},
            json={"device_name": "Cihaz 6"},
        )
        assert resp.status_code == 400
        assert "limiti" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_device_endpoint(self, client, family_subscription):
        """PUT /devices/{id} should update device fields."""
        # Create device
        create_resp = await client.post(
            "/api/family/devices",
            params={"subscription_id": family_subscription},
            json={"device_name": "Old Name"},
        )
        device_id = create_resp.json()["id"]

        # Update
        resp = await client.put(
            f"/api/family/devices/{device_id}",
            json={"name": "New Name", "owner_name": "Okan"},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "New Name"
        assert resp.json()["owner_name"] == "Okan"

    @pytest.mark.asyncio
    async def test_delete_device_endpoint(self, client, family_subscription):
        """DELETE /devices/{id} should deactivate the device."""
        # Create device
        create_resp = await client.post(
            "/api/family/devices",
            params={"subscription_id": family_subscription},
            json={"device_name": "Delete Me"},
        )
        device_id = create_resp.json()["id"]

        # Delete
        resp = await client.delete(f"/api/family/devices/{device_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_get_alerts_endpoint(self, client, family_subscription):
        """GET /alerts should return empty list when no devices."""
        resp = await client.get(
            "/api/family/alerts",
            params={"subscription_id": family_subscription},
        )
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_get_overview_endpoint(self, client, family_subscription):
        """GET /overview should return valid overview after adding devices."""
        # Add a device
        await client.post(
            "/api/family/devices",
            params={"subscription_id": family_subscription},
            json={"device_name": "Overview Test"},
        )

        resp = await client.get(
            "/api/family/overview",
            params={"subscription_id": family_subscription},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["family_name"] == "Ailem"
        assert data["max_devices"] == 5
        assert len(data["devices"]) == 1
        assert data["devices"][0]["name"] == "Overview Test"

    @pytest.mark.asyncio
    async def test_get_timeline_endpoint(self, client, family_subscription):
        """GET /timeline should return timeline entries."""
        # Add a device first
        await client.post(
            "/api/family/devices",
            params={"subscription_id": family_subscription},
            json={"device_name": "Timeline Test"},
        )

        resp = await client.get(
            "/api/family/timeline",
            params={"subscription_id": family_subscription},
        )
        assert resp.status_code == 200
        entries = resp.json()
        assert len(entries) >= 1
        assert entries[0]["event_type"] == "device_added"
