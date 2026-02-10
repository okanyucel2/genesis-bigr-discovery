"""Tests for the Remediation engine, Dead Man Switch, and API endpoints."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from bigr.core.database import Base, get_engine, get_session_factory, reset_engine
from bigr.core.models_db import (
    AgentDB,
    AssetDB,
    RemediationActionDB,
    ScanAssetDB,
    ScanDB,
    ShieldFindingDB,
    ShieldScanDB,
)
from bigr.dashboard.app import create_app
from bigr.remediation.deadman import DeadManSwitch
from bigr.remediation.engine import RemediationEngine
from bigr.remediation.models import DeadManSwitchConfig, DeadManSwitchStatus


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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
async def seeded_db(setup_db):
    """Seed test data: assets, scans, agents, shield findings."""
    factory = get_session_factory()
    now_iso = datetime.now(timezone.utc).isoformat()
    five_min_ago = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    two_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()

    async with factory() as session:
        # Agent (alive)
        agent_alive = AgentDB(
            id="agent-alive",
            name="Office-Agent",
            site_name="HQ",
            token_hash="hash1",
            is_active=1,
            registered_at=now_iso,
            last_seen=five_min_ago,
            status="online",
        )
        # Agent (dead / no heartbeat for 2 hours)
        agent_dead = AgentDB(
            id="agent-dead",
            name="Remote-Agent",
            site_name="Branch",
            token_hash="hash2",
            is_active=1,
            registered_at=now_iso,
            last_seen=two_hours_ago,
            status="online",
        )
        # Agent (never reported)
        agent_ghost = AgentDB(
            id="agent-ghost",
            name="Ghost-Agent",
            site_name="Unknown",
            token_hash="hash3",
            is_active=1,
            registered_at=now_iso,
            last_seen=None,
            status="offline",
        )

        # Scan + assets with risky ports
        scan = ScanDB(
            id="scan-r1",
            target="10.0.0.0/24",
            scan_method="active",
            started_at=now_iso,
            completed_at=now_iso,
            total_assets=3,
            is_root=0,
        )
        asset_risky = AssetDB(
            id="a-risky",
            ip="10.0.0.50",
            mac="aa:bb:cc:dd:ee:01",
            hostname="risky.local",
            bigr_category="uygulamalar",
            confidence_score=0.8,
            scan_method="active",
            first_seen=now_iso,
            last_seen=now_iso,
            agent_id="agent-alive",
        )
        asset_safe = AssetDB(
            id="a-safe",
            ip="10.0.0.1",
            mac="aa:bb:cc:dd:ee:02",
            hostname="gw.local",
            bigr_category="ag_ve_sistemler",
            confidence_score=0.9,
            scan_method="active",
            first_seen=now_iso,
            last_seen=now_iso,
        )
        asset_noport = AssetDB(
            id="a-noport",
            ip="10.0.0.200",
            mac="aa:bb:cc:dd:ee:03",
            hostname="clean.local",
            bigr_category="tasinabilir",
            confidence_score=0.7,
            scan_method="active",
            first_seen=now_iso,
            last_seen=now_iso,
        )

        # Scan assets: risky has FTP, Telnet, SMB; safe has SSH, HTTPS; noport has nothing
        sa_risky = ScanAssetDB(
            scan_id="scan-r1",
            asset_id="a-risky",
            open_ports=json.dumps([21, 23, 445, 80]),
            confidence_score=0.8,
            bigr_category="uygulamalar",
        )
        sa_safe = ScanAssetDB(
            scan_id="scan-r1",
            asset_id="a-safe",
            open_ports=json.dumps([22, 443]),
            confidence_score=0.9,
            bigr_category="ag_ve_sistemler",
        )
        sa_noport = ScanAssetDB(
            scan_id="scan-r1",
            asset_id="a-noport",
            open_ports=json.dumps([]),
            confidence_score=0.7,
            bigr_category="tasinabilir",
        )

        # Shield scan + findings
        shield_scan = ShieldScanDB(
            id="shield-s1",
            agent_id="agent-alive",
            site_name="HQ",
            target="10.0.0.50",
            started_at=now_iso,
            completed_at=now_iso,
        )
        finding = ShieldFindingDB(
            scan_id="shield-s1",
            module="port_scan",
            severity="high",
            title="Weak SSH Config",
            detail="SSH allows password authentication",
            target_ip="10.0.0.50",
            remediation="Disable password auth, use keys only.",
        )

        session.add_all([
            agent_alive,
            agent_dead,
            agent_ghost,
            scan,
            asset_risky,
            asset_safe,
            asset_noport,
            sa_risky,
            sa_safe,
            sa_noport,
            shield_scan,
            finding,
        ])
        await session.commit()


@pytest.fixture
def app():
    return create_app(data_path="/tmp/__nonexistent_bigr_test__.json")


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# RemediationEngine unit tests
# ---------------------------------------------------------------------------


class TestRemediationEnginePortRemediation:
    """Test port-based remediation generation."""

    def test_high_risk_ports_generate_actions(self):
        engine = RemediationEngine()
        actions = engine._port_remediations("10.0.0.1", [21, 23, 445])
        assert len(actions) == 3
        assert actions[0].target_port == 21
        assert actions[0].severity == "high"
        assert actions[1].target_port == 23
        assert actions[1].severity == "critical"
        assert actions[2].target_port == 445
        assert actions[2].severity == "critical"

    def test_safe_ports_no_actions(self):
        engine = RemediationEngine()
        actions = engine._port_remediations("10.0.0.1", [22, 80, 443])
        assert len(actions) == 0

    def test_empty_ports_no_actions(self):
        engine = RemediationEngine()
        actions = engine._port_remediations("10.0.0.1", [])
        assert len(actions) == 0

    def test_mixed_ports_only_risky(self):
        engine = RemediationEngine()
        actions = engine._port_remediations("10.0.0.1", [22, 3389, 443, 6379])
        assert len(actions) == 2
        port_numbers = [a.target_port for a in actions]
        assert 3389 in port_numbers
        assert 6379 in port_numbers

    def test_action_has_turkish_text(self):
        engine = RemediationEngine()
        actions = engine._port_remediations("10.0.0.1", [27017])
        assert len(actions) == 1
        assert "MongoDB" in actions[0].title_tr
        assert actions[0].auto_fixable is True

    def test_action_id_format(self):
        engine = RemediationEngine()
        actions = engine._port_remediations("192.168.1.1", [21])
        assert actions[0].id == "port-192.168.1.1-21"

    def test_all_high_risk_ports_covered(self):
        """Verify all key ports from the spec produce actions."""
        engine = RemediationEngine()
        spec_ports = [21, 23, 445, 3389, 5900, 6379, 27017]
        for port in spec_ports:
            actions = engine._port_remediations("10.0.0.1", [port])
            assert len(actions) == 1, f"Port {port} should generate an action"


class TestRemediationEnginePlan:
    """Test plan generation from database."""

    async def test_generate_plan_risky_asset(self, seeded_db):
        engine = RemediationEngine()
        factory = get_session_factory()
        async with factory() as session:
            plan = await engine.generate_plan("10.0.0.50", session)

        assert plan.asset_ip == "10.0.0.50"
        assert plan.total_actions >= 3  # FTP + Telnet + SMB + maybe finding
        assert plan.critical_count >= 2  # Telnet + SMB are critical
        assert plan.auto_fixable_count >= 3

    async def test_generate_plan_safe_asset(self, seeded_db):
        engine = RemediationEngine()
        factory = get_session_factory()
        async with factory() as session:
            plan = await engine.generate_plan("10.0.0.1", session)

        assert plan.asset_ip == "10.0.0.1"
        assert plan.total_actions == 0  # Only SSH and HTTPS — both safe

    async def test_generate_plan_clean_asset(self, seeded_db):
        engine = RemediationEngine()
        factory = get_session_factory()
        async with factory() as session:
            plan = await engine.generate_plan("10.0.0.200", session)

        assert plan.asset_ip == "10.0.0.200"
        assert plan.total_actions == 0

    async def test_generate_plan_unknown_ip(self, seeded_db):
        engine = RemediationEngine()
        factory = get_session_factory()
        async with factory() as session:
            plan = await engine.generate_plan("99.99.99.99", session)

        assert plan.asset_ip == "99.99.99.99"
        assert plan.total_actions == 0

    async def test_generate_network_plan(self, seeded_db):
        engine = RemediationEngine()
        factory = get_session_factory()
        async with factory() as session:
            plan = await engine.generate_network_plan(session)

        assert plan.asset_ip is None
        assert plan.total_actions >= 3  # At least FTP + Telnet + SMB from risky asset

    async def test_shield_findings_included(self, seeded_db):
        engine = RemediationEngine()
        factory = get_session_factory()
        async with factory() as session:
            plan = await engine.generate_plan("10.0.0.50", session)

        finding_actions = [a for a in plan.actions if a.id.startswith("finding-")]
        assert len(finding_actions) >= 1
        assert "Weak SSH Config" in finding_actions[0].title


class TestRemediationExecute:
    """Test remediation action execution."""

    async def test_execute_with_agent(self, seeded_db):
        engine = RemediationEngine()
        factory = get_session_factory()
        async with factory() as session:
            result = await engine.execute_action("port-10.0.0.50-21", session)

        assert result["status"] == "ok"
        assert "command_id" in result
        assert result["agent_id"] == "agent-alive"

    async def test_execute_without_agent(self, seeded_db):
        engine = RemediationEngine()
        factory = get_session_factory()
        async with factory() as session:
            result = await engine.execute_action("port-10.0.0.1-22", session)

        # asset 10.0.0.1 has no agent_id
        assert result["status"] == "manual"

    async def test_execute_invalid_action(self, seeded_db):
        engine = RemediationEngine()
        factory = get_session_factory()
        async with factory() as session:
            result = await engine.execute_action("invalid", session)

        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# DeadManSwitch unit tests
# ---------------------------------------------------------------------------


class TestDeadManSwitch:
    """Test Dead Man Switch logic."""

    async def test_alive_agent(self, seeded_db):
        switch = DeadManSwitch(DeadManSwitchConfig(timeout_minutes=30))
        factory = get_session_factory()
        async with factory() as session:
            status = await switch.get_status("agent-alive", session)

        assert status is not None
        assert status.is_alive is True
        assert status.alert_triggered is False
        assert status.agent_name == "Office-Agent"

    async def test_dead_agent(self, seeded_db):
        switch = DeadManSwitch(DeadManSwitchConfig(timeout_minutes=30))
        factory = get_session_factory()
        async with factory() as session:
            status = await switch.get_status("agent-dead", session)

        assert status is not None
        assert status.is_alive is False
        assert status.alert_triggered is True
        assert status.minutes_since_heartbeat is not None
        assert status.minutes_since_heartbeat > 30

    async def test_ghost_agent_never_reported(self, seeded_db):
        switch = DeadManSwitch(DeadManSwitchConfig(timeout_minutes=30))
        factory = get_session_factory()
        async with factory() as session:
            status = await switch.get_status("agent-ghost", session)

        assert status is not None
        assert status.is_alive is False
        assert status.last_heartbeat is None

    async def test_nonexistent_agent(self, seeded_db):
        switch = DeadManSwitch()
        factory = get_session_factory()
        async with factory() as session:
            status = await switch.get_status("nonexistent", session)

        assert status is None

    async def test_check_all_agents(self, seeded_db):
        switch = DeadManSwitch(DeadManSwitchConfig(timeout_minutes=30))
        factory = get_session_factory()
        async with factory() as session:
            statuses = await switch.check_agents(session)

        assert len(statuses) == 3
        alive = [s for s in statuses if s.is_alive]
        dead = [s for s in statuses if not s.is_alive]
        assert len(alive) == 1
        assert len(dead) == 2

    async def test_config_update(self):
        switch = DeadManSwitch()
        assert switch.config.timeout_minutes == 30

        new_config = DeadManSwitchConfig(timeout_minutes=60, enabled=False)
        await switch.update_config(new_config)
        assert switch.config.timeout_minutes == 60
        assert switch.config.enabled is False

    async def test_disabled_switch_no_alerts(self, seeded_db):
        switch = DeadManSwitch(DeadManSwitchConfig(enabled=False))
        factory = get_session_factory()
        async with factory() as session:
            statuses = await switch.check_agents(session)

        alerts = [s for s in statuses if s.alert_triggered]
        assert len(alerts) == 0

    async def test_trigger_alert_returns_message(self):
        switch = DeadManSwitch()
        result = await switch.trigger_alert("agent-test", 45.0)
        assert result["status"] == "alert_sent"
        assert "45" in result["message_tr"]

    async def test_alert_suppression(self):
        switch = DeadManSwitch()
        # First alert should send
        result1 = await switch.trigger_alert("agent-test", 45.0)
        assert result1["status"] == "alert_sent"
        # Second alert within 10 min should be suppressed
        result2 = await switch.trigger_alert("agent-test", 46.0)
        assert result2["status"] == "suppressed"


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


class TestRemediationAPI:
    """Test remediation API endpoints."""

    async def test_get_plan_for_ip(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/remediation/plan/10.0.0.50")
        assert resp.status_code == 200
        data = resp.json()
        assert data["asset_ip"] == "10.0.0.50"
        assert data["total_actions"] >= 3

    async def test_get_plan_safe_ip(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/remediation/plan/10.0.0.1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_actions"] == 0

    async def test_get_network_plan(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/remediation/plan")
        assert resp.status_code == 200
        data = resp.json()
        assert data["asset_ip"] is None
        assert data["total_actions"] >= 3

    async def test_execute_action(self, client: AsyncClient, seeded_db):
        resp = await client.post("/api/remediation/execute/port-10.0.0.50-21")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    async def test_get_history_empty(self, client: AsyncClient, setup_db):
        resp = await client.get("/api/remediation/history")
        assert resp.status_code == 200
        data = resp.json()
        assert data["history"] == []

    async def test_get_history_after_execution(self, client: AsyncClient, seeded_db):
        # Execute an action first
        await client.post("/api/remediation/execute/port-10.0.0.50-21")
        # Then check history
        resp = await client.get("/api/remediation/history")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["history"]) >= 1


class TestDeadManAPI:
    """Test Dead Man Switch API endpoints."""

    async def test_get_status(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/deadman/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_agents"] == 3
        assert data["alive_count"] == 1
        assert "summary_tr" in data

    async def test_get_agent_status(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/deadman/status/agent-alive")
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_alive"] is True

    async def test_get_agent_status_not_found(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/deadman/status/nonexistent")
        assert resp.status_code == 404

    async def test_update_config(self, client: AsyncClient, setup_db):
        resp = await client.put(
            "/api/deadman/config",
            json={"enabled": True, "timeout_minutes": 60},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["config"]["timeout_minutes"] == 60

    async def test_force_check(self, client: AsyncClient, seeded_db):
        resp = await client.post("/api/deadman/check")
        assert resp.status_code == 200
        data = resp.json()
        assert data["checked"] == 3
        assert "message_tr" in data


# ---------------------------------------------------------------------------
# Pydantic model tests
# ---------------------------------------------------------------------------


class TestPydanticModels:
    def test_deadman_config_defaults(self):
        config = DeadManSwitchConfig()
        assert config.enabled is True
        assert config.timeout_minutes == 30
        assert config.alert_email is None
        assert config.alert_webhook is None

    def test_deadman_status_serialization(self):
        status = DeadManSwitchStatus(
            agent_id="test-1",
            agent_name="Test Agent",
            last_heartbeat="2026-02-10T10:00:00Z",
            minutes_since_heartbeat=5.0,
            is_alive=True,
            alert_triggered=False,
        )
        data = status.model_dump()
        assert data["agent_id"] == "test-1"
        assert data["is_alive"] is True
