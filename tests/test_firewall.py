"""Tests for the Firewall module — rule engine, service, adapter, and API endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from bigr.core.database import Base, get_engine, get_session_factory, reset_engine
from bigr.core.models_db import FirewallEventDB, FirewallRuleDB
from bigr.dashboard.app import create_app
from bigr.firewall.adapters.macos import MacOSFirewallAdapter
from bigr.firewall.models import (
    FirewallConfig,
    FirewallEvent,
    FirewallRule,
    FirewallStatus,
)
from bigr.firewall.rule_engine import FirewallRuleEngine
from bigr.firewall.service import FirewallService


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
    """Seed test data: firewall rules and events."""
    factory = get_session_factory()
    now_iso = datetime.now(timezone.utc).isoformat()

    async with factory() as session:
        # Block IP rule
        rule_ip = FirewallRuleDB(
            id="rule-ip-block",
            rule_type="block_ip",
            target="10.0.0.99",
            direction="both",
            protocol="any",
            source="threat_intel",
            reason="Known malicious IP",
            reason_tr="Bilinen zararli IP",
            is_active=1,
            created_at=now_iso,
            hit_count=5,
        )
        # Block port rule
        rule_port = FirewallRuleDB(
            id="rule-port-block",
            rule_type="block_port",
            target="23",
            direction="inbound",
            protocol="tcp",
            source="remediation",
            reason="Telnet",
            reason_tr="Telnet - sifrelenmemis protokol",
            is_active=1,
            created_at=now_iso,
            hit_count=12,
        )
        # Allow IP rule
        rule_allow = FirewallRuleDB(
            id="rule-ip-allow",
            rule_type="allow_ip",
            target="192.168.1.1",
            direction="both",
            protocol="any",
            source="user",
            reason="Trusted gateway",
            reason_tr="Guvenilir ag gecidi",
            is_active=1,
            created_at=now_iso,
            hit_count=0,
        )
        # Block domain rule
        rule_domain = FirewallRuleDB(
            id="rule-domain-block",
            rule_type="block_domain",
            target="malware.example.com",
            direction="outbound",
            protocol="tcp",
            source="threat_intel",
            reason="Malware C2 domain",
            reason_tr="Zararli yazilim C2 domaini",
            is_active=1,
            created_at=now_iso,
            hit_count=3,
        )
        # Inactive rule
        rule_inactive = FirewallRuleDB(
            id="rule-inactive",
            rule_type="block_ip",
            target="172.16.0.1",
            direction="both",
            protocol="any",
            source="user",
            reason="Temporarily disabled",
            reason_tr="Gecici olarak devre disi",
            is_active=0,
            created_at=now_iso,
            hit_count=0,
        )

        # Events
        event_blocked = FirewallEventDB(
            id="evt-1",
            timestamp=now_iso,
            action="blocked",
            rule_id="rule-ip-block",
            source_ip="192.168.1.50",
            dest_ip="10.0.0.99",
            dest_port=443,
            protocol="tcp",
            process_name="curl",
            direction="outbound",
        )
        event_allowed = FirewallEventDB(
            id="evt-2",
            timestamp=now_iso,
            action="allowed",
            rule_id=None,
            source_ip="192.168.1.50",
            dest_ip="8.8.8.8",
            dest_port=53,
            protocol="udp",
            process_name="chrome",
            direction="outbound",
        )

        session.add_all([
            rule_ip,
            rule_port,
            rule_allow,
            rule_domain,
            rule_inactive,
            event_blocked,
            event_allowed,
        ])
        await session.commit()


@pytest.fixture
def app():
    return create_app(data_path="/tmp/__nonexistent_bigr_fw_test__.json")


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# FirewallRuleEngine unit tests
# ---------------------------------------------------------------------------


class TestRuleEngineIPBlock:
    """Test IP block matching."""

    def test_ip_block_matches(self):
        engine = FirewallRuleEngine()
        engine.load_rules([
            FirewallRule(
                id="r1",
                rule_type="block_ip",
                target="10.0.0.99",
                source="threat_intel",
                reason="malicious",
                reason_tr="zararli",
            ),
        ])
        action, rule = engine.evaluate("10.0.0.99", 443)
        assert action == "blocked"
        assert rule is not None
        assert rule.target == "10.0.0.99"

    def test_ip_allow_overrides_block(self):
        """Whitelist ALWAYS wins over blacklist."""
        engine = FirewallRuleEngine()
        engine.load_rules([
            FirewallRule(
                id="r-block",
                rule_type="block_ip",
                target="10.0.0.99",
                source="threat_intel",
                reason="malicious",
                reason_tr="zararli",
            ),
            FirewallRule(
                id="r-allow",
                rule_type="allow_ip",
                target="10.0.0.99",
                source="user",
                reason="whitelisted",
                reason_tr="beyaz listede",
            ),
        ])
        action, rule = engine.evaluate("10.0.0.99", 443)
        assert action == "allowed"
        assert rule is None

    def test_unmatched_ip_allowed_by_default(self):
        engine = FirewallRuleEngine()
        engine.load_rules([
            FirewallRule(
                id="r1",
                rule_type="block_ip",
                target="10.0.0.99",
                source="threat_intel",
                reason="malicious",
                reason_tr="zararli",
            ),
        ])
        action, rule = engine.evaluate("8.8.8.8", 53)
        assert action == "allowed"
        assert rule is None


class TestRuleEnginePortBlock:
    """Test port block matching."""

    def test_port_block(self):
        engine = FirewallRuleEngine()
        engine.load_rules([
            FirewallRule(
                id="r1",
                rule_type="block_port",
                target="23",
                source="remediation",
                reason="telnet",
                reason_tr="telnet",
            ),
        ])
        action, rule = engine.evaluate("192.168.1.1", 23)
        assert action == "blocked"
        assert rule is not None
        assert rule.target == "23"

    def test_safe_port_allowed(self):
        engine = FirewallRuleEngine()
        engine.load_rules([
            FirewallRule(
                id="r1",
                rule_type="block_port",
                target="23",
                source="remediation",
                reason="telnet",
                reason_tr="telnet",
            ),
        ])
        action, rule = engine.evaluate("192.168.1.1", 443)
        assert action == "allowed"
        assert rule is None


class TestRuleEngineDomainBlock:
    """Test domain block matching."""

    def test_domain_block(self):
        engine = FirewallRuleEngine()
        engine.load_rules([
            FirewallRule(
                id="r1",
                rule_type="block_domain",
                target="malware.example.com",
                source="threat_intel",
                reason="c2",
                reason_tr="c2 domaini",
            ),
        ])
        action, rule = engine.evaluate("1.2.3.4", 443, domain="malware.example.com")
        assert action == "blocked"
        assert rule is not None

    def test_domain_allow_overrides_block(self):
        engine = FirewallRuleEngine()
        engine.load_rules([
            FirewallRule(
                id="r-block",
                rule_type="block_domain",
                target="example.com",
                source="threat_intel",
                reason="blocked",
                reason_tr="engellendi",
            ),
            FirewallRule(
                id="r-allow",
                rule_type="allow_domain",
                target="example.com",
                source="user",
                reason="whitelisted",
                reason_tr="beyaz listede",
            ),
        ])
        action, rule = engine.evaluate("1.2.3.4", 443, domain="example.com")
        assert action == "allowed"

    def test_domain_case_insensitive(self):
        engine = FirewallRuleEngine()
        engine.load_rules([
            FirewallRule(
                id="r1",
                rule_type="block_domain",
                target="MALWARE.Example.COM",
                source="threat_intel",
                reason="c2",
                reason_tr="c2",
            ),
        ])
        action, rule = engine.evaluate("1.2.3.4", 443, domain="malware.example.com")
        assert action == "blocked"


class TestRuleEngineLoading:
    """Test rule loading and stats."""

    def test_load_rules_builds_sets(self):
        engine = FirewallRuleEngine()
        rules = [
            FirewallRule(id="1", rule_type="block_ip", target="1.1.1.1", source="user", reason="", reason_tr=""),
            FirewallRule(id="2", rule_type="block_ip", target="2.2.2.2", source="user", reason="", reason_tr=""),
            FirewallRule(id="3", rule_type="allow_ip", target="3.3.3.3", source="user", reason="", reason_tr=""),
            FirewallRule(id="4", rule_type="block_port", target="21", source="user", reason="", reason_tr=""),
            FirewallRule(id="5", rule_type="block_domain", target="evil.com", source="user", reason="", reason_tr=""),
            FirewallRule(id="6", rule_type="allow_domain", target="good.com", source="user", reason="", reason_tr=""),
        ]
        engine.load_rules(rules)
        stats = engine.stats
        assert stats["total_rules"] == 6
        assert stats["ip_blocks"] == 2
        assert stats["ip_allows"] == 1
        assert stats["port_blocks"] == 1
        assert stats["domain_blocks"] == 1
        assert stats["domain_allows"] == 1

    def test_stats_calculation(self):
        engine = FirewallRuleEngine()
        engine.load_rules([])
        stats = engine.stats
        assert stats["total_rules"] == 0
        assert stats["ip_blocks"] == 0

    def test_inactive_rules_ignored(self):
        engine = FirewallRuleEngine()
        engine.load_rules([
            FirewallRule(
                id="r1",
                rule_type="block_ip",
                target="10.0.0.1",
                is_active=False,
                source="user",
                reason="",
                reason_tr="",
            ),
        ])
        action, rule = engine.evaluate("10.0.0.1", 443)
        assert action == "allowed"
        assert rule is None
        assert engine.stats["total_rules"] == 0

    def test_default_allow_when_no_rules(self):
        engine = FirewallRuleEngine()
        engine.load_rules([])
        action, rule = engine.evaluate("1.2.3.4", 80)
        assert action == "allowed"
        assert rule is None


# ---------------------------------------------------------------------------
# FirewallService tests
# ---------------------------------------------------------------------------


class TestFirewallServiceRules:
    """Test FirewallService rule operations."""

    async def test_add_rule_persists(self, setup_db):
        service = FirewallService()
        factory = get_session_factory()
        async with factory() as session:
            rule = FirewallRule(
                id=str(uuid.uuid4()),
                rule_type="block_ip",
                target="10.10.10.10",
                source="user",
                reason="test",
                reason_tr="test",
            )
            created = await service.add_rule(rule, session)
            assert created.target == "10.10.10.10"

            # Verify it's retrievable
            rules = await service.get_rules(session)
            assert len(rules) == 1
            assert rules[0].target == "10.10.10.10"

    async def test_remove_rule_deactivates(self, seeded_db):
        service = FirewallService()
        factory = get_session_factory()
        async with factory() as session:
            result = await service.remove_rule("rule-ip-block", session)
            assert result["status"] == "ok"

            # Verify it's deactivated
            rules = await service.get_rules(session, active_only=True)
            ids = [r.id for r in rules]
            assert "rule-ip-block" not in ids

    async def test_toggle_rule_flips_state(self, seeded_db):
        service = FirewallService()
        factory = get_session_factory()
        async with factory() as session:
            # Active -> Inactive
            toggled = await service.toggle_rule("rule-ip-block", session)
            assert toggled is not None
            assert toggled.is_active is False

            # Inactive -> Active
            toggled2 = await service.toggle_rule("rule-ip-block", session)
            assert toggled2 is not None
            assert toggled2.is_active is True

    async def test_get_rules_filtered(self, seeded_db):
        service = FirewallService()
        factory = get_session_factory()
        async with factory() as session:
            block_rules = await service.get_rules(session, rule_type="block_ip")
            assert len(block_rules) == 1
            assert block_rules[0].target == "10.0.0.99"

    async def test_toggle_nonexistent_returns_none(self, setup_db):
        service = FirewallService()
        factory = get_session_factory()
        async with factory() as session:
            result = await service.toggle_rule("nonexistent", session)
            assert result is None


class TestFirewallServiceEvents:
    """Test FirewallService event operations."""

    async def test_log_event_and_get_events(self, setup_db):
        service = FirewallService()
        factory = get_session_factory()
        now_iso = datetime.now(timezone.utc).isoformat()
        async with factory() as session:
            event = FirewallEvent(
                id=str(uuid.uuid4()),
                timestamp=now_iso,
                action="blocked",
                source_ip="192.168.1.100",
                dest_ip="10.0.0.99",
                dest_port=443,
                protocol="tcp",
                process_name="wget",
                direction="outbound",
            )
            await service.log_event(event, session)

            events = await service.get_events(session)
            assert len(events) == 1
            assert events[0].action == "blocked"
            assert events[0].dest_ip == "10.0.0.99"

    async def test_get_events_filtered_by_action(self, seeded_db):
        service = FirewallService()
        factory = get_session_factory()
        async with factory() as session:
            blocked = await service.get_events(session, action="blocked")
            assert len(blocked) == 1
            assert blocked[0].action == "blocked"

            allowed = await service.get_events(session, action="allowed")
            assert len(allowed) == 1
            assert allowed[0].action == "allowed"


class TestFirewallServiceStatus:
    """Test FirewallService status."""

    async def test_get_status(self, seeded_db):
        service = FirewallService()
        factory = get_session_factory()
        async with factory() as session:
            status = await service.get_status(session)
            assert status.total_rules == 5  # 4 active + 1 inactive
            assert status.active_rules == 4
            assert status.is_enabled is True

    async def test_get_daily_stats(self, seeded_db):
        service = FirewallService()
        factory = get_session_factory()
        async with factory() as session:
            stats = await service.get_daily_stats(session)
            assert stats["blocked"] == 1
            assert stats["allowed"] == 1
            assert stats["total"] == 2


class TestFirewallServiceSync:
    """Test rule synchronization."""

    async def test_sync_port_rules(self, setup_db):
        service = FirewallService()
        factory = get_session_factory()
        async with factory() as session:
            result = await service.sync_port_rules(session)
            assert result["status"] == "ok"
            assert result["rules_created"] > 0

            # Verify rules were created
            rules = await service.get_rules(session, rule_type="block_port")
            assert len(rules) > 0

    async def test_sync_port_rules_idempotent(self, setup_db):
        service = FirewallService()
        factory = get_session_factory()
        async with factory() as session:
            result1 = await service.sync_port_rules(session)
            result2 = await service.sync_port_rules(session)
            # Second sync should create 0 new rules
            assert result2["rules_created"] == 0


class TestFirewallServiceConfig:
    """Test config operations."""

    async def test_get_config(self):
        service = FirewallService()
        config = await service.get_config()
        assert config.enabled is True
        assert config.default_action == "allow"

    async def test_update_config(self):
        service = FirewallService()
        new_config = FirewallConfig(
            enabled=False,
            default_action="block",
            protection_level="strict",
        )
        updated = await service.update_config(new_config)
        assert updated.enabled is False
        assert updated.default_action == "block"
        assert updated.protection_level == "strict"


# ---------------------------------------------------------------------------
# MacOS Adapter tests
# ---------------------------------------------------------------------------


class TestMacOSAdapter:
    """Test macOS NEFilterDataProvider adapter (stubbed)."""

    async def test_install_returns_stub(self):
        adapter = MacOSFirewallAdapter()
        result = await adapter.install()
        # Either stub (on macOS) or error (on other platforms)
        assert result["status"] in ("stub", "error")

    async def test_apply_rules_counts(self):
        adapter = MacOSFirewallAdapter()
        rules = [
            FirewallRule(
                id="r1",
                rule_type="block_ip",
                target="1.1.1.1",
                source="user",
                reason="",
                reason_tr="",
            ),
            FirewallRule(
                id="r2",
                rule_type="block_port",
                target="23",
                source="user",
                reason="",
                reason_tr="",
            ),
        ]
        result = await adapter.apply_rules(rules)
        assert result["rules_pushed"] == 2

    async def test_platform_name(self):
        adapter = MacOSFirewallAdapter()
        assert adapter.platform_name() == "macos"

    async def test_get_status_before_install(self):
        adapter = MacOSFirewallAdapter()
        status = await adapter.get_status()
        assert status["is_installed"] is False
        assert status["platform"] == "macos"
        assert status["engine"] == "ne_filter"

    async def test_uninstall(self):
        adapter = MacOSFirewallAdapter()
        await adapter.install()
        result = await adapter.uninstall()
        assert result["status"] == "ok"
        status = await adapter.get_status()
        assert status["is_installed"] is False


# ---------------------------------------------------------------------------
# Pydantic model tests
# ---------------------------------------------------------------------------


class TestPydanticModels:
    """Test Pydantic model serialization."""

    def test_firewall_rule_defaults(self):
        rule = FirewallRule(
            id="test",
            rule_type="block_ip",
            target="1.1.1.1",
            source="user",
            reason="test",
            reason_tr="test",
        )
        assert rule.direction == "both"
        assert rule.protocol == "any"
        assert rule.is_active is True
        assert rule.hit_count == 0
        assert rule.expires_at is None

    def test_firewall_config_defaults(self):
        config = FirewallConfig()
        assert config.enabled is True
        assert config.default_action == "allow"
        assert config.block_known_threats is True
        assert config.protection_level == "balanced"

    def test_firewall_status_serialization(self):
        status = FirewallStatus(
            is_enabled=True,
            platform="macos",
            engine="ne_filter",
            total_rules=10,
            active_rules=8,
            blocked_today=50,
            allowed_today=200,
            last_updated="2026-02-10T12:00:00Z",
            protection_level="balanced",
        )
        data = status.model_dump()
        assert data["is_enabled"] is True
        assert data["platform"] == "macos"
        assert data["blocked_today"] == 50


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


class TestFirewallAPI:
    """Test firewall API endpoints."""

    async def test_get_status(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/firewall/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "is_enabled" in data
        assert data["total_rules"] == 5

    async def test_get_rules(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/firewall/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 4  # 4 active rules
        assert len(data["rules"]) >= 4

    async def test_get_rules_filtered(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/firewall/rules", params={"rule_type": "block_ip"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert all(r["rule_type"] == "block_ip" for r in data["rules"])

    async def test_add_rule(self, client: AsyncClient, setup_db):
        resp = await client.post(
            "/api/firewall/rules",
            json={
                "id": "new-rule",
                "rule_type": "block_ip",
                "target": "5.5.5.5",
                "direction": "both",
                "protocol": "any",
                "source": "user",
                "reason": "test",
                "reason_tr": "test kurali",
                "is_active": True,
                "created_at": "",
                "expires_at": None,
                "hit_count": 0,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["rule"]["target"] == "5.5.5.5"

    async def test_remove_rule(self, client: AsyncClient, seeded_db):
        resp = await client.delete("/api/firewall/rules/rule-ip-block")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    async def test_remove_nonexistent_rule(self, client: AsyncClient, setup_db):
        resp = await client.delete("/api/firewall/rules/nonexistent")
        assert resp.status_code == 404

    async def test_toggle_rule(self, client: AsyncClient, seeded_db):
        resp = await client.put("/api/firewall/rules/rule-ip-block/toggle")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["rule"]["is_active"] is False

    async def test_toggle_nonexistent_rule(self, client: AsyncClient, setup_db):
        resp = await client.put("/api/firewall/rules/nonexistent/toggle")
        assert resp.status_code == 404

    async def test_sync_ports(self, client: AsyncClient, setup_db):
        resp = await client.post("/api/firewall/sync/ports")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["rules_created"] > 0

    async def test_get_events(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/firewall/events")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2

    async def test_get_events_filtered(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/firewall/events", params={"action": "blocked"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["events"][0]["action"] == "blocked"

    async def test_get_config(self, client: AsyncClient, setup_db):
        resp = await client.get("/api/firewall/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled"] is True
        assert data["default_action"] == "allow"

    async def test_update_config(self, client: AsyncClient, setup_db):
        resp = await client.put(
            "/api/firewall/config",
            json={
                "enabled": False,
                "default_action": "block",
                "block_known_threats": True,
                "block_high_risk_ports": True,
                "log_allowed": True,
                "auto_sync_threats": False,
                "protection_level": "strict",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["config"]["enabled"] is False
        assert data["config"]["protection_level"] == "strict"

    async def test_get_daily_stats(self, client: AsyncClient, seeded_db):
        resp = await client.get("/api/firewall/stats/daily")
        assert resp.status_code == 200
        data = resp.json()
        assert "blocked" in data
        assert "allowed" in data
        assert "block_rate" in data

    async def test_install_adapter(self, client: AsyncClient, setup_db):
        resp = await client.post("/api/firewall/adapter/install")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("stub", "error")
