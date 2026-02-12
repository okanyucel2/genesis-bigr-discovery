"""Tests for query decision engine."""

from __future__ import annotations

import pytest

from bigr.guardian.config import GuardianConfig
from bigr.guardian.dns.blocklist import BlocklistManager
from bigr.guardian.dns.decision import (
    DecisionAction,
    DecisionReason,
    QueryDecisionEngine,
)
from bigr.guardian.dns.rules import CustomRulesManager


@pytest.fixture
def blocklist():
    config = GuardianConfig()
    mgr = BlocklistManager(config)
    mgr._blocked_domains = {"ads.doubleclick.net", "malware.com", "tracker.io"}
    mgr._domain_categories = {
        "ads.doubleclick.net": "ad",
        "malware.com": "malware",
        "tracker.io": "tracker",
    }
    return mgr


@pytest.fixture
def rules():
    mgr = CustomRulesManager()
    mgr._rules = {
        "allowed.com": ("allow", "rule-allow-1", "custom"),
        "blocked-custom.com": ("block", "rule-block-1", "custom"),
    }
    return mgr


@pytest.fixture
def engine(blocklist, rules):
    return QueryDecisionEngine(
        blocklist_manager=blocklist,
        rules_manager=rules,
        sinkhole_ip="0.0.0.0",
    )


class TestDecisionPriority:
    def test_custom_allow_overrides_blocklist(self, engine: QueryDecisionEngine):
        """Custom allow should take priority over everything."""
        decision = engine.decide("allowed.com")
        assert decision.action == DecisionAction.ALLOW
        assert decision.reason == DecisionReason.CUSTOM_ALLOW
        assert decision.should_resolve is True

    def test_custom_block_overrides_default(self, engine: QueryDecisionEngine):
        decision = engine.decide("blocked-custom.com")
        assert decision.action == DecisionAction.BLOCK
        assert decision.reason == DecisionReason.CUSTOM_BLOCK
        assert decision.should_resolve is False
        assert decision.rule_id == "rule-block-1"

    def test_blocklist_blocks(self, engine: QueryDecisionEngine):
        decision = engine.decide("ads.doubleclick.net")
        assert decision.action == DecisionAction.BLOCK
        assert decision.reason == DecisionReason.BLOCKLIST
        assert decision.category == "ad"
        assert decision.should_resolve is False

    def test_default_allows(self, engine: QueryDecisionEngine):
        decision = engine.decide("example.com")
        assert decision.action == DecisionAction.ALLOW
        assert decision.reason == DecisionReason.DEFAULT_ALLOW
        assert decision.should_resolve is True


class TestDecisionSinkhole:
    def test_blocked_domain_gets_sinkhole_ip(self, engine: QueryDecisionEngine):
        decision = engine.decide("malware.com")
        assert decision.sinkhole_ip == "0.0.0.0"

    def test_allowed_domain_no_sinkhole(self, engine: QueryDecisionEngine):
        decision = engine.decide("example.com")
        assert decision.should_resolve is True

    def test_custom_sinkhole_ip(self, blocklist, rules):
        engine = QueryDecisionEngine(
            blocklist_manager=blocklist,
            rules_manager=rules,
            sinkhole_ip="127.0.0.1",
        )
        decision = engine.decide("malware.com")
        assert decision.sinkhole_ip == "127.0.0.1"


class TestDecisionEdgeCases:
    def test_trailing_dot(self, engine: QueryDecisionEngine):
        decision = engine.decide("malware.com.")
        assert decision.action == DecisionAction.BLOCK

    def test_case_insensitive(self, engine: QueryDecisionEngine):
        decision = engine.decide("MALWARE.COM")
        assert decision.action == DecisionAction.BLOCK

    def test_subdomain_of_blocked(self, engine: QueryDecisionEngine):
        decision = engine.decide("sub.malware.com")
        assert decision.action == DecisionAction.BLOCK
        assert decision.reason == DecisionReason.BLOCKLIST

    def test_custom_allow_has_rule_id(self, engine: QueryDecisionEngine):
        decision = engine.decide("allowed.com")
        assert decision.rule_id == "rule-allow-1"

    def test_blocklist_no_rule_id(self, engine: QueryDecisionEngine):
        decision = engine.decide("tracker.io")
        assert decision.rule_id is None
