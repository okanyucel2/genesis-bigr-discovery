"""Tests for bigr.shared types."""

from __future__ import annotations

from bigr.shared.threat_types import ThreatEntry, ThreatReputation
from bigr.shared.rule_types import RuleAction, RuleCategory


class TestThreatReputation:
    def test_enum_values(self):
        assert ThreatReputation.SAFE == "safe"
        assert ThreatReputation.SUSPICIOUS == "suspicious"
        assert ThreatReputation.MALICIOUS == "malicious"
        assert ThreatReputation.UNKNOWN == "unknown"

    def test_from_string(self):
        assert ThreatReputation("safe") is ThreatReputation.SAFE
        assert ThreatReputation("malicious") is ThreatReputation.MALICIOUS


class TestThreatEntry:
    def test_create_minimal(self):
        entry = ThreatEntry(indicator="evil.com", indicator_type="domain")
        assert entry.indicator == "evil.com"
        assert entry.indicator_type == "domain"
        assert entry.reputation == ThreatReputation.UNKNOWN
        assert entry.confidence == 0.0

    def test_create_full(self):
        entry = ThreatEntry(
            indicator="1.2.3.4",
            indicator_type="ip",
            reputation=ThreatReputation.MALICIOUS,
            source="abuseipdb",
            category="botnet",
            first_seen="2026-01-01",
            last_seen="2026-02-01",
            confidence=0.95,
        )
        assert entry.reputation == ThreatReputation.MALICIOUS
        assert entry.source == "abuseipdb"
        assert entry.confidence == 0.95

    def test_serialization(self):
        entry = ThreatEntry(indicator="bad.com", indicator_type="domain")
        data = entry.model_dump()
        assert data["indicator"] == "bad.com"
        assert data["reputation"] == "unknown"


class TestRuleCategory:
    def test_enum_values(self):
        assert RuleCategory.MALWARE == "malware"
        assert RuleCategory.AD == "ad"
        assert RuleCategory.TRACKER == "tracker"
        assert RuleCategory.PHISHING == "phishing"
        assert RuleCategory.CUSTOM == "custom"

    def test_all_categories(self):
        assert len(RuleCategory) == 5


class TestRuleAction:
    def test_enum_values(self):
        assert RuleAction.BLOCK == "block"
        assert RuleAction.ALLOW == "allow"

    def test_from_string(self):
        assert RuleAction("block") is RuleAction.BLOCK
        assert RuleAction("allow") is RuleAction.ALLOW
