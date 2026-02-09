"""Tests for YAML rules engine."""

from pathlib import Path

from bigr.classifier.rules_engine import (
    Rule,
    RuleMatch,
    RuleSet,
    apply_hostname_rules,
    apply_port_rules,
    apply_vendor_rules,
    load_rules,
)


class TestRuleEvaluation:
    def test_port_include_all(self):
        rule = Rule(
            name="test",
            match=RuleMatch(ports_include_all=[22, 80, 443]),
            scores={"ag_ve_sistemler": 0.4},
        )
        assert rule.evaluate_ports([22, 80, 443, 8080]) is True
        assert rule.evaluate_ports([22, 80]) is False

    def test_port_include_any(self):
        rule = Rule(
            name="test",
            match=RuleMatch(ports_include_any=[9100, 554]),
            scores={"iot": 0.5},
        )
        assert rule.evaluate_ports([9100]) is True
        assert rule.evaluate_ports([554, 80]) is True
        assert rule.evaluate_ports([22, 80]) is False

    def test_port_exclude(self):
        rule = Rule(
            name="test",
            match=RuleMatch(ports_include_any=[80, 443], ports_exclude=[22]),
            scores={"uygulamalar": 0.4},
        )
        assert rule.evaluate_ports([80, 443]) is True
        assert rule.evaluate_ports([22, 80, 443]) is False

    def test_vendor_contains(self):
        rule = Rule(
            name="test",
            match=RuleMatch(vendor_contains=["Cisco", "Meraki"]),
            scores={"ag_ve_sistemler": 0.5},
        )
        assert rule.evaluate_vendor("Cisco Systems Inc") is True
        assert rule.evaluate_vendor("Cisco Meraki") is True
        assert rule.evaluate_vendor("Apple Inc") is False
        assert rule.evaluate_vendor(None) is False

    def test_hostname_pattern(self):
        rule = Rule(
            name="test",
            match=RuleMatch(hostname_pattern=r"sw[\-_]|switch"),
            scores={"ag_ve_sistemler": 0.4},
        )
        assert rule.evaluate_hostname("core-sw-01") is True
        assert rule.evaluate_hostname("switch-main") is True
        assert rule.evaluate_hostname("my-laptop") is False
        assert rule.evaluate_hostname(None) is False


class TestApplyRules:
    def test_apply_port_rules(self):
        rules = [
            Rule(name="SSH+HTTP", match=RuleMatch(ports_include_all=[22, 80]), scores={"ag_ve_sistemler": 0.4}),
            Rule(name="RTSP", match=RuleMatch(ports_include_any=[554]), scores={"iot": 0.5}),
        ]
        scores, evidence = apply_port_rules(rules, [22, 80, 443])
        assert scores["ag_ve_sistemler"] == 0.4
        assert len(evidence) == 1

    def test_apply_vendor_rules(self):
        rules = [
            Rule(name="Cisco", match=RuleMatch(vendor_contains=["Cisco"]), scores={"ag_ve_sistemler": 0.5}),
        ]
        scores, evidence = apply_vendor_rules(rules, "Cisco Systems")
        assert scores["ag_ve_sistemler"] == 0.5
        assert evidence is not None

    def test_apply_vendor_no_match(self):
        rules = [
            Rule(name="Cisco", match=RuleMatch(vendor_contains=["Cisco"]), scores={"ag_ve_sistemler": 0.5}),
        ]
        scores, evidence = apply_vendor_rules(rules, "Apple Inc")
        assert scores == {}
        assert evidence is None

    def test_apply_hostname_rules(self):
        rules = [
            Rule(name="Switch", match=RuleMatch(hostname_pattern=r"sw[\-_]"), scores={"ag_ve_sistemler": 0.4}),
            Rule(name="Camera", match=RuleMatch(hostname_pattern=r"cam[\-_]"), scores={"iot": 0.4}),
        ]
        scores, evidence = apply_hostname_rules(rules, "core-sw-01")
        assert scores["ag_ve_sistemler"] == 0.4
        assert len(evidence) == 1


class TestLoadRules:
    def test_load_project_rules(self):
        rules_dir = Path(__file__).parent.parent / "rules"
        ruleset = load_rules(rules_dir)
        assert ruleset.total_rules > 0
        assert len(ruleset.port_rules) > 0
        assert len(ruleset.vendor_rules) > 0
        assert len(ruleset.hostname_rules) > 0

    def test_load_nonexistent_dir(self):
        ruleset = load_rules("/nonexistent/path")
        assert ruleset.total_rules == 0

    def test_rules_have_valid_structure(self):
        rules_dir = Path(__file__).parent.parent / "rules"
        ruleset = load_rules(rules_dir)
        for rule in ruleset.port_rules:
            assert rule.name
            assert rule.scores
        for rule in ruleset.vendor_rules:
            assert rule.name
            assert rule.scores
        for rule in ruleset.hostname_rules:
            assert rule.name
            assert rule.scores
