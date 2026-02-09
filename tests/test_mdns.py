"""Tests for mDNS/Bonjour service discovery and classification."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from bigr.classifier.bigr_mapper import ClassificationScores, score_by_services
from bigr.classifier.rules_engine import (
    Rule,
    RuleMatch,
    apply_service_rules,
    load_rules,
)
from bigr.models import Asset
from bigr.scanner.mdns import MdnsService, enrich_assets_with_mdns


class TestMdnsServiceDataclass:
    def test_create_basic(self):
        svc = MdnsService(
            name="Living Room Speaker._googlecast._tcp.local.",
            service_type="_googlecast._tcp.local.",
            ip="192.168.1.50",
            port=8009,
        )
        assert svc.name == "Living Room Speaker._googlecast._tcp.local."
        assert svc.service_type == "_googlecast._tcp.local."
        assert svc.ip == "192.168.1.50"
        assert svc.port == 8009
        assert svc.hostname is None
        assert svc.properties == {}

    def test_create_with_all_fields(self):
        svc = MdnsService(
            name="HP LaserJet._ipp._tcp.local.",
            service_type="_ipp._tcp.local.",
            ip="192.168.1.100",
            port=631,
            hostname="hplaserjet.local.",
            properties={"ty": "HP LaserJet Pro", "pdl": "application/pdf"},
        )
        assert svc.hostname == "hplaserjet.local."
        assert svc.properties["ty"] == "HP LaserJet Pro"


class TestEnrichAssetsWithMdns:
    def test_matches_by_ip(self):
        assets = [
            Asset(ip="192.168.1.50", mac="aa:bb:cc:dd:ee:01"),
            Asset(ip="192.168.1.60", mac="aa:bb:cc:dd:ee:02"),
        ]
        services = [
            MdnsService(
                name="Chromecast._googlecast._tcp.local.",
                service_type="_googlecast._tcp.local.",
                ip="192.168.1.50",
                port=8009,
                hostname="chromecast-abc.local.",
                properties={"fn": "Living Room"},
            ),
        ]
        result = enrich_assets_with_mdns(assets, services)

        # First asset should be enriched
        assert result[0].raw_evidence.get("mdns_services") is not None
        assert len(result[0].raw_evidence["mdns_services"]) == 1
        assert result[0].raw_evidence["mdns_services"][0]["service_type"] == "_googlecast._tcp.local."

        # Second asset should NOT be enriched
        assert result[1].raw_evidence.get("mdns_services") is None

    def test_adds_hostname(self):
        assets = [Asset(ip="192.168.1.50", hostname=None)]
        services = [
            MdnsService(
                name="test._http._tcp.local.",
                service_type="_http._tcp.local.",
                ip="192.168.1.50",
                port=80,
                hostname="mydevice.local.",
            ),
        ]
        result = enrich_assets_with_mdns(assets, services)
        assert result[0].hostname == "mydevice.local."

    def test_does_not_overwrite_existing_hostname(self):
        assets = [Asset(ip="192.168.1.50", hostname="already-set.local")]
        services = [
            MdnsService(
                name="test._http._tcp.local.",
                service_type="_http._tcp.local.",
                ip="192.168.1.50",
                port=80,
                hostname="mdns-hostname.local.",
            ),
        ]
        result = enrich_assets_with_mdns(assets, services)
        assert result[0].hostname == "already-set.local"

    def test_no_match_leaves_asset_unchanged(self):
        assets = [Asset(ip="192.168.1.99")]
        services = [
            MdnsService(
                name="test._http._tcp.local.",
                service_type="_http._tcp.local.",
                ip="192.168.1.50",
                port=80,
            ),
        ]
        result = enrich_assets_with_mdns(assets, services)
        assert result[0].raw_evidence.get("mdns_services") is None
        assert result[0].hostname is None

    def test_multiple_services_same_ip(self):
        assets = [Asset(ip="192.168.1.50")]
        services = [
            MdnsService(
                name="device._http._tcp.local.",
                service_type="_http._tcp.local.",
                ip="192.168.1.50",
                port=80,
                hostname="nas.local.",
            ),
            MdnsService(
                name="device._smb._tcp.local.",
                service_type="_smb._tcp.local.",
                ip="192.168.1.50",
                port=445,
            ),
        ]
        result = enrich_assets_with_mdns(assets, services)
        assert len(result[0].raw_evidence["mdns_services"]) == 2
        # First service with hostname should set it
        assert result[0].hostname == "nas.local."


class TestServiceScoringPrinter:
    def test_ipp_printer_scores_iot(self):
        """IPP printer service should score high for IoT."""
        rules = [
            Rule(
                name="Printer (IPP/mDNS)",
                match=RuleMatch(service_type_contains=["_ipp._tcp", "_printer._tcp"]),
                scores={"iot": 0.6},
                description="mDNS printer service",
            ),
        ]
        scores, evidence = apply_service_rules(rules, ["_ipp._tcp.local."])
        assert scores["iot"] == 0.6
        assert len(evidence) == 1

    def test_printer_tcp_scores_iot(self):
        rules = [
            Rule(
                name="Printer (IPP/mDNS)",
                match=RuleMatch(service_type_contains=["_ipp._tcp", "_printer._tcp"]),
                scores={"iot": 0.6},
            ),
        ]
        scores, evidence = apply_service_rules(rules, ["_printer._tcp.local."])
        assert scores["iot"] == 0.6


class TestServiceScoringChromecast:
    def test_googlecast_scores_iot(self):
        """Chromecast service should score high for IoT."""
        rules = [
            Rule(
                name="Chromecast",
                match=RuleMatch(service_type_contains=["_googlecast._tcp"]),
                scores={"iot": 0.6},
                description="Chromecast media device",
            ),
        ]
        scores, evidence = apply_service_rules(rules, ["_googlecast._tcp.local."])
        assert scores["iot"] == 0.6
        assert len(evidence) == 1


class TestServiceScoringAirplay:
    def test_airplay_scores_mixed(self):
        """AirPlay should score for both tasinabilir and IoT."""
        rules = [
            Rule(
                name="Apple AirPlay",
                match=RuleMatch(service_type_contains=["_airplay._tcp", "_raop._tcp"]),
                scores={"tasinabilir": 0.3, "iot": 0.2},
                description="AirPlay device",
            ),
        ]
        scores, evidence = apply_service_rules(rules, ["_airplay._tcp.local."])
        assert scores["tasinabilir"] == 0.3
        assert scores["iot"] == 0.2

    def test_raop_also_matches(self):
        rules = [
            Rule(
                name="Apple AirPlay",
                match=RuleMatch(service_type_contains=["_airplay._tcp", "_raop._tcp"]),
                scores={"tasinabilir": 0.3, "iot": 0.2},
            ),
        ]
        scores, evidence = apply_service_rules(rules, ["_raop._tcp.local."])
        assert scores["tasinabilir"] == 0.3


class TestServiceRulesYamlLoads:
    def test_service_rules_load_from_yaml(self):
        """service_rules.yaml should load correctly and contain rules."""
        rules_dir = Path(__file__).parent.parent / "rules"
        ruleset = load_rules(rules_dir)
        assert len(ruleset.service_rules) > 0

    def test_service_rules_have_valid_structure(self):
        rules_dir = Path(__file__).parent.parent / "rules"
        ruleset = load_rules(rules_dir)
        for rule in ruleset.service_rules:
            assert rule.name, "Every service rule must have a name"
            assert rule.scores, "Every service rule must have scores"
            assert rule.match.service_type_contains, "Every service rule must have service_type_contains"

    def test_total_rules_includes_service_rules(self):
        """total_rules property should count service rules too."""
        rules_dir = Path(__file__).parent.parent / "rules"
        ruleset = load_rules(rules_dir)
        expected = (
            len(ruleset.port_rules)
            + len(ruleset.vendor_rules)
            + len(ruleset.hostname_rules)
            + len(ruleset.service_rules)
        )
        assert ruleset.total_rules == expected


class TestRuleEvaluateService:
    def test_evaluate_service_match(self):
        rule = Rule(
            name="test",
            match=RuleMatch(service_type_contains=["_googlecast._tcp"]),
            scores={"iot": 0.6},
        )
        assert rule.evaluate_service(["_googlecast._tcp.local."]) is True

    def test_evaluate_service_no_match(self):
        rule = Rule(
            name="test",
            match=RuleMatch(service_type_contains=["_googlecast._tcp"]),
            scores={"iot": 0.6},
        )
        assert rule.evaluate_service(["_http._tcp.local."]) is False

    def test_evaluate_service_empty_list(self):
        rule = Rule(
            name="test",
            match=RuleMatch(service_type_contains=["_googlecast._tcp"]),
            scores={"iot": 0.6},
        )
        assert rule.evaluate_service([]) is False

    def test_evaluate_service_no_rule_pattern(self):
        rule = Rule(
            name="test",
            match=RuleMatch(),
            scores={"iot": 0.6},
        )
        assert rule.evaluate_service(["_googlecast._tcp.local."]) is False

    def test_evaluate_service_multiple_patterns(self):
        rule = Rule(
            name="test",
            match=RuleMatch(service_type_contains=["_airplay._tcp", "_raop._tcp"]),
            scores={"tasinabilir": 0.3},
        )
        assert rule.evaluate_service(["_raop._tcp.local."]) is True
        assert rule.evaluate_service(["_airplay._tcp.local."]) is True
        assert rule.evaluate_service(["_ssh._tcp.local."]) is False


class TestScoreByServices:
    def test_scores_from_mdns_evidence(self):
        """score_by_services should score based on mdns_services in raw_evidence."""
        raw_evidence = {
            "mdns_services": [
                {"service_type": "_googlecast._tcp.local.", "name": "Chromecast", "port": 8009},
            ]
        }
        scores = ClassificationScores()
        score_by_services(raw_evidence, scores)
        # Should have scored via service_rules.yaml
        assert scores.iot > 0

    def test_no_mdns_services_no_score(self):
        """Without mdns_services in evidence, no scoring should happen."""
        raw_evidence = {}
        scores = ClassificationScores()
        score_by_services(raw_evidence, scores)
        assert scores.confidence == 0.0

    def test_empty_mdns_services_no_score(self):
        raw_evidence = {"mdns_services": []}
        scores = ClassificationScores()
        score_by_services(raw_evidence, scores)
        assert scores.confidence == 0.0


class TestApplyServiceRules:
    def test_multiple_rules_accumulate(self):
        """Multiple matching rules should accumulate scores."""
        rules = [
            Rule(
                name="HTTP",
                match=RuleMatch(service_type_contains=["_http._tcp"]),
                scores={"uygulamalar": 0.2},
            ),
            Rule(
                name="SSH",
                match=RuleMatch(service_type_contains=["_ssh._tcp"]),
                scores={"ag_ve_sistemler": 0.3},
            ),
        ]
        scores, evidence = apply_service_rules(
            rules, ["_http._tcp.local.", "_ssh._tcp.local."]
        )
        assert scores["uygulamalar"] == 0.2
        assert scores["ag_ve_sistemler"] == 0.3
        assert len(evidence) == 2

    def test_no_matching_rules(self):
        rules = [
            Rule(
                name="Chromecast",
                match=RuleMatch(service_type_contains=["_googlecast._tcp"]),
                scores={"iot": 0.6},
            ),
        ]
        scores, evidence = apply_service_rules(rules, ["_ssh._tcp.local."])
        assert scores == {}
        assert evidence == []


class TestDiscoverMdnsServicesMocked:
    """Test discover_mdns_services with mocked Zeroconf to avoid network calls."""

    @patch("bigr.scanner.mdns.Zeroconf")
    @patch("bigr.scanner.mdns.ServiceBrowser")
    @patch("bigr.scanner.mdns.time")
    def test_discover_returns_empty_on_no_services(self, mock_time, mock_browser, mock_zc):
        """With no services found, returns empty list."""
        from bigr.scanner.mdns import discover_mdns_services

        mock_zc_instance = MagicMock()
        mock_zc.return_value = mock_zc_instance

        result = discover_mdns_services(timeout=1.0)
        assert result == []
        mock_zc_instance.close.assert_called_once()

    @patch("bigr.scanner.mdns.Zeroconf")
    @patch("bigr.scanner.mdns.ServiceBrowser")
    @patch("bigr.scanner.mdns.time")
    def test_discover_creates_browsers_for_all_service_types(self, mock_time, mock_browser, mock_zc):
        """Should create a ServiceBrowser for each interesting service type."""
        from bigr.scanner.mdns import INTERESTING_SERVICES, discover_mdns_services

        mock_zc_instance = MagicMock()
        mock_zc.return_value = mock_zc_instance

        discover_mdns_services(timeout=1.0)

        assert mock_browser.call_count == len(INTERESTING_SERVICES)

    @patch("bigr.scanner.mdns.Zeroconf")
    def test_discover_handles_zeroconf_init_failure(self, mock_zc):
        """If Zeroconf fails to initialize, return empty list gracefully."""
        from bigr.scanner.mdns import discover_mdns_services

        mock_zc.side_effect = OSError("Network unavailable")

        result = discover_mdns_services(timeout=1.0)
        assert result == []
