"""Tests for BİGR classification engine."""

from bigr.classifier.bigr_mapper import (
    ClassificationScores,
    classify_asset,
    score_by_hostname,
    score_by_os,
    score_by_ports,
    score_by_vendor,
)
from bigr.classifier.mac_lookup import get_vendor_category_hint, lookup_vendor
from bigr.models import Asset, BigrCategory


class TestClassificationScores:
    def test_winner(self):
        scores = ClassificationScores(ag_ve_sistemler=0.9, uygulamalar=0.2, iot=0.1, tasinabilir=0.1)
        assert scores.winner == BigrCategory.AG_VE_SISTEMLER

    def test_confidence(self):
        scores = ClassificationScores(ag_ve_sistemler=0.9, uygulamalar=0.4, iot=0.1, tasinabilir=0.2)
        # 0.9 / 1.6 = 0.5625
        assert abs(scores.confidence - 0.5625) < 0.001

    def test_zero_confidence(self):
        scores = ClassificationScores()
        assert scores.confidence == 0.0


class TestScoreByPorts:
    def test_server_ports(self):
        scores = ClassificationScores()
        score_by_ports([22, 80, 443], scores)
        assert scores.ag_ve_sistemler > 0
        assert "port_rules" in scores.evidence

    def test_web_only(self):
        scores = ClassificationScores()
        score_by_ports([80, 443], scores)
        assert scores.uygulamalar > 0

    def test_printer_port(self):
        scores = ClassificationScores()
        score_by_ports([9100], scores)
        assert scores.iot >= 0.5

    def test_rdp(self):
        scores = ClassificationScores()
        score_by_ports([3389], scores)
        assert scores.tasinabilir > 0

    def test_rtsp_camera(self):
        scores = ClassificationScores()
        score_by_ports([554], scores)
        assert scores.iot >= 0.5

    def test_empty_ports(self):
        scores = ClassificationScores()
        score_by_ports([], scores)
        assert scores.confidence == 0.0


class TestScoreByVendor:
    def test_cisco(self):
        scores = ClassificationScores()
        score_by_vendor("Cisco Systems", scores)
        assert scores.ag_ve_sistemler >= 0.5

    def test_hikvision(self):
        scores = ClassificationScores()
        score_by_vendor("Hikvision Digital", scores)
        assert scores.iot >= 0.5

    def test_apple(self):
        scores = ClassificationScores()
        score_by_vendor("Apple Inc", scores)
        assert scores.tasinabilir >= 0.4

    def test_unknown(self):
        scores = ClassificationScores()
        score_by_vendor("Unknown Corp", scores)
        assert scores.confidence == 0.0

    def test_none(self):
        scores = ClassificationScores()
        score_by_vendor(None, scores)
        assert scores.confidence == 0.0


class TestScoreByHostname:
    def test_switch(self):
        scores = ClassificationScores()
        score_by_hostname("core-sw-01", scores)
        assert scores.ag_ve_sistemler >= 0.4

    def test_camera(self):
        scores = ClassificationScores()
        score_by_hostname("lobby-cam-01", scores)
        assert scores.iot >= 0.4

    def test_laptop(self):
        scores = ClassificationScores()
        score_by_hostname("okan-laptop", scores)
        assert scores.tasinabilir >= 0.4

    def test_web_server(self):
        scores = ClassificationScores()
        score_by_hostname("web-prod-01", scores)
        assert scores.uygulamalar >= 0.4

    def test_no_match(self):
        scores = ClassificationScores()
        score_by_hostname("unknown-device", scores)
        assert scores.confidence == 0.0

    def test_none(self):
        scores = ClassificationScores()
        score_by_hostname(None, scores)
        assert scores.confidence == 0.0


class TestScoreByOS:
    def test_network_equipment(self):
        scores = ClassificationScores()
        score_by_os("Network Equipment (Cisco)", scores)
        assert scores.ag_ve_sistemler >= 0.4

    def test_windows(self):
        scores = ClassificationScores()
        score_by_os("Windows", scores)
        assert scores.tasinabilir >= 0.3

    def test_ip_camera(self):
        scores = ClassificationScores()
        score_by_os("IP Camera", scores)
        assert scores.iot >= 0.5


class TestMacLookup:
    def test_known_cisco(self):
        vendor = lookup_vendor("00:1e:bd:aa:bb:cc")
        assert vendor == "Cisco"

    def test_known_hikvision(self):
        vendor = lookup_vendor("a4:14:37:00:11:22")
        assert vendor == "Hikvision"

    def test_unknown_mac(self):
        vendor = lookup_vendor("ff:ee:dd:cc:bb:aa")
        assert vendor is None

    def test_none_mac(self):
        vendor = lookup_vendor(None)
        assert vendor is None

    def test_vendor_category_hint(self):
        assert get_vendor_category_hint("Cisco Systems") == "ag_ve_sistemler"
        assert get_vendor_category_hint("Hikvision Digital") == "iot"
        assert get_vendor_category_hint("Apple Inc") == "tasinabilir"
        assert get_vendor_category_hint(None) is None
        assert get_vendor_category_hint("Unknown") is None


class TestClassifyAsset:
    def test_cisco_switch(self):
        asset = Asset(
            ip="10.0.0.1",
            mac="00:1e:bd:aa:bb:cc",
            hostname="core-sw-01",
            open_ports=[22, 80, 443, 161],
        )
        result = classify_asset(asset, do_fingerprint=False)
        assert result.bigr_category == BigrCategory.AG_VE_SISTEMLER
        assert result.confidence_score >= 0.4

    def test_hikvision_camera(self):
        asset = Asset(
            ip="10.0.0.50",
            mac="a4:14:37:00:11:22",
            hostname="lobby-cam-01",
            open_ports=[80, 554],
        )
        result = classify_asset(asset, do_fingerprint=False)
        assert result.bigr_category == BigrCategory.IOT
        assert result.confidence_score >= 0.4

    def test_laptop_rdp(self):
        asset = Asset(
            ip="10.0.0.100",
            mac="00:21:cc:aa:bb:cc",
            hostname="okan-laptop",
            open_ports=[3389],
        )
        result = classify_asset(asset, do_fingerprint=False)
        assert result.bigr_category == BigrCategory.TASINABILIR
        assert result.confidence_score >= 0.3

    def test_unclassified_minimal_info(self):
        asset = Asset(ip="10.0.0.200")
        result = classify_asset(asset, do_fingerprint=False)
        assert result.bigr_category == BigrCategory.UNCLASSIFIED
        assert result.confidence_score < 0.3
