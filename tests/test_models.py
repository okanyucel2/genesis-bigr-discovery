"""Tests for core data models."""

from datetime import datetime, timezone

from bigr.models import Asset, BigrCategory, ConfidenceLevel, ScanMethod, ScanResult


class TestBigrCategory:
    def test_label_tr(self):
        assert BigrCategory.AG_VE_SISTEMLER.label_tr == "Ağ ve Sistemler"
        assert BigrCategory.IOT.label_tr == "IoT"
        assert BigrCategory.TASINABILIR.label_tr == "Taşınabilir Cihazlar"
        assert BigrCategory.UYGULAMALAR.label_tr == "Uygulamalar"
        assert BigrCategory.UNCLASSIFIED.label_tr == "Sınıflandırılmamış"


class TestConfidenceLevel:
    def test_high(self):
        assert ConfidenceLevel.from_score(0.9) == ConfidenceLevel.HIGH
        assert ConfidenceLevel.from_score(0.7) == ConfidenceLevel.HIGH

    def test_medium(self):
        assert ConfidenceLevel.from_score(0.5) == ConfidenceLevel.MEDIUM
        assert ConfidenceLevel.from_score(0.4) == ConfidenceLevel.MEDIUM

    def test_low(self):
        assert ConfidenceLevel.from_score(0.35) == ConfidenceLevel.LOW
        assert ConfidenceLevel.from_score(0.3) == ConfidenceLevel.LOW

    def test_unclassified(self):
        assert ConfidenceLevel.from_score(0.2) == ConfidenceLevel.UNCLASSIFIED
        assert ConfidenceLevel.from_score(0.0) == ConfidenceLevel.UNCLASSIFIED


class TestAsset:
    def test_defaults(self):
        asset = Asset(ip="192.168.1.1")
        assert asset.mac is None
        assert asset.bigr_category == BigrCategory.UNCLASSIFIED
        assert asset.confidence_score == 0.0
        assert asset.scan_method == ScanMethod.PASSIVE

    def test_to_dict(self):
        asset = Asset(
            ip="192.168.1.1",
            mac="aa:bb:cc:dd:ee:ff",
            hostname="router-01",
            vendor="Cisco",
            open_ports=[22, 80, 443],
            bigr_category=BigrCategory.AG_VE_SISTEMLER,
            confidence_score=0.85,
        )
        d = asset.to_dict()
        assert d["ip"] == "192.168.1.1"
        assert d["bigr_category"] == "ag_ve_sistemler"
        assert d["bigr_category_tr"] == "Ağ ve Sistemler"
        assert d["confidence_level"] == "high"
        assert d["open_ports"] == [22, 80, 443]

    def test_confidence_level_property(self):
        asset = Asset(ip="10.0.0.1", confidence_score=0.55)
        assert asset.confidence_level == ConfidenceLevel.MEDIUM


class TestScanResult:
    def test_category_summary(self):
        assets = [
            Asset(ip="10.0.0.1", bigr_category=BigrCategory.AG_VE_SISTEMLER),
            Asset(ip="10.0.0.2", bigr_category=BigrCategory.AG_VE_SISTEMLER),
            Asset(ip="10.0.0.3", bigr_category=BigrCategory.IOT),
        ]
        result = ScanResult(
            target="10.0.0.0/24",
            scan_method=ScanMethod.HYBRID,
            started_at=datetime.now(timezone.utc),
            assets=assets,
        )
        summary = result.category_summary
        assert summary["ag_ve_sistemler"] == 2
        assert summary["iot"] == 1

    def test_duration(self):
        t1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 1, 12, 0, 30, tzinfo=timezone.utc)
        result = ScanResult(
            target="10.0.0.0/24",
            scan_method=ScanMethod.PASSIVE,
            started_at=t1,
            completed_at=t2,
        )
        assert result.duration_seconds == 30.0

    def test_to_dict(self):
        result = ScanResult(
            target="192.168.1.0/24",
            scan_method=ScanMethod.HYBRID,
            started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
        )
        d = result.to_dict()
        assert d["target"] == "192.168.1.0/24"
        assert d["total_assets"] == 0
        assert d["duration_seconds"] == 60.0
