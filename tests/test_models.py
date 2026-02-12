"""Tests for core data models."""

from datetime import datetime, timezone

from bigr.models import (
    Asset,
    BigrCategory,
    ConfidenceLevel,
    ScanMethod,
    ScanResult,
    SensitivityLevel,
    derive_sensitivity,
    is_randomized_mac,
    normalize_mac,
)


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


class TestDeriveSensitivity:
    def test_iot_camera_hostname_is_fragile(self):
        result = derive_sensitivity(BigrCategory.IOT, "Hikvision", "cam-entrance", None)
        assert result == SensitivityLevel.FRAGILE

    def test_iot_sensor_hostname_is_fragile(self):
        result = derive_sensitivity(BigrCategory.IOT, "Acme", "sensor-temp", None)
        assert result == SensitivityLevel.FRAGILE

    def test_iot_embedded_os_is_fragile(self):
        result = derive_sensitivity(BigrCategory.IOT, "Generic", "device-01", "Embedded Linux 4.x")
        assert result == SensitivityLevel.FRAGILE

    def test_iot_printer_is_cautious(self):
        result = derive_sensitivity(BigrCategory.IOT, "HP", "printer-floor1", None)
        assert result == SensitivityLevel.CAUTIOUS

    def test_iot_generic_is_cautious(self):
        result = derive_sensitivity(BigrCategory.IOT, "Unknown", "smart-plug-01", None)
        assert result == SensitivityLevel.CAUTIOUS

    def test_ag_ve_sistemler_is_safe(self):
        result = derive_sensitivity(BigrCategory.AG_VE_SISTEMLER, "Cisco", "sw-core-01", None)
        assert result == SensitivityLevel.SAFE

    def test_uygulamalar_is_safe(self):
        result = derive_sensitivity(BigrCategory.UYGULAMALAR, "Dell", "web-srv-01", "Ubuntu 22.04")
        assert result == SensitivityLevel.SAFE


class TestNormalizeMac:
    def test_pads_single_digit_octets(self):
        assert normalize_mac("cc:8:fa:6d:fc:59") == "cc:08:fa:6d:fc:59"
        assert normalize_mac("6:11:e5:ea:68:5c") == "06:11:e5:ea:68:5c"

    def test_lowercases(self):
        assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"

    def test_converts_dashes(self):
        assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"

    def test_already_normalized(self):
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"

    def test_none_returns_none(self):
        assert normalize_mac(None) is None

    def test_empty_returns_none(self):
        assert normalize_mac("") is None

    def test_invalid_format_returns_as_is(self):
        assert normalize_mac("not-a-mac") == "not:a:mac"
        assert normalize_mac("aabb.ccdd.eeff") == "aabb.ccdd.eeff"


class TestIsRandomizedMac:
    def test_randomized_mac(self):
        # 0x3e = 0011 1110, bit 1 (0x02) is set → randomized
        assert is_randomized_mac("3e:aa:bb:cc:dd:ee") is True
        # 0xba = 1011 1010, bit 1 is set → randomized
        assert is_randomized_mac("ba:11:22:33:44:55") is True
        # 0x06 = 0000 0110, bit 1 is set → randomized
        assert is_randomized_mac("06:aa:bb:cc:dd:ee") is True

    def test_non_randomized_mac(self):
        # 0xaa = 1010 1010, bit 1 is set → actually randomized
        # 0x00 = 0000 0000, bit 1 not set → NOT randomized
        assert is_randomized_mac("00:1a:1e:aa:bb:cc") is False
        # 0xac = 1010 1100, bit 1 not set → NOT randomized
        assert is_randomized_mac("ac:de:48:aa:bb:cc") is False

    def test_none_returns_false(self):
        assert is_randomized_mac(None) is False

    def test_empty_returns_false(self):
        assert is_randomized_mac("") is False

    def test_handles_unnormalized_input(self):
        # Single-digit octet should still work via normalize_mac
        assert is_randomized_mac("6:11:e5:ea:68:5c") is True  # 0x06 & 0x02 = 0x02
