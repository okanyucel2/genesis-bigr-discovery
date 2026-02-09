"""Tests for BİGR Alert & Notification Engine (Phase 3B)."""

from __future__ import annotations

import json
import logging
import platform
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Part 1: Alert Models
# ---------------------------------------------------------------------------


class TestAlertModels:
    """Tests for Alert, AlertSeverity, AlertType dataclasses."""

    def test_alert_creation(self):
        """Alert dataclass with all fields."""
        from bigr.alerts.models import Alert, AlertSeverity, AlertType

        alert = Alert(
            alert_type=AlertType.NEW_DEVICE,
            severity=AlertSeverity.WARNING,
            ip="192.168.1.100",
            mac="aa:bb:cc:dd:ee:ff",
            message="New device detected",
        )
        assert alert.alert_type == AlertType.NEW_DEVICE
        assert alert.severity == AlertSeverity.WARNING
        assert alert.ip == "192.168.1.100"
        assert alert.mac == "aa:bb:cc:dd:ee:ff"
        assert alert.message == "New device detected"
        assert isinstance(alert.details, dict)
        assert isinstance(alert.timestamp, datetime)

    def test_alert_severity_ordering(self):
        """CRITICAL > WARNING > INFO."""
        from bigr.alerts.models import AlertSeverity

        severities = [AlertSeverity.INFO, AlertSeverity.CRITICAL, AlertSeverity.WARNING]
        # Sorted by value-based ordering: critical < info < warning alphabetically
        # But we want logical ordering: CRITICAL > WARNING > INFO
        assert AlertSeverity.CRITICAL.level > AlertSeverity.WARNING.level
        assert AlertSeverity.WARNING.level > AlertSeverity.INFO.level

    def test_alert_type_enum(self):
        """All alert types: new_device, rogue_device, port_change, category_change, device_missing, mass_change."""
        from bigr.alerts.models import AlertType

        expected = {
            "new_device",
            "rogue_device",
            "port_change",
            "category_change",
            "device_missing",
            "mass_change",
        }
        actual = {member.value for member in AlertType}
        assert actual == expected

    def test_alert_to_dict(self):
        """Alert should serialize to dict for channels."""
        from bigr.alerts.models import Alert, AlertSeverity, AlertType

        alert = Alert(
            alert_type=AlertType.PORT_CHANGE,
            severity=AlertSeverity.INFO,
            ip="10.0.0.1",
            mac="11:22:33:44:55:66",
            message="Port changed",
            details={"old_ports": [80], "new_ports": [80, 443]},
        )
        d = alert.to_dict()
        assert d["alert_type"] == "port_change"
        assert d["severity"] == "info"
        assert d["ip"] == "10.0.0.1"
        assert d["mac"] == "11:22:33:44:55:66"
        assert d["message"] == "Port changed"
        assert d["details"] == {"old_ports": [80], "new_ports": [80, 443]}
        assert "timestamp" in d
        # timestamp should be ISO string
        assert isinstance(d["timestamp"], str)

    def test_alert_message_format(self):
        """Alert should have human-readable message property."""
        from bigr.alerts.models import Alert, AlertSeverity, AlertType

        alert = Alert(
            alert_type=AlertType.ROGUE_DEVICE,
            severity=AlertSeverity.CRITICAL,
            ip="192.168.1.200",
            mac="de:ad:be:ef:00:01",
            message="Rogue device detected on network",
        )
        formatted = alert.formatted_message
        assert "CRITICAL" in formatted
        assert "192.168.1.200" in formatted
        assert "Rogue device" in formatted


# ---------------------------------------------------------------------------
# Part 2: Alert Engine
# ---------------------------------------------------------------------------


class TestAlertEngine:
    """Tests for evaluate_diff function."""

    def _make_diff(self, new=None, removed=None, changed=None, unchanged=0):
        """Helper to build a DiffResult."""
        from bigr.diff import AssetChange, DiffResult

        return DiffResult(
            new_assets=new or [],
            removed_assets=removed or [],
            changed_assets=changed or [],
            unchanged_count=unchanged,
        )

    def test_new_device_generates_warning(self):
        """New device in diff should produce WARNING alert."""
        from bigr.alerts.engine import evaluate_diff
        from bigr.alerts.models import AlertSeverity, AlertType

        diff = self._make_diff(
            new=[{"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff"}]
        )
        alerts = evaluate_diff(diff)
        assert len(alerts) >= 1
        new_alerts = [a for a in alerts if a.alert_type == AlertType.NEW_DEVICE]
        assert len(new_alerts) == 1
        assert new_alerts[0].severity == AlertSeverity.WARNING
        assert new_alerts[0].ip == "192.168.1.50"

    def test_removed_device_generates_info(self):
        """Missing device should produce INFO alert."""
        from bigr.alerts.engine import evaluate_diff
        from bigr.alerts.models import AlertSeverity, AlertType

        diff = self._make_diff(
            removed=[{"ip": "192.168.1.99", "mac": "ff:ee:dd:cc:bb:aa"}]
        )
        alerts = evaluate_diff(diff)
        missing = [a for a in alerts if a.alert_type == AlertType.DEVICE_MISSING]
        assert len(missing) == 1
        assert missing[0].severity == AlertSeverity.INFO
        assert missing[0].ip == "192.168.1.99"

    def test_port_change_generates_info(self):
        """Port change should produce INFO alert."""
        from bigr.alerts.engine import evaluate_diff
        from bigr.alerts.models import AlertSeverity, AlertType
        from bigr.diff import AssetChange

        diff = self._make_diff(
            changed=[
                AssetChange(
                    ip="10.0.0.5",
                    mac="11:22:33:44:55:66",
                    change_type="port_change",
                    field="open_ports",
                    old_value="[80]",
                    new_value="[80, 443]",
                )
            ]
        )
        alerts = evaluate_diff(diff)
        port_alerts = [a for a in alerts if a.alert_type == AlertType.PORT_CHANGE]
        assert len(port_alerts) == 1
        assert port_alerts[0].severity == AlertSeverity.INFO

    def test_category_change_generates_warning(self):
        """Category change should produce WARNING alert."""
        from bigr.alerts.engine import evaluate_diff
        from bigr.alerts.models import AlertSeverity, AlertType
        from bigr.diff import AssetChange

        diff = self._make_diff(
            changed=[
                AssetChange(
                    ip="10.0.0.10",
                    mac="aa:aa:bb:bb:cc:cc",
                    change_type="category_change",
                    field="bigr_category",
                    old_value="unclassified",
                    new_value="iot",
                )
            ]
        )
        alerts = evaluate_diff(diff)
        cat_alerts = [a for a in alerts if a.alert_type == AlertType.CATEGORY_CHANGE]
        assert len(cat_alerts) == 1
        assert cat_alerts[0].severity == AlertSeverity.WARNING

    def test_mass_change_generates_critical(self):
        """10+ new devices in single scan should produce CRITICAL alert."""
        from bigr.alerts.engine import evaluate_diff
        from bigr.alerts.models import AlertSeverity, AlertType

        new_devices = [
            {"ip": f"192.168.1.{i}", "mac": f"aa:bb:cc:dd:ee:{i:02x}"}
            for i in range(11)
        ]
        diff = self._make_diff(new=new_devices)
        alerts = evaluate_diff(diff)
        mass = [a for a in alerts if a.alert_type == AlertType.MASS_CHANGE]
        assert len(mass) == 1
        assert mass[0].severity == AlertSeverity.CRITICAL

    def test_mass_change_threshold_configurable(self):
        """Mass change threshold should be configurable (default 10)."""
        from bigr.alerts.engine import evaluate_diff
        from bigr.alerts.models import AlertType

        new_devices = [
            {"ip": f"192.168.1.{i}", "mac": f"aa:bb:cc:dd:ee:{i:02x}"}
            for i in range(5)
        ]
        diff = self._make_diff(new=new_devices)

        # Default threshold 10: 5 devices should NOT trigger mass_change
        alerts_default = evaluate_diff(diff)
        mass_default = [a for a in alerts_default if a.alert_type == AlertType.MASS_CHANGE]
        assert len(mass_default) == 0

        # Custom threshold 3: 5 devices SHOULD trigger mass_change
        alerts_custom = evaluate_diff(diff, mass_threshold=3)
        mass_custom = [a for a in alerts_custom if a.alert_type == AlertType.MASS_CHANGE]
        assert len(mass_custom) == 1

    def test_no_changes_no_alerts(self):
        """Empty diff should produce no alerts."""
        from bigr.alerts.engine import evaluate_diff

        diff = self._make_diff(unchanged=10)
        alerts = evaluate_diff(diff)
        assert alerts == []

    def test_evaluate_diff_returns_alert_list(self):
        """evaluate_diff(diff_result) should return list[Alert]."""
        from bigr.alerts.engine import evaluate_diff
        from bigr.alerts.models import Alert

        diff = self._make_diff(
            new=[{"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"}]
        )
        result = evaluate_diff(diff)
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, Alert)

    def test_rogue_device_custom_rule(self):
        """Rogue device alert when new device matches custom conditions."""
        from bigr.alerts.engine import evaluate_diff
        from bigr.alerts.models import AlertSeverity, AlertType

        # A rogue device rule: any new device in 10.0.0.x range is rogue
        rules = [
            {
                "trigger": "rogue_device",
                "severity": "critical",
                "condition": {"ip_prefix": "10.0.0."},
            }
        ]
        diff = self._make_diff(
            new=[{"ip": "10.0.0.99", "mac": "de:ad:be:ef:00:01"}]
        )
        alerts = evaluate_diff(diff, rules=rules)
        rogue = [a for a in alerts if a.alert_type == AlertType.ROGUE_DEVICE]
        assert len(rogue) == 1
        assert rogue[0].severity == AlertSeverity.CRITICAL
        assert rogue[0].ip == "10.0.0.99"


# ---------------------------------------------------------------------------
# Part 3: Notification Channels
# ---------------------------------------------------------------------------


class TestLogChannel:
    """Tests for LogChannel."""

    def test_log_channel_writes_to_file(self, tmp_path):
        """LogChannel should append alert to log file."""
        from bigr.alerts.channels import LogChannel
        from bigr.alerts.models import Alert, AlertSeverity, AlertType

        log_file = tmp_path / "alerts.log"
        channel = LogChannel(log_path=log_file)
        alert = Alert(
            alert_type=AlertType.NEW_DEVICE,
            severity=AlertSeverity.WARNING,
            ip="192.168.1.10",
            mac="aa:bb:cc:dd:ee:ff",
            message="New device found",
        )
        result = channel.send(alert)
        assert result is True
        assert log_file.exists()
        content = log_file.read_text()
        assert "192.168.1.10" in content

    def test_log_channel_format(self, tmp_path):
        """Log entry should include timestamp, severity, type, message."""
        from bigr.alerts.channels import LogChannel
        from bigr.alerts.models import Alert, AlertSeverity, AlertType

        log_file = tmp_path / "alerts.log"
        channel = LogChannel(log_path=log_file)
        alert = Alert(
            alert_type=AlertType.PORT_CHANGE,
            severity=AlertSeverity.INFO,
            ip="10.0.0.5",
            mac=None,
            message="Ports changed on device",
        )
        channel.send(alert)
        content = log_file.read_text()
        assert "INFO" in content
        assert "port_change" in content
        assert "Ports changed on device" in content
        # Should have some timestamp indicator
        assert "202" in content  # year prefix

    def test_log_channel_creates_file(self, tmp_path):
        """Should create log file if it doesn't exist."""
        from bigr.alerts.channels import LogChannel
        from bigr.alerts.models import Alert, AlertSeverity, AlertType

        log_file = tmp_path / "subdir" / "new_alerts.log"
        assert not log_file.exists()
        channel = LogChannel(log_path=log_file)
        alert = Alert(
            alert_type=AlertType.DEVICE_MISSING,
            severity=AlertSeverity.INFO,
            ip="172.16.0.1",
            mac="ff:ff:ff:ff:ff:ff",
            message="Device missing",
        )
        channel.send(alert)
        assert log_file.exists()


class TestWebhookChannel:
    """Tests for WebhookChannel."""

    def test_webhook_sends_post(self):
        """WebhookChannel should POST JSON to URL."""
        from bigr.alerts.channels import WebhookChannel
        from bigr.alerts.models import Alert, AlertSeverity, AlertType

        alert = Alert(
            alert_type=AlertType.NEW_DEVICE,
            severity=AlertSeverity.WARNING,
            ip="192.168.1.50",
            mac="aa:bb:cc:dd:ee:ff",
            message="New device",
        )
        channel = WebhookChannel(url="http://example.com/webhook")

        with patch("bigr.alerts.channels.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = MagicMock()
            mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
            result = channel.send(alert)

        assert result is True
        mock_urlopen.assert_called_once()
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        assert isinstance(request, urllib.request.Request)
        assert request.full_url == "http://example.com/webhook"
        assert request.method == "POST"

    def test_webhook_includes_alert_data(self):
        """POST body should contain alert dict."""
        from bigr.alerts.channels import WebhookChannel
        from bigr.alerts.models import Alert, AlertSeverity, AlertType

        alert = Alert(
            alert_type=AlertType.MASS_CHANGE,
            severity=AlertSeverity.CRITICAL,
            ip="0.0.0.0",
            mac=None,
            message="Mass change detected",
            details={"count": 15},
        )
        channel = WebhookChannel(url="http://hooks.example.com/alert")

        with patch("bigr.alerts.channels.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = MagicMock()
            mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
            channel.send(alert)

        request = mock_urlopen.call_args[0][0]
        body = json.loads(request.data.decode("utf-8"))
        assert body["alert_type"] == "mass_change"
        assert body["severity"] == "critical"
        assert body["details"]["count"] == 15

    def test_webhook_handles_failure_gracefully(self):
        """Network failure should not crash, just log warning."""
        from bigr.alerts.channels import WebhookChannel
        from bigr.alerts.models import Alert, AlertSeverity, AlertType

        alert = Alert(
            alert_type=AlertType.NEW_DEVICE,
            severity=AlertSeverity.WARNING,
            ip="10.0.0.1",
            mac=None,
            message="test",
        )
        channel = WebhookChannel(url="http://unreachable.invalid/hook")

        with patch("bigr.alerts.channels.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = Exception("Connection refused")
            result = channel.send(alert)

        assert result is False

    def test_webhook_timeout(self):
        """Should timeout after configured seconds."""
        from bigr.alerts.channels import WebhookChannel

        channel = WebhookChannel(url="http://example.com/hook", timeout=10.0)
        assert channel.timeout == 10.0

        channel2 = WebhookChannel(url="http://example.com/hook", timeout=5.0)
        assert channel2.timeout == 5.0


class TestDesktopChannel:
    """Tests for DesktopChannel."""

    def test_desktop_calls_notify(self):
        """DesktopChannel should call OS notification."""
        from bigr.alerts.channels import DesktopChannel
        from bigr.alerts.models import Alert, AlertSeverity, AlertType

        alert = Alert(
            alert_type=AlertType.ROGUE_DEVICE,
            severity=AlertSeverity.CRITICAL,
            ip="192.168.1.200",
            mac="de:ad:be:ef:00:01",
            message="Rogue device detected",
        )
        channel = DesktopChannel()

        with patch("bigr.alerts.channels.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = channel.send(alert)

        assert result is True
        mock_run.assert_called_once()

    def test_desktop_fallback_on_unsupported(self):
        """Should not crash on unsupported OS."""
        from bigr.alerts.channels import DesktopChannel
        from bigr.alerts.models import Alert, AlertSeverity, AlertType

        alert = Alert(
            alert_type=AlertType.NEW_DEVICE,
            severity=AlertSeverity.INFO,
            ip="10.0.0.1",
            mac=None,
            message="test",
        )
        channel = DesktopChannel()

        with patch("bigr.alerts.channels.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("osascript not found")
            result = channel.send(alert)

        assert result is False


class TestChannelDispatch:
    """Tests for dispatch_alerts function."""

    def test_dispatch_to_multiple_channels(self, tmp_path):
        """dispatch_alerts should send to all configured channels."""
        from bigr.alerts.channels import LogChannel, dispatch_alerts
        from bigr.alerts.models import Alert, AlertSeverity, AlertType

        log1 = tmp_path / "log1.log"
        log2 = tmp_path / "log2.log"
        channels = [LogChannel(log_path=log1), LogChannel(log_path=log2)]

        alert = Alert(
            alert_type=AlertType.NEW_DEVICE,
            severity=AlertSeverity.WARNING,
            ip="192.168.1.50",
            mac="aa:bb:cc:dd:ee:ff",
            message="New device",
        )
        count = dispatch_alerts([alert], channels)
        assert count == 2
        assert log1.exists()
        assert log2.exists()

    def test_dispatch_filters_by_severity(self, tmp_path):
        """Channel with min_severity should skip lower alerts."""
        from bigr.alerts.channels import LogChannel, dispatch_alerts
        from bigr.alerts.models import Alert, AlertSeverity, AlertType

        log_file = tmp_path / "filtered.log"
        channels = [LogChannel(log_path=log_file)]

        info_alert = Alert(
            alert_type=AlertType.PORT_CHANGE,
            severity=AlertSeverity.INFO,
            ip="10.0.0.5",
            mac=None,
            message="Port change",
        )
        # min_severity=WARNING should skip INFO alerts
        count = dispatch_alerts(
            [info_alert], channels, min_severity=AlertSeverity.WARNING
        )
        assert count == 0
        assert not log_file.exists()

        # WARNING alert should pass through with min_severity=WARNING
        warn_alert = Alert(
            alert_type=AlertType.NEW_DEVICE,
            severity=AlertSeverity.WARNING,
            ip="10.0.0.6",
            mac=None,
            message="New device",
        )
        count = dispatch_alerts(
            [warn_alert], channels, min_severity=AlertSeverity.WARNING
        )
        assert count == 1

    def test_dispatch_empty_alerts(self, tmp_path):
        """No alerts should not call any channel."""
        from bigr.alerts.channels import LogChannel, dispatch_alerts

        log_file = tmp_path / "empty.log"
        channels = [LogChannel(log_path=log_file)]

        count = dispatch_alerts([], channels)
        assert count == 0
        assert not log_file.exists()
