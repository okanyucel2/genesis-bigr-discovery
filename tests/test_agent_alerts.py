"""Tests for bigr.agent.alerts — agent alert service."""

from __future__ import annotations

import pytest

from bigr.agent.alerts import Alert, AlertService, alert_critical_finding, alert_service


class TestAlertService:
    def test_emit_and_recent(self):
        svc = AlertService()
        svc.emit(Alert(level="critical", category="test", title="T1", detail="D1"))
        svc.emit(Alert(level="warning", category="test", title="T2", detail="D2"))
        alerts = svc.recent(limit=10)
        assert len(alerts) == 2
        # Most recent first
        assert alerts[0]["title"] == "T2"
        assert alerts[1]["title"] == "T1"

    def test_recent_respects_limit(self):
        svc = AlertService()
        for i in range(10):
            svc.emit(Alert(level="info", category="test", title=f"T{i}", detail=""))
        assert len(svc.recent(limit=3)) == 3

    def test_alert_dict_shape(self):
        a = Alert(level="critical", category="critical_finding", title="Open SSH", detail="10.0.0.5")
        d = a.to_dict()
        assert d["level"] == "critical"
        assert d["category"] == "critical_finding"
        assert d["title"] == "Open SSH"
        assert "timestamp" in d


class TestCriticalFindingAlert:
    def test_alert_emitted_for_critical(self):
        alert_service._log.clear()
        alert_critical_finding(
            finding_title="Expired SSL cert",
            target="192.168.1.0/24",
            site_name="HQ",
            agent_name="scanner-1",
        )
        alerts = alert_service.recent()
        assert len(alerts) == 1
        assert alerts[0]["level"] == "critical"
        assert "Expired SSL cert" in alerts[0]["title"]
        assert "HQ" in alerts[0]["detail"]
