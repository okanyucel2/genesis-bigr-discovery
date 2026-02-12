"""Tests for watcher REST API endpoints."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from bigr.watcher_api import router, set_watcher, get_watcher


@pytest.fixture()
def _clear_watcher():
    """Reset shared watcher state between tests."""
    set_watcher(None)
    yield
    set_watcher(None)


@pytest.fixture()
def client(_clear_watcher):
    """Create a test client with the watcher router."""
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestWatcherAPI:
    def test_status_not_running(self, client):
        """Status should report not running when no watcher."""
        resp = client.get("/api/watcher/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_running"] is False
        assert data["scan_count"] == 0

    def test_status_running(self, client, tmp_path):
        """Status should report running when watcher is active."""
        import time

        mock_watcher = MagicMock()
        mock_watcher._running = True
        mock_watcher.started_at = time.time() - 120
        mock_watcher.scan_history = [
            {"subnet": "10.0.0.0/24", "completed_at": "2026-01-01T00:00:00+00:00"}
        ]
        mock_watcher.scan_count = 5
        mock_watcher.targets = [{"subnet": "10.0.0.0/24", "interval_seconds": 60}]

        set_watcher(mock_watcher)

        resp = client.get("/api/watcher/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_running"] is True
        assert data["scan_count"] == 5
        assert data["uptime_seconds"] >= 100
        assert len(data["targets"]) == 1

    def test_history_empty(self, client):
        """History should return empty list when no watcher."""
        resp = client.get("/api/watcher/history")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scans"] == []
        assert data["total"] == 0

    def test_history_with_data(self, client):
        """History should return scan records from watcher."""
        mock_watcher = MagicMock()
        mock_watcher.scan_history = [
            {"subnet": "10.0.0.0/24", "started_at": "2026-01-01T00:00:00+00:00",
             "completed_at": "2026-01-01T00:00:05+00:00", "asset_count": 10, "changes_count": 2},
            {"subnet": "10.0.1.0/24", "started_at": "2026-01-01T00:01:00+00:00",
             "completed_at": "2026-01-01T00:01:05+00:00", "asset_count": 5, "changes_count": 0},
        ]
        set_watcher(mock_watcher)

        resp = client.get("/api/watcher/history?limit=1")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["scans"]) == 1
        assert data["total"] == 2

    def test_alerts_empty(self, client):
        """Alerts should return empty list when no watcher."""
        resp = client.get("/api/watcher/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["alerts"] == []
        assert data["total"] == 0

    def test_scan_now_no_watcher(self, client):
        """scan-now should 404 when no watcher running."""
        resp = client.post("/api/watcher/scan-now")
        assert resp.status_code == 404

    def test_scan_now_triggers_scan(self, client):
        """scan-now should trigger a scan cycle."""
        mock_watcher = MagicMock()
        mock_watcher.targets = [{"subnet": "10.0.0.0/24", "interval_seconds": 60}]
        mock_watcher._last_scan_time = {"10.0.0.0/24": 123}
        set_watcher(mock_watcher)

        resp = client.post("/api/watcher/scan-now")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "triggered"
        assert data["subnet"] == "10.0.0.0/24"
        mock_watcher._run_single_cycle.assert_called_once()

    def test_stop_not_running(self, client):
        """Stop should report not running when watcher is inactive."""
        resp = client.post("/api/watcher/stop")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "not_running"
