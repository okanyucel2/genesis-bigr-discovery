"""Tests for web dashboard."""

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from bigr.dashboard.app import create_app


@pytest.fixture
def sample_data(tmp_path: Path) -> Path:
    """Create a sample assets.json for testing."""
    data = {
        "target": "192.168.1.0/24",
        "scan_method": "hybrid",
        "duration_seconds": 12.5,
        "total_assets": 2,
        "category_summary": {"ag_ve_sistemler": 1, "iot": 1},
        "assets": [
            {
                "ip": "192.168.1.1",
                "mac": "00:1e:bd:aa:bb:cc",
                "hostname": "router-01",
                "vendor": "Cisco",
                "open_ports": [22, 80, 443],
                "os_hint": "Linux",
                "bigr_category": "ag_ve_sistemler",
                "bigr_category_tr": "Ağ ve Sistemler",
                "confidence_score": 0.85,
                "confidence_level": "high",
                "scan_method": "hybrid",
            },
            {
                "ip": "192.168.1.50",
                "mac": "a4:14:37:00:11:22",
                "hostname": "cam-01",
                "vendor": "Hikvision",
                "open_ports": [80, 554],
                "os_hint": "IP Camera",
                "bigr_category": "iot",
                "bigr_category_tr": "IoT",
                "confidence_score": 0.72,
                "confidence_level": "high",
                "scan_method": "hybrid",
            },
        ],
    }
    json_path = tmp_path / "assets.json"
    json_path.write_text(json.dumps(data))
    return json_path


@pytest.fixture
def app(sample_data: Path):
    return create_app(data_path=str(sample_data))


@pytest.mark.asyncio
async def test_dashboard_page(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/")
        assert resp.status_code == 200
        assert "BIGR Discovery Dashboard" in resp.text
        assert "192.168.1.1" in resp.text
        assert "Cisco" in resp.text


@pytest.mark.asyncio
async def test_api_data(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/data")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_assets"] == 2
        assert len(data["assets"]) == 2


@pytest.mark.asyncio
async def test_api_health(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert resp.json()["exists"] is True


@pytest.mark.asyncio
async def test_dashboard_no_data(tmp_path: Path):
    missing_app = create_app(data_path=str(tmp_path / "nope.json"))
    transport = ASGITransport(app=missing_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/")
        assert resp.status_code == 200
        assert "BIGR Discovery Dashboard" in resp.text
