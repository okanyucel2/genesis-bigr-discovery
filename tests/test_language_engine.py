"""Tests for the BİGR Product Language Engine.

Covers template-based humanization, placeholder filling, AI humanization
with mock router, batch processing, API endpoints, and edge cases.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from bigr.language.humanizer import NotificationHumanizer
from bigr.language.models import (
    HumanizeRequest,
    HumanNotification,
    NotificationPreferences,
)
from bigr.language.templates import FALLBACK_TEMPLATE, TEMPLATES


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def humanizer() -> NotificationHumanizer:
    """A humanizer with no AI router (template-only mode)."""
    return NotificationHumanizer()


@pytest.fixture()
def mock_router() -> MagicMock:
    """A mock InferenceRouter that returns a canned AI response."""
    router = MagicMock()
    result = MagicMock()
    result.content = "Aginda supheli bir hareket var. Ama merak etme, kontrol altinda."
    result.tier_used = "L1_haiku"
    router.route = AsyncMock(return_value=result)
    return router


@pytest.fixture()
def ai_humanizer(mock_router: MagicMock) -> NotificationHumanizer:
    """A humanizer with a mock AI router."""
    return NotificationHumanizer(ai_router=mock_router)


@pytest.fixture()
def sample_request() -> HumanizeRequest:
    """A sample humanize request for a port change alert."""
    return HumanizeRequest(
        alert_type="port_change",
        severity="warning",
        ip="192.168.1.5",
        message="Port 445 (SMB) open on 192.168.1.5 - EternalBlue risk",
        device_name="Oturma Odasi PC",
        details={"port": 445},
    )


# ---------------------------------------------------------------------------
# Template-based humanization tests
# ---------------------------------------------------------------------------


class TestTemplateHumanization:
    """Tests for the rule-based template path."""

    @pytest.mark.asyncio()
    async def test_new_device_info(self, humanizer: NotificationHumanizer) -> None:
        req = HumanizeRequest(
            alert_type="new_device",
            severity="info",
            ip="192.168.1.23",
            message="New device detected: 192.168.1.23",
        )
        result = await humanizer.humanize(req)
        assert isinstance(result, HumanNotification)
        assert result.title == "Yeni Misafir"
        assert "192.168.1.23" in result.body
        assert result.severity == "info"
        assert result.generated_by == "rules"
        assert result.original_alert_type == "new_device"

    @pytest.mark.asyncio()
    async def test_new_device_warning(self, humanizer: NotificationHumanizer) -> None:
        req = HumanizeRequest(
            alert_type="new_device",
            severity="warning",
            ip="192.168.1.50",
            message="New device detected: 192.168.1.50",
        )
        result = await humanizer.humanize(req)
        assert result.title == "Tanimadigi Bir Cihaz"
        assert "192.168.1.50" in result.body
        assert result.action_label == "Kim Bu?"
        assert result.action_type == "investigate"

    @pytest.mark.asyncio()
    async def test_port_change_info(self, humanizer: NotificationHumanizer) -> None:
        req = HumanizeRequest(
            alert_type="port_change",
            severity="info",
            ip="192.168.1.5",
            message="Port 80 opened on 192.168.1.5",
            device_name="Web Sunucu",
        )
        result = await humanizer.humanize(req)
        assert result.title == "Port Degisikligi"
        assert "Web Sunucu" in result.body

    @pytest.mark.asyncio()
    async def test_port_change_warning(
        self, humanizer: NotificationHumanizer, sample_request: HumanizeRequest
    ) -> None:
        result = await humanizer.humanize(sample_request)
        assert result.title == "Riskli Port Acik"
        assert "Oturma Odasi PC" in result.body
        assert result.action_label == "Onar"
        assert result.action_type == "fix_it"

    @pytest.mark.asyncio()
    async def test_port_change_critical(self, humanizer: NotificationHumanizer) -> None:
        req = HumanizeRequest(
            alert_type="port_change",
            severity="critical",
            ip="192.168.1.5",
            message="Port 445 open - CRITICAL",
            device_name="Sunucu",
        )
        result = await humanizer.humanize(req)
        assert result.title == "Tehlikeli Port!"
        assert result.severity == "critical"
        assert result.action_type == "fix_it"

    @pytest.mark.asyncio()
    async def test_rogue_device_warning(self, humanizer: NotificationHumanizer) -> None:
        req = HumanizeRequest(
            alert_type="rogue_device",
            severity="warning",
            ip="192.168.1.99",
            message="Unauthorized device 192.168.1.99",
        )
        result = await humanizer.humanize(req)
        assert result.title == "Supheli Cihaz"
        assert "192.168.1.99" in result.body
        assert result.action_label == "Engelle"

    @pytest.mark.asyncio()
    async def test_rogue_device_critical(self, humanizer: NotificationHumanizer) -> None:
        req = HumanizeRequest(
            alert_type="rogue_device",
            severity="critical",
            ip="192.168.1.99",
            message="Rogue device 192.168.1.99",
        )
        result = await humanizer.humanize(req)
        assert result.title == "Izinsiz Giris!"
        assert result.action_type == "fix_it"

    @pytest.mark.asyncio()
    async def test_device_missing_info(self, humanizer: NotificationHumanizer) -> None:
        req = HumanizeRequest(
            alert_type="device_missing",
            severity="info",
            ip="192.168.1.10",
            message="Device 192.168.1.10 no longer responding",
        )
        result = await humanizer.humanize(req)
        assert result.title == "Cihaz Ayrildi"
        assert "192.168.1.10" in result.body

    @pytest.mark.asyncio()
    async def test_mass_change_critical(self, humanizer: NotificationHumanizer) -> None:
        req = HumanizeRequest(
            alert_type="mass_change",
            severity="critical",
            ip="0.0.0.0",
            message="Mass change: 15 new devices",
        )
        result = await humanizer.humanize(req)
        assert result.title == "Buyuk Degisiklik!"
        assert result.action_type == "investigate"

    @pytest.mark.asyncio()
    async def test_category_change_info(self, humanizer: NotificationHumanizer) -> None:
        req = HumanizeRequest(
            alert_type="category_change",
            severity="info",
            ip="192.168.1.7",
            message="Category changed to tasinabilir",
            device_name="Yazici",
        )
        result = await humanizer.humanize(req)
        assert result.title == "Cihaz Guncellendi"
        assert "Yazici" in result.body

    @pytest.mark.asyncio()
    async def test_threat_detected_warning(self, humanizer: NotificationHumanizer) -> None:
        req = HumanizeRequest(
            alert_type="threat_detected",
            severity="warning",
            ip="10.0.0.1",
            message="Threat score 0.85",
        )
        result = await humanizer.humanize(req)
        assert result.title == "Tehdit Algilandi"
        assert "koruma" in result.body.lower()


# ---------------------------------------------------------------------------
# Fallback and placeholder tests
# ---------------------------------------------------------------------------


class TestFallbackAndPlaceholders:
    """Tests for template fallback and placeholder handling."""

    @pytest.mark.asyncio()
    async def test_unknown_alert_type_falls_back(self, humanizer: NotificationHumanizer) -> None:
        """Unknown alert types should use the fallback template."""
        req = HumanizeRequest(
            alert_type="unknown_type",
            severity="warning",
            message="Some unknown alert",
        )
        result = await humanizer.humanize(req)
        assert result.title == "Dikkat"
        assert result.generated_by == "rules"

    @pytest.mark.asyncio()
    async def test_unknown_severity_falls_back(self, humanizer: NotificationHumanizer) -> None:
        """Unknown severity in a known alert type falls back to generic."""
        req = HumanizeRequest(
            alert_type="new_device",
            severity="critical",  # new_device has no critical template
            message="Critical new device",
        )
        result = await humanizer.humanize(req)
        # Should fall back to FALLBACK_TEMPLATE["critical"]
        assert result.title == "Acil Durum"
        assert result.severity == "critical"

    @pytest.mark.asyncio()
    async def test_missing_ip_uses_default(self, humanizer: NotificationHumanizer) -> None:
        """Missing IP should use 'bilinmeyen' placeholder."""
        req = HumanizeRequest(
            alert_type="new_device",
            severity="info",
            message="New device detected",
            # ip is None
        )
        result = await humanizer.humanize(req)
        assert "bilinmeyen" in result.body

    @pytest.mark.asyncio()
    async def test_missing_device_name_uses_ip(self, humanizer: NotificationHumanizer) -> None:
        """Missing device_name should fall back to IP address."""
        req = HumanizeRequest(
            alert_type="port_change",
            severity="info",
            ip="192.168.1.5",
            message="Port change",
            # device_name is None
        )
        result = await humanizer.humanize(req)
        assert "192.168.1.5" in result.body

    @pytest.mark.asyncio()
    async def test_port_placeholder_from_details(self, humanizer: NotificationHumanizer) -> None:
        """Port number should come from details dict."""
        req = HumanizeRequest(
            alert_type="port_change",
            severity="warning",
            ip="192.168.1.5",
            message="Port 445 open",
            device_name="Server",
            details={"port": 445},
        )
        result = await humanizer.humanize(req)
        # The port_change warning template doesn't use {port} directly
        # but the filling should not raise
        assert result.body is not None

    @pytest.mark.asyncio()
    async def test_empty_details_handled_gracefully(self, humanizer: NotificationHumanizer) -> None:
        """Empty details dict should not cause errors."""
        req = HumanizeRequest(
            alert_type="port_change",
            severity="info",
            ip="192.168.1.5",
            message="Port change",
            details={},
        )
        result = await humanizer.humanize(req)
        assert result.body is not None


# ---------------------------------------------------------------------------
# Notification model field tests
# ---------------------------------------------------------------------------


class TestNotificationFields:
    """Tests that HumanNotification fields are correctly populated."""

    @pytest.mark.asyncio()
    async def test_all_fields_present(
        self, humanizer: NotificationHumanizer, sample_request: HumanizeRequest
    ) -> None:
        result = await humanizer.humanize(sample_request)
        assert result.id  # non-empty UUID string
        assert result.title
        assert result.body
        assert result.severity == "warning"
        assert result.icon
        assert result.original_alert_type == "port_change"
        assert result.original_message == sample_request.message
        assert result.generated_by == "rules"
        assert result.created_at  # ISO timestamp

    @pytest.mark.asyncio()
    async def test_notification_id_is_unique(self, humanizer: NotificationHumanizer) -> None:
        req = HumanizeRequest(
            alert_type="new_device",
            severity="info",
            message="Test",
        )
        r1 = await humanizer.humanize(req)
        r2 = await humanizer.humanize(req)
        assert r1.id != r2.id

    @pytest.mark.asyncio()
    async def test_action_fields_none_when_no_action(self, humanizer: NotificationHumanizer) -> None:
        """Info-level port_change has no action button."""
        req = HumanizeRequest(
            alert_type="port_change",
            severity="info",
            ip="192.168.1.5",
            message="Port change",
            device_name="Router",
        )
        result = await humanizer.humanize(req)
        assert result.action_label is None
        assert result.action_type is None


# ---------------------------------------------------------------------------
# Batch humanization tests
# ---------------------------------------------------------------------------


class TestBatchHumanization:
    """Tests for batch processing of multiple alerts."""

    @pytest.mark.asyncio()
    async def test_batch_returns_all(self, humanizer: NotificationHumanizer) -> None:
        requests = [
            HumanizeRequest(alert_type="new_device", severity="info", message="New 1"),
            HumanizeRequest(alert_type="port_change", severity="warning", ip="1.2.3.4", message="Port", device_name="PC"),
            HumanizeRequest(alert_type="rogue_device", severity="critical", ip="5.6.7.8", message="Rogue"),
        ]
        results = await humanizer.humanize_batch(requests)
        assert len(results) == 3
        assert all(isinstance(r, HumanNotification) for r in results)

    @pytest.mark.asyncio()
    async def test_batch_empty_list(self, humanizer: NotificationHumanizer) -> None:
        results = await humanizer.humanize_batch([])
        assert results == []


# ---------------------------------------------------------------------------
# AI humanization tests
# ---------------------------------------------------------------------------


class TestAIHumanization:
    """Tests for AI-based humanization with a mock router."""

    @pytest.mark.asyncio()
    async def test_ai_used_for_warning(
        self, ai_humanizer: NotificationHumanizer, mock_router: MagicMock
    ) -> None:
        req = HumanizeRequest(
            alert_type="port_change",
            severity="warning",
            ip="192.168.1.5",
            message="Port 445 open",
            device_name="PC",
        )
        result = await ai_humanizer.humanize(req)
        mock_router.route.assert_called_once()
        assert result.generated_by == "L1"
        assert "supheli" in result.body.lower() or "kontrol" in result.body.lower()

    @pytest.mark.asyncio()
    async def test_ai_used_for_critical(
        self, ai_humanizer: NotificationHumanizer, mock_router: MagicMock
    ) -> None:
        req = HumanizeRequest(
            alert_type="rogue_device",
            severity="critical",
            ip="192.168.1.99",
            message="Rogue device",
        )
        result = await ai_humanizer.humanize(req)
        mock_router.route.assert_called_once()
        assert result.generated_by == "L1"

    @pytest.mark.asyncio()
    async def test_ai_not_used_for_info(
        self, ai_humanizer: NotificationHumanizer, mock_router: MagicMock
    ) -> None:
        """Info-level alerts should use templates, not AI."""
        req = HumanizeRequest(
            alert_type="new_device",
            severity="info",
            ip="192.168.1.23",
            message="New device",
        )
        result = await ai_humanizer.humanize(req)
        mock_router.route.assert_not_called()
        assert result.generated_by == "rules"

    @pytest.mark.asyncio()
    async def test_ai_fallback_on_error(self, mock_router: MagicMock) -> None:
        """When AI router raises an exception, fall back to templates."""
        mock_router.route = AsyncMock(side_effect=RuntimeError("Connection failed"))
        humanizer = NotificationHumanizer(ai_router=mock_router)

        req = HumanizeRequest(
            alert_type="port_change",
            severity="warning",
            ip="192.168.1.5",
            message="Port 445 open",
            device_name="PC",
        )
        result = await humanizer.humanize(req)
        assert result.generated_by == "rules"
        assert result.title == "Riskli Port Acik"

    @pytest.mark.asyncio()
    async def test_ai_strips_quotes(self, mock_router: MagicMock) -> None:
        """AI output wrapped in quotes should have quotes stripped."""
        mock_result = MagicMock()
        mock_result.content = '"Aginda supheli bir hareket var."'
        mock_result.tier_used = "L0_local"
        mock_router.route = AsyncMock(return_value=mock_result)

        humanizer = NotificationHumanizer(ai_router=mock_router)
        req = HumanizeRequest(
            alert_type="rogue_device",
            severity="warning",
            ip="1.2.3.4",
            message="Rogue device",
        )
        result = await humanizer.humanize(req)
        assert not result.body.startswith('"')
        assert not result.body.endswith('"')
        assert result.generated_by == "L0"


# ---------------------------------------------------------------------------
# Template coverage tests
# ---------------------------------------------------------------------------


class TestTemplateCoverage:
    """Tests that all templates have required fields and all AlertTypes are covered."""

    def test_all_templates_have_required_fields(self) -> None:
        """Every template must have title, body, and icon."""
        for alert_type, severities in TEMPLATES.items():
            for severity, template in severities.items():
                assert "title" in template, f"{alert_type}/{severity} missing title"
                assert "body" in template, f"{alert_type}/{severity} missing body"
                assert "icon" in template, f"{alert_type}/{severity} missing icon"

    def test_fallback_templates_have_required_fields(self) -> None:
        """Fallback templates must have title, body, and icon."""
        for severity, template in FALLBACK_TEMPLATE.items():
            assert "title" in template, f"fallback/{severity} missing title"
            assert "body" in template, f"fallback/{severity} missing body"
            assert "icon" in template, f"fallback/{severity} missing icon"

    def test_all_alert_types_covered(self) -> None:
        """All AlertType enum values must have a template."""
        from bigr.alerts.models import AlertType

        for alert_type in AlertType:
            assert alert_type.value in TEMPLATES, (
                f"AlertType.{alert_type.name} ({alert_type.value}) has no template"
            )

    def test_fallback_covers_all_severities(self) -> None:
        """Fallback should have info, warning, and critical."""
        assert "info" in FALLBACK_TEMPLATE
        assert "warning" in FALLBACK_TEMPLATE
        assert "critical" in FALLBACK_TEMPLATE

    def test_templates_have_at_least_one_severity(self) -> None:
        """Each alert type template must have at least one severity."""
        for alert_type, severities in TEMPLATES.items():
            assert len(severities) >= 1, f"{alert_type} has no severity entries"


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


class TestLanguageAPI:
    """Tests for the FastAPI language engine endpoints."""

    @pytest.fixture()
    def app_client(self) -> TestClient:
        """Create a test client for the language API."""
        from fastapi import FastAPI
        from bigr.language.api import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_humanize_endpoint(self, app_client: TestClient) -> None:
        resp = app_client.post(
            "/api/language/humanize",
            json={
                "alert_type": "new_device",
                "severity": "info",
                "ip": "192.168.1.23",
                "message": "New device detected",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "notification" in data
        notif = data["notification"]
        assert notif["title"] == "Yeni Misafir"
        assert notif["severity"] == "info"
        assert notif["generated_by"] == "rules"

    def test_humanize_batch_endpoint(self, app_client: TestClient) -> None:
        resp = app_client.post(
            "/api/language/humanize/batch",
            json=[
                {"alert_type": "new_device", "severity": "info", "message": "New 1"},
                {"alert_type": "port_change", "severity": "warning", "ip": "1.2.3.4", "message": "Port", "device_name": "PC"},
            ],
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2
        assert len(data["notifications"]) == 2

    def test_templates_endpoint(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/language/templates")
        assert resp.status_code == 200
        data = resp.json()
        assert "templates" in data
        assert "fallback" in data
        assert "alert_types" in data
        assert "new_device" in data["alert_types"]

    def test_preview_endpoint(self, app_client: TestClient) -> None:
        resp = app_client.post(
            "/api/language/preview",
            json={
                "alert_type": "rogue_device",
                "severity": "critical",
                "ip": "192.168.1.99",
                "message": "Rogue device detected",
            },
            params={"tone": "warm"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "preview" in data
        assert data["tone"] == "warm"

    def test_sample_notifications_endpoint(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/language/sample-notifications")
        assert resp.status_code == 200
        data = resp.json()
        assert "samples" in data
        assert data["count"] > 0
        # Should have notifications for multiple alert types
        alert_types = {s["original_alert_type"] for s in data["samples"]}
        assert len(alert_types) >= 5

    def test_humanize_with_unknown_type(self, app_client: TestClient) -> None:
        """Unknown alert types should still return a valid notification."""
        resp = app_client.post(
            "/api/language/humanize",
            json={
                "alert_type": "totally_unknown",
                "severity": "info",
                "message": "Something happened",
            },
        )
        assert resp.status_code == 200
        notif = resp.json()["notification"]
        assert notif["title"] == "Bilgi"  # fallback


# ---------------------------------------------------------------------------
# Preferences tests
# ---------------------------------------------------------------------------


class TestPreferences:
    """Tests for notification preferences."""

    @pytest.mark.asyncio()
    async def test_default_preferences(self, humanizer: NotificationHumanizer) -> None:
        req = HumanizeRequest(
            alert_type="new_device",
            severity="info",
            message="Test",
        )
        result = await humanizer.humanize(req)
        # With default preferences, should still work fine
        assert result.body is not None

    @pytest.mark.asyncio()
    async def test_custom_preferences_passed(self, humanizer: NotificationHumanizer) -> None:
        prefs = NotificationPreferences(
            language="tr",
            tone="professional",
            include_technical=True,
        )
        req = HumanizeRequest(
            alert_type="new_device",
            severity="info",
            message="Test",
        )
        # Should not raise with custom preferences
        result = await humanizer.humanize(req, prefs)
        assert result.body is not None
