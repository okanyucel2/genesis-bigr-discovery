"""Tests for bigr.shield.api — Shield API endpoints.

These tests exercise the orchestrator and API logic directly without requiring
the shield router to be registered in create_app(). We test the orchestrator
and route handlers in isolation.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bigr.shield.models import (
    FindingSeverity,
    ModuleScore,
    ScanDepth,
    ScanStatus,
    ShieldFinding,
    ShieldGrade,
    ShieldScan,
)
from bigr.shield.orchestrator import ShieldOrchestrator


class TestOrchestratorCreateScan:
    """Test ShieldOrchestrator.create_scan()."""

    @pytest.mark.asyncio
    async def test_create_scan_returns_scan(self):
        orch = ShieldOrchestrator()
        scan = await orch.create_scan("example.com")
        assert scan.target == "example.com"
        assert scan.status == ScanStatus.QUEUED
        assert scan.id.startswith("sh_")
        assert "tls" in scan.modules_enabled

    @pytest.mark.asyncio
    async def test_create_scan_custom_depth(self):
        orch = ShieldOrchestrator()
        scan = await orch.create_scan("example.com", depth=ScanDepth.STANDARD)
        assert scan.scan_depth == ScanDepth.STANDARD
        assert "tls" in scan.modules_enabled
        assert "ports" in scan.modules_enabled

    @pytest.mark.asyncio
    async def test_create_scan_custom_modules(self):
        orch = ShieldOrchestrator()
        scan = await orch.create_scan("example.com", modules=["tls", "headers"])
        assert scan.modules_enabled == ["tls", "headers"]

    @pytest.mark.asyncio
    async def test_create_scan_detects_ip(self):
        orch = ShieldOrchestrator()
        scan = await orch.create_scan("192.168.1.1")
        assert scan.target_type == "ip"

    @pytest.mark.asyncio
    async def test_create_scan_detects_cidr(self):
        orch = ShieldOrchestrator()
        scan = await orch.create_scan("10.0.0.0/24")
        assert scan.target_type == "cidr"

    @pytest.mark.asyncio
    async def test_create_scan_detects_domain(self):
        orch = ShieldOrchestrator()
        scan = await orch.create_scan("example.com")
        assert scan.target_type == "domain"


class TestOrchestratorSensitivity:
    """Test sensitivity-based module filtering in create_scan()."""

    @pytest.mark.asyncio
    async def test_fragile_restricts_to_passive(self):
        orch = ShieldOrchestrator()
        scan = await orch.create_scan("192.168.1.50", depth=ScanDepth.DEEP, sensitivity="fragile")
        assert set(scan.modules_enabled) == {"tls", "dns", "headers"}
        assert scan.sensitivity == "fragile"

    @pytest.mark.asyncio
    async def test_cautious_excludes_creds_owasp(self):
        orch = ShieldOrchestrator()
        scan = await orch.create_scan("192.168.1.60", depth=ScanDepth.DEEP, sensitivity="cautious")
        assert "creds" not in scan.modules_enabled
        assert "owasp" not in scan.modules_enabled
        assert "cve" not in scan.modules_enabled
        assert "tls" in scan.modules_enabled
        assert "ports" in scan.modules_enabled

    @pytest.mark.asyncio
    async def test_safe_no_restriction(self):
        orch = ShieldOrchestrator()
        scan = await orch.create_scan("192.168.1.1", depth=ScanDepth.DEEP, sensitivity="safe")
        # safe = no restriction, full deep modules
        assert "creds" in scan.modules_enabled
        assert "owasp" in scan.modules_enabled

    @pytest.mark.asyncio
    async def test_none_sensitivity_no_restriction(self):
        orch = ShieldOrchestrator()
        scan = await orch.create_scan("192.168.1.1", depth=ScanDepth.DEEP)
        assert "creds" in scan.modules_enabled

    @pytest.mark.asyncio
    async def test_sensitivity_stored_in_scan(self):
        orch = ShieldOrchestrator()
        scan = await orch.create_scan("192.168.1.50", sensitivity="fragile")
        assert scan.to_dict()["sensitivity"] == "fragile"


class TestOrchestratorGetScan:
    """Test ShieldOrchestrator.get_scan()."""

    @pytest.mark.asyncio
    async def test_get_existing_scan(self):
        orch = ShieldOrchestrator()
        scan = await orch.create_scan("example.com")
        retrieved = orch.get_scan(scan.id)
        assert retrieved is not None
        assert retrieved.id == scan.id

    def test_get_nonexistent_scan(self):
        orch = ShieldOrchestrator()
        assert orch.get_scan("sh_doesnotexist") is None


class TestOrchestratorRunScan:
    """Test ShieldOrchestrator.run_scan()."""

    @pytest.mark.asyncio
    async def test_run_scan_completes(self):
        orch = ShieldOrchestrator()

        # Mock the TLS module to return a known finding
        mock_module = MagicMock()
        mock_module.name = "tls"
        mock_module.weight = 20
        mock_module.check_available.return_value = True
        mock_module.scan = AsyncMock(return_value=[
            ShieldFinding(
                module="tls",
                severity=FindingSeverity.LOW,
                title="HSTS Missing",
            ),
        ])
        orch._modules = {"tls": mock_module}

        scan = await orch.create_scan("test.example.com")
        result = await orch.run_scan(scan.id)

        assert result.status == ScanStatus.COMPLETED
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.shield_score is not None
        assert result.grade is not None
        assert len(result.findings) == 1
        assert result.findings[0].scan_id == scan.id
        assert "tls" in result.module_scores

    @pytest.mark.asyncio
    async def test_run_scan_not_found(self):
        orch = ShieldOrchestrator()
        with pytest.raises(ValueError, match="not found"):
            await orch.run_scan("sh_nonexistent")

    @pytest.mark.asyncio
    async def test_run_scan_already_completed(self):
        orch = ShieldOrchestrator()

        mock_module = MagicMock()
        mock_module.name = "tls"
        mock_module.weight = 20
        mock_module.check_available.return_value = True
        mock_module.scan = AsyncMock(return_value=[])
        orch._modules = {"tls": mock_module}

        scan = await orch.create_scan("test.example.com")
        await orch.run_scan(scan.id)

        with pytest.raises(ValueError, match="not in a runnable state"):
            await orch.run_scan(scan.id)

    @pytest.mark.asyncio
    async def test_run_scan_no_findings_perfect_score(self):
        orch = ShieldOrchestrator()

        mock_module = MagicMock()
        mock_module.name = "tls"
        mock_module.weight = 20
        mock_module.check_available.return_value = True
        mock_module.scan = AsyncMock(return_value=[])
        orch._modules = {"tls": mock_module}

        scan = await orch.create_scan("perfect.example.com")
        result = await orch.run_scan(scan.id)

        assert result.shield_score == 100.0
        assert result.grade == ShieldGrade.A_PLUS
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_run_scan_module_unavailable_skipped(self):
        orch = ShieldOrchestrator()

        mock_module = MagicMock()
        mock_module.name = "tls"
        mock_module.weight = 20
        mock_module.check_available.return_value = False
        orch._modules = {"tls": mock_module}

        scan = await orch.create_scan("test.example.com")
        result = await orch.run_scan(scan.id)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) == 0
        # No module scores since the only module was unavailable
        assert len(result.module_scores) == 0

    @pytest.mark.asyncio
    async def test_run_scan_module_exception_handled(self):
        """If a module raises, the scan should still complete."""
        orch = ShieldOrchestrator()

        mock_module = MagicMock()
        mock_module.name = "tls"
        mock_module.weight = 20
        mock_module.check_available.return_value = True
        mock_module.scan = AsyncMock(side_effect=RuntimeError("module crashed"))
        orch._modules = {"tls": mock_module}

        scan = await orch.create_scan("error.example.com")
        result = await orch.run_scan(scan.id)

        # Scan completes but with empty results for the failed module
        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) == 0


class TestOrchestratorListScans:
    """Test ShieldOrchestrator.list_scans()."""

    @pytest.mark.asyncio
    async def test_list_scans_empty(self):
        orch = ShieldOrchestrator()
        assert orch.list_scans() == []

    @pytest.mark.asyncio
    async def test_list_scans_returns_recent_first(self):
        orch = ShieldOrchestrator()
        scan1 = await orch.create_scan("first.com")
        scan2 = await orch.create_scan("second.com")
        scan3 = await orch.create_scan("third.com")

        scans = orch.list_scans()
        assert len(scans) == 3
        # Most recent first
        assert scans[0].id == scan3.id
        assert scans[2].id == scan1.id

    @pytest.mark.asyncio
    async def test_list_scans_limit(self):
        orch = ShieldOrchestrator()
        for i in range(5):
            await orch.create_scan(f"host{i}.com")

        scans = orch.list_scans(limit=3)
        assert len(scans) == 3


class TestOrchestratorGetFindings:
    """Test retrieving findings from a completed scan."""

    @pytest.mark.asyncio
    async def test_findings_tagged_with_scan_id(self):
        orch = ShieldOrchestrator()

        finding = ShieldFinding(
            module="tls",
            severity=FindingSeverity.HIGH,
            title="Test Finding",
        )
        mock_module = MagicMock()
        mock_module.name = "tls"
        mock_module.weight = 20
        mock_module.check_available.return_value = True
        mock_module.scan = AsyncMock(return_value=[finding])
        orch._modules = {"tls": mock_module}

        scan = await orch.create_scan("example.com")
        result = await orch.run_scan(scan.id)

        assert len(result.findings) == 1
        assert result.findings[0].scan_id == scan.id


class TestOrchestratorModules:
    """Test the modules listing functionality."""

    def test_default_modules(self):
        orch = ShieldOrchestrator()
        assert "tls" in orch._modules
        assert orch._modules["tls"].check_available() is True


class TestAPIRouterDirect:
    """Test the API route handlers by importing and calling them directly.

    Since we cannot wire up the router to create_app() without modifying it,
    we test the underlying orchestrator which the routes delegate to.
    """

    @pytest.mark.asyncio
    async def test_quick_scan_end_to_end(self):
        """Simulate what POST /api/shield/quick does."""
        orch = ShieldOrchestrator()

        mock_module = MagicMock()
        mock_module.name = "tls"
        mock_module.weight = 20
        mock_module.check_available.return_value = True
        mock_module.scan = AsyncMock(return_value=[
            ShieldFinding(
                module="tls",
                severity=FindingSeverity.LOW,
                title="HSTS Missing",
            ),
        ])
        orch._modules = {"tls": mock_module}

        scan = await orch.create_scan(target="quick.example.com", depth=ScanDepth.QUICK)
        await orch.run_scan(scan.id)

        result_dict = scan.to_dict()
        assert result_dict["status"] == "completed"
        assert result_dict["target"] == "quick.example.com"
        assert result_dict["shield_score"] is not None
        assert result_dict["grade"] is not None
        assert result_dict["findings_count"] == 1

    @pytest.mark.asyncio
    async def test_nonexistent_scan_returns_none(self):
        """Simulate what GET /api/shield/scan/{id} returns for 404."""
        orch = ShieldOrchestrator()
        result = orch.get_scan("sh_nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_scan_findings_retrieval(self):
        """Simulate what GET /api/shield/scan/{id}/findings returns."""
        orch = ShieldOrchestrator()

        mock_module = MagicMock()
        mock_module.name = "tls"
        mock_module.weight = 20
        mock_module.check_available.return_value = True
        mock_module.scan = AsyncMock(return_value=[
            ShieldFinding(module="tls", severity=FindingSeverity.HIGH, title="Finding A"),
            ShieldFinding(module="tls", severity=FindingSeverity.LOW, title="Finding B"),
        ])
        orch._modules = {"tls": mock_module}

        scan = await orch.create_scan("findings.example.com")
        await orch.run_scan(scan.id)

        result = orch.get_scan(scan.id)
        assert result is not None
        findings_response = {
            "scan_id": result.id,
            "target": result.target,
            "total_findings": len(result.findings),
            "findings": [f.to_dict() for f in result.findings],
        }
        assert findings_response["total_findings"] == 2
        assert findings_response["findings"][0]["title"] == "Finding A"
        assert findings_response["findings"][1]["title"] == "Finding B"

    def test_modules_listing(self):
        """Simulate what GET /api/shield/modules returns."""
        orch = ShieldOrchestrator()
        modules = []
        for name, mod in orch._modules.items():
            modules.append({
                "name": mod.name,
                "weight": mod.weight,
                "available": mod.check_available(),
            })
        assert len(modules) >= 1
        tls_mod = next((m for m in modules if m["name"] == "tls"), None)
        assert tls_mod is not None
        assert tls_mod["weight"] == 20
        assert tls_mod["available"] is True
