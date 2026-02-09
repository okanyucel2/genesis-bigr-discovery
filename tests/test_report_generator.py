"""Tests for BİGR report generation (Phase 5B).

TDD: All tests written FIRST, then implementation.
"""

from __future__ import annotations

import os

import pytest

from bigr.report.charts import (
    generate_bar_chart_svg,
    generate_gauge_svg,
    generate_pie_chart_svg,
    generate_trend_line_svg,
)
from bigr.report.generator import (
    GeneratedReport,
    ReportConfig,
    build_full_report,
    build_html_wrapper,
    generate_action_items_section,
    generate_asset_table_section,
    generate_category_section,
    generate_changes_section,
    generate_executive_summary,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_COLORS = {
    "ag_ve_sistemler": "#3b82f6",
    "uygulamalar": "#10b981",
    "iot": "#f59e0b",
    "tasinabilir": "#ef4444",
    "unclassified": "#6b7280",
}

SAMPLE_DISTRIBUTION = {
    "ag_ve_sistemler": 5,
    "uygulamalar": 3,
    "iot": 2,
    "tasinabilir": 1,
}


@pytest.fixture
def sample_assets() -> list[dict]:
    return [
        {
            "ip": "192.168.1.1",
            "mac": "aa:bb:cc:dd:ee:01",
            "hostname": "router.local",
            "vendor": "Cisco",
            "open_ports": [22, 80, 443],
            "bigr_category": "ag_ve_sistemler",
            "bigr_category_tr": "Ağ ve Sistemler",
            "confidence_score": 0.95,
            "confidence_level": "high",
        },
        {
            "ip": "192.168.1.10",
            "mac": "aa:bb:cc:dd:ee:02",
            "hostname": "webserver.local",
            "vendor": "Dell",
            "open_ports": [80, 443, 8080],
            "bigr_category": "uygulamalar",
            "bigr_category_tr": "Uygulamalar",
            "confidence_score": 0.85,
            "confidence_level": "high",
        },
        {
            "ip": "192.168.1.20",
            "mac": "aa:bb:cc:dd:ee:03",
            "hostname": "camera-01",
            "vendor": "Hikvision",
            "open_ports": [554, 80],
            "bigr_category": "iot",
            "bigr_category_tr": "IoT",
            "confidence_score": 0.78,
            "confidence_level": "high",
        },
        {
            "ip": "192.168.1.100",
            "mac": "aa:bb:cc:dd:ee:04",
            "hostname": "laptop-okan",
            "vendor": "Apple",
            "open_ports": [],
            "bigr_category": "tasinabilir",
            "bigr_category_tr": "Taşınabilir Cihazlar",
            "confidence_score": 0.72,
            "confidence_level": "high",
        },
    ]


@pytest.fixture
def sample_compliance_data() -> dict:
    return {
        "score": 85.5,
        "grade": "B+",
        "scan_date": "2026-02-09",
        "category_distribution": SAMPLE_DISTRIBUTION,
        "total_classified": 11,
        "total_unclassified": 0,
    }


@pytest.fixture
def sample_changes() -> list[dict]:
    return [
        {
            "change_type": "new_asset",
            "ip": "192.168.1.50",
            "mac": "aa:bb:cc:dd:ee:50",
            "detected_at": "2026-02-09T10:00:00",
        },
        {
            "change_type": "field_changed",
            "ip": "192.168.1.1",
            "field_name": "open_ports",
            "old_value": "[22, 80]",
            "new_value": "[22, 80, 443]",
            "detected_at": "2026-02-09T10:00:00",
        },
    ]


@pytest.fixture
def sample_action_items() -> list[dict]:
    return [
        {
            "priority": "critical",
            "title": "Unclassified IoT device detected",
            "description": "Device at 192.168.1.99 has no BİGR classification",
            "ip": "192.168.1.99",
        },
        {
            "priority": "normal",
            "title": "Update firmware on router",
            "description": "Router at 192.168.1.1 running outdated firmware",
            "ip": "192.168.1.1",
        },
    ]


# ===========================================================================
# TestPieChartSvg
# ===========================================================================


class TestPieChartSvg:
    def test_generates_svg(self):
        svg = generate_pie_chart_svg(SAMPLE_DISTRIBUTION, SAMPLE_COLORS)
        assert svg.strip().startswith("<svg")

    def test_includes_all_categories(self):
        svg = generate_pie_chart_svg(SAMPLE_DISTRIBUTION, SAMPLE_COLORS)
        for key in SAMPLE_DISTRIBUTION:
            assert key in svg

    def test_empty_data(self):
        svg = generate_pie_chart_svg({}, SAMPLE_COLORS)
        assert svg.strip().startswith("<svg")
        assert "</svg>" in svg

    def test_single_category(self):
        data = {"ag_ve_sistemler": 10}
        svg = generate_pie_chart_svg(data, SAMPLE_COLORS)
        assert svg.strip().startswith("<svg")
        assert "ag_ve_sistemler" in svg

    def test_uses_provided_colors(self):
        svg = generate_pie_chart_svg(SAMPLE_DISTRIBUTION, SAMPLE_COLORS)
        assert "#3b82f6" in svg  # ag_ve_sistemler color
        assert "#10b981" in svg  # uygulamalar color


# ===========================================================================
# TestBarChartSvg
# ===========================================================================


class TestBarChartSvg:
    def test_generates_svg(self):
        svg = generate_bar_chart_svg(SAMPLE_DISTRIBUTION, SAMPLE_COLORS)
        assert svg.strip().startswith("<svg")

    def test_bar_for_each_category(self):
        svg = generate_bar_chart_svg(SAMPLE_DISTRIBUTION, SAMPLE_COLORS)
        # Each category should have a rect element
        assert svg.count("<rect") >= len(SAMPLE_DISTRIBUTION)

    def test_labels_included(self):
        svg = generate_bar_chart_svg(SAMPLE_DISTRIBUTION, SAMPLE_COLORS)
        for key in SAMPLE_DISTRIBUTION:
            assert key in svg

    def test_empty_data(self):
        svg = generate_bar_chart_svg({}, SAMPLE_COLORS)
        assert svg.strip().startswith("<svg")
        assert "</svg>" in svg


# ===========================================================================
# TestGaugeSvg
# ===========================================================================


class TestGaugeSvg:
    def test_generates_svg(self):
        svg = generate_gauge_svg(75.0)
        assert svg.strip().startswith("<svg")

    def test_high_score_green(self):
        svg = generate_gauge_svg(95.0)
        # Should contain a green color indicator
        assert "#22c55e" in svg or "green" in svg.lower()

    def test_medium_score_yellow(self):
        svg = generate_gauge_svg(75.0)
        assert "#eab308" in svg or "yellow" in svg.lower()

    def test_low_score_red(self):
        svg = generate_gauge_svg(30.0)
        assert "#ef4444" in svg or "red" in svg.lower()

    def test_label_included(self):
        svg = generate_gauge_svg(80.0, label="Compliance")
        assert "Compliance" in svg

    def test_zero_value(self):
        svg = generate_gauge_svg(0.0)
        assert svg.strip().startswith("<svg")
        assert "</svg>" in svg


# ===========================================================================
# TestTrendLineSvg
# ===========================================================================


class TestTrendLineSvg:
    def test_generates_svg(self):
        points = [("2026-02-01", 75.5), ("2026-02-02", 78.0), ("2026-02-03", 80.0)]
        svg = generate_trend_line_svg(points)
        assert svg.strip().startswith("<svg")

    def test_data_points_rendered(self):
        points = [("2026-02-01", 75.5), ("2026-02-02", 78.0), ("2026-02-03", 80.0)]
        svg = generate_trend_line_svg(points)
        # Should have circle elements for data points
        assert "<circle" in svg or "<polyline" in svg or "<path" in svg

    def test_empty_data(self):
        svg = generate_trend_line_svg([])
        assert svg.strip().startswith("<svg")
        assert "</svg>" in svg

    def test_single_point(self):
        points = [("2026-02-01", 75.5)]
        svg = generate_trend_line_svg(points)
        assert svg.strip().startswith("<svg")
        assert "</svg>" in svg


# ===========================================================================
# TestReportConfig
# ===========================================================================


class TestReportConfig:
    def test_defaults(self):
        config = ReportConfig()
        assert config.organization == "BİGR Discovery"
        assert config.author == "BİGR Discovery Agent"
        assert config.logo_path is None
        assert config.include_charts is True
        assert config.include_action_items is True
        assert config.include_changes is True
        assert config.days_lookback == 30

    def test_custom_config(self):
        config = ReportConfig(
            organization="Acme Corp",
            author="Test User",
            logo_path="/path/to/logo.png",
            include_charts=False,
            include_action_items=False,
            include_changes=False,
            days_lookback=7,
        )
        assert config.organization == "Acme Corp"
        assert config.author == "Test User"
        assert config.logo_path == "/path/to/logo.png"
        assert config.include_charts is False
        assert config.include_action_items is False
        assert config.include_changes is False
        assert config.days_lookback == 7


# ===========================================================================
# TestGeneratedReport
# ===========================================================================


class TestGeneratedReport:
    def test_save_html(self, tmp_path):
        report = GeneratedReport(
            title="Test Report",
            html_content="<html><body>Hello</body></html>",
        )
        path = str(tmp_path / "report.html")
        result = report.save(path)
        assert result == path

    def test_save_creates_file(self, tmp_path):
        report = GeneratedReport(
            title="Test Report",
            html_content="<html><body>Content</body></html>",
        )
        path = str(tmp_path / "report.html")
        report.save(path)
        assert os.path.exists(path)

    def test_html_content_preserved(self, tmp_path):
        html = "<html><body><h1>BİGR Report</h1></body></html>"
        report = GeneratedReport(title="Test", html_content=html)
        path = str(tmp_path / "report.html")
        report.save(path)
        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert content == html


# ===========================================================================
# TestExecutiveSummary
# ===========================================================================


class TestExecutiveSummary:
    def test_contains_total_assets(self, sample_assets, sample_compliance_data):
        html = generate_executive_summary(sample_assets, sample_compliance_data)
        assert "4" in html  # 4 assets

    def test_contains_compliance_score(self, sample_assets, sample_compliance_data):
        html = generate_executive_summary(sample_assets, sample_compliance_data)
        assert "85.5" in html

    def test_contains_grade(self, sample_assets, sample_compliance_data):
        html = generate_executive_summary(sample_assets, sample_compliance_data)
        assert "B+" in html

    def test_empty_assets(self, sample_compliance_data):
        html = generate_executive_summary([], sample_compliance_data)
        assert "0" in html


# ===========================================================================
# TestCategorySection
# ===========================================================================


class TestCategorySection:
    def test_contains_category_names(self):
        html = generate_category_section(SAMPLE_DISTRIBUTION)
        assert "ag_ve_sistemler" in html or "Ağ ve Sistemler" in html

    def test_contains_counts(self):
        html = generate_category_section(SAMPLE_DISTRIBUTION)
        assert "5" in html  # ag_ve_sistemler count
        assert "3" in html  # uygulamalar count

    def test_includes_chart_svg(self):
        html = generate_category_section(SAMPLE_DISTRIBUTION)
        assert "<svg" in html


# ===========================================================================
# TestAssetTableSection
# ===========================================================================


class TestAssetTableSection:
    def test_contains_asset_ips(self, sample_assets):
        html = generate_asset_table_section(sample_assets)
        assert "192.168.1.1" in html
        assert "192.168.1.10" in html

    def test_filtered_by_category(self, sample_assets):
        html = generate_asset_table_section(sample_assets, category="iot")
        assert "192.168.1.20" in html  # IoT camera
        assert "192.168.1.1" not in html  # Router (ag_ve_sistemler)

    def test_empty_assets(self):
        html = generate_asset_table_section([])
        assert "<table" in html or "Varlık bulunamadı" in html or "table" in html.lower()

    def test_all_columns_present(self, sample_assets):
        html = generate_asset_table_section(sample_assets)
        # Check column headers exist
        assert "IP" in html
        assert "MAC" in html
        # hostname or Hostname
        assert "ostname" in html  # matches Hostname or hostname
        # vendor or Vendor
        assert "endor" in html  # matches Vendor or vendor
        # category
        assert "ategor" in html or "BİGR" in html  # matches Category or Kategori


# ===========================================================================
# TestChangesSection
# ===========================================================================


class TestChangesSection:
    def test_shows_new_assets(self, sample_changes):
        html = generate_changes_section(sample_changes)
        assert "192.168.1.50" in html
        assert "new" in html.lower() or "yeni" in html.lower()

    def test_shows_changed_fields(self, sample_changes):
        html = generate_changes_section(sample_changes)
        assert "open_ports" in html or "port" in html.lower()

    def test_empty_changes(self):
        html = generate_changes_section([])
        assert "değişiklik" in html.lower() or "change" in html.lower() or "yok" in html.lower()


# ===========================================================================
# TestActionItemsSection
# ===========================================================================


class TestActionItemsSection:
    def test_shows_critical_items(self, sample_action_items):
        html = generate_action_items_section(sample_action_items)
        assert "critical" in html.lower() or "kritik" in html.lower()
        assert "192.168.1.99" in html

    def test_shows_normal_items(self, sample_action_items):
        html = generate_action_items_section(sample_action_items)
        assert "192.168.1.1" in html

    def test_empty_items(self):
        html = generate_action_items_section([])
        assert "aksiyon" in html.lower() or "action" in html.lower() or "yok" in html.lower()


# ===========================================================================
# TestBuildFullReport
# ===========================================================================


class TestBuildFullReport:
    def test_returns_generated_report(self, sample_assets, sample_compliance_data):
        report = build_full_report(sample_assets, sample_compliance_data)
        assert isinstance(report, GeneratedReport)

    def test_has_all_sections(self, sample_assets, sample_compliance_data, sample_changes):
        report = build_full_report(
            sample_assets, sample_compliance_data, changes=sample_changes
        )
        html = report.html_content
        # Executive summary
        assert "Özet" in html or "Summary" in html or "özet" in html
        # Category distribution
        assert "Kategori" in html or "Category" in html or "kategori" in html
        # Assets table
        assert "192.168.1.1" in html
        # Changes
        assert "Değişiklik" in html or "Change" in html or "değişiklik" in html

    def test_html_is_valid(self, sample_assets, sample_compliance_data):
        report = build_full_report(sample_assets, sample_compliance_data)
        html = report.html_content
        assert "<html" in html
        assert "<body" in html
        assert "</html>" in html

    def test_includes_title(self, sample_assets, sample_compliance_data):
        report = build_full_report(sample_assets, sample_compliance_data)
        assert report.title
        assert len(report.title) > 0

    def test_turkish_characters(self, sample_assets, sample_compliance_data):
        report = build_full_report(sample_assets, sample_compliance_data)
        html = report.html_content
        # Turkish chars should be preserved (UTF-8)
        assert "Ağ" in html or "ağ" in html  # from category label
        assert "Taşınabilir" in html or "taşınabilir" in html or "Tasinabilir" in html.replace("ş", "s").replace("ı", "i")


# ===========================================================================
# TestHtmlWrapper
# ===========================================================================


class TestHtmlWrapper:
    def test_full_html_document(self):
        html = build_html_wrapper("Test", "<p>Body</p>")
        assert "<!DOCTYPE html>" in html or "<!doctype html>" in html.lower()
        assert "<html" in html
        assert "<head" in html
        assert "<body" in html
        assert "</html>" in html

    def test_utf8_meta(self):
        html = build_html_wrapper("Test", "<p>Body</p>")
        assert "charset" in html.lower()
        assert "utf-8" in html.lower() or "UTF-8" in html

    def test_includes_css(self):
        html = build_html_wrapper("Test", "<p>Body</p>")
        assert "<style" in html

    def test_print_friendly(self):
        html = build_html_wrapper("Test", "<p>Body</p>")
        assert "@media print" in html

    def test_organization_in_header(self):
        config = ReportConfig(organization="Acme Corp")
        html = build_html_wrapper("Test", "<p>Body</p>", config=config)
        assert "Acme Corp" in html


# ===========================================================================
# TestCliHtmlReport
# ===========================================================================


class TestCliHtmlReport:
    def test_html_report_format(self, tmp_path, sample_assets, sample_compliance_data):
        """Test --format html-report generates an HTML file."""
        import json

        from typer.testing import CliRunner

        from bigr.cli import app

        runner = CliRunner()

        # Create a scan result file
        scan_data = {
            "target": "192.168.1.0/24",
            "total_assets": len(sample_assets),
            "category_summary": {
                "ag_ve_sistemler": 1,
                "uygulamalar": 1,
                "iot": 1,
                "tasinabilir": 1,
            },
            "assets": sample_assets,
        }
        input_file = tmp_path / "scan.json"
        input_file.write_text(json.dumps(scan_data, ensure_ascii=False), encoding="utf-8")

        output_file = tmp_path / "report.html"
        result = runner.invoke(
            app,
            ["report", "--input", str(input_file), "--format", "html-report", "--output", str(output_file)],
        )
        assert result.exit_code == 0, f"CLI failed: {result.output}"
        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        assert "<html" in content

    def test_html_report_output_flag(self, tmp_path, sample_assets):
        """Test --output flag sets the filename."""
        import json

        from typer.testing import CliRunner

        from bigr.cli import app

        runner = CliRunner()

        scan_data = {
            "target": "10.0.0.0/8",
            "total_assets": 1,
            "category_summary": {"ag_ve_sistemler": 1},
            "assets": sample_assets[:1],
        }
        input_file = tmp_path / "scan2.json"
        input_file.write_text(json.dumps(scan_data, ensure_ascii=False), encoding="utf-8")

        custom_output = tmp_path / "custom_report.html"
        result = runner.invoke(
            app,
            ["report", "--input", str(input_file), "--format", "html-report", "--output", str(custom_output)],
        )
        assert result.exit_code == 0, f"CLI failed: {result.output}"
        assert custom_output.exists()
        assert "custom_report.html" in str(custom_output)
