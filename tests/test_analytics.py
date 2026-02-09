"""Tests for historical trending and analytics engine."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bigr.db import _connect, init_db


# ---------------------------------------------------------------------------
# Test data helper
# ---------------------------------------------------------------------------


def _populate_test_db(db_path: Path, days: int = 7) -> None:
    """Populate a test database with sample scan data over N days."""
    init_db(db_path)
    conn = _connect(db_path)

    categories = ["ag_ve_sistemler", "iot", "tasinabilir", "uygulamalar"]
    # Track asset ids keyed by (ip, mac) so we can reuse across days
    asset_ids: dict[tuple[str, str], str] = {}

    for day_offset in range(days):
        scan_date = datetime.now(timezone.utc) - timedelta(days=days - day_offset - 1)
        scan_id = str(uuid.uuid4())

        # Create scan
        conn.execute(
            "INSERT INTO scans (id, target, scan_method, started_at, completed_at, total_assets, is_root) VALUES (?,?,?,?,?,?,?)",
            (
                scan_id,
                "10.0.0.0/24",
                "hybrid",
                scan_date.isoformat(),
                (scan_date + timedelta(seconds=30)).isoformat(),
                5 + day_offset,
                1,
            ),
        )

        # Create assets for this scan
        last_asset_id = None
        for i in range(5 + day_offset):
            cat = categories[i % len(categories)]
            ip = f"10.0.0.{10 + i}"
            mac = f"aa:bb:cc:dd:ee:{i:02x}"
            key = (ip, mac)

            if key not in asset_ids:
                asset_id = str(uuid.uuid4())
                asset_ids[key] = asset_id
                conn.execute(
                    "INSERT INTO assets (id, ip, mac, bigr_category, confidence_score, scan_method, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        asset_id,
                        ip,
                        mac,
                        cat,
                        0.7,
                        "hybrid",
                        scan_date.isoformat(),
                        scan_date.isoformat(),
                    ),
                )
            else:
                asset_id = asset_ids[key]
                conn.execute(
                    "UPDATE assets SET last_seen = ? WHERE id = ?",
                    (scan_date.isoformat(), asset_id),
                )

            last_asset_id = asset_id
            conn.execute(
                "INSERT INTO scan_assets (scan_id, asset_id, open_ports, confidence_score, bigr_category) VALUES (?,?,?,?,?)",
                (scan_id, asset_id, json.dumps([22, 80]), 0.7, cat),
            )

        # Add some changes for days after the first
        if day_offset > 0 and last_asset_id is not None:
            conn.execute(
                "INSERT INTO asset_changes (asset_id, scan_id, change_type, detected_at) VALUES (?,?,?,?)",
                (last_asset_id, scan_id, "new_asset", scan_date.isoformat()),
            )

    conn.commit()
    conn.close()


# ===========================================================================
# TrendPoint
# ===========================================================================


class TestTrendPoint:
    def test_fields(self):
        from bigr.analytics import TrendPoint

        tp = TrendPoint(date="2026-02-09", value=42, label="test")
        assert tp.date == "2026-02-09"
        assert tp.value == 42
        assert tp.label == "test"

    def test_default_label(self):
        from bigr.analytics import TrendPoint

        tp = TrendPoint(date="2026-02-09", value=10)
        assert tp.label is None


# ===========================================================================
# TrendSeries
# ===========================================================================


class TestTrendSeries:
    def test_to_dict(self):
        from bigr.analytics import TrendPoint, TrendSeries

        series = TrendSeries(
            name="test",
            points=[TrendPoint(date="2026-02-09", value=5, label="a")],
        )
        d = series.to_dict()
        assert d["name"] == "test"
        assert len(d["points"]) == 1
        assert d["points"][0]["date"] == "2026-02-09"
        assert d["points"][0]["value"] == 5
        assert d["points"][0]["label"] == "a"

    def test_empty_points(self):
        from bigr.analytics import TrendSeries

        series = TrendSeries(name="empty")
        d = series.to_dict()
        assert d["name"] == "empty"
        assert d["points"] == []

    def test_multiple_points(self):
        from bigr.analytics import TrendPoint, TrendSeries

        pts = [
            TrendPoint(date="2026-02-01", value=1),
            TrendPoint(date="2026-02-02", value=2),
            TrendPoint(date="2026-02-03", value=3),
        ]
        series = TrendSeries(name="multi", points=pts)
        d = series.to_dict()
        assert len(d["points"]) == 3
        assert d["points"][2]["value"] == 3


# ===========================================================================
# AnalyticsResult
# ===========================================================================


class TestAnalyticsResult:
    def test_to_dict_empty(self):
        from bigr.analytics import AnalyticsResult

        result = AnalyticsResult()
        d = result.to_dict()
        assert d["asset_count_trend"] is None
        assert d["category_trends"] == []
        assert d["new_vs_removed"] is None
        assert d["most_changed_assets"] == []
        assert d["scan_frequency"] == []

    def test_to_dict_full(self):
        from bigr.analytics import AnalyticsResult, TrendPoint, TrendSeries

        result = AnalyticsResult(
            asset_count_trend=TrendSeries(
                name="assets", points=[TrendPoint(date="2026-02-09", value=10)]
            ),
            category_trends=[
                TrendSeries(
                    name="iot", points=[TrendPoint(date="2026-02-09", value=3)]
                ),
            ],
            new_vs_removed=TrendSeries(
                name="new_vs_removed",
                points=[TrendPoint(date="2026-02-09", value=5, label="new")],
            ),
            most_changed_assets=[{"ip": "10.0.0.1", "change_count": 5}],
            scan_frequency=[{"date": "2026-02-09", "scan_count": 2}],
        )
        d = result.to_dict()
        assert d["asset_count_trend"] is not None
        assert d["asset_count_trend"]["name"] == "assets"
        assert len(d["category_trends"]) == 1
        assert d["new_vs_removed"] is not None
        assert len(d["most_changed_assets"]) == 1
        assert len(d["scan_frequency"]) == 1


# ===========================================================================
# get_asset_count_trend
# ===========================================================================


class TestGetAssetCountTrend:
    def test_returns_trend_series(self, tmp_path: Path):
        from bigr.analytics import TrendSeries, get_asset_count_trend

        _populate_test_db(tmp_path / "test.db", days=3)
        result = get_asset_count_trend(days=30, db_path=tmp_path / "test.db")
        assert isinstance(result, TrendSeries)

    def test_correct_counts(self, tmp_path: Path):
        from bigr.analytics import get_asset_count_trend

        db = tmp_path / "test.db"
        _populate_test_db(db, days=7)
        result = get_asset_count_trend(days=30, db_path=db)
        # We have 7 days of data with increasing asset counts (5,6,7,8,9,10,11)
        assert len(result.points) == 7
        # First day has 5 assets, last day has 11
        assert result.points[0].value == 5
        assert result.points[-1].value == 11

    def test_empty_db(self, tmp_path: Path):
        from bigr.analytics import get_asset_count_trend

        db = tmp_path / "test.db"
        init_db(db)
        result = get_asset_count_trend(days=30, db_path=db)
        assert result.points == []

    def test_days_filter(self, tmp_path: Path):
        from bigr.analytics import get_asset_count_trend

        db = tmp_path / "test.db"
        _populate_test_db(db, days=10)
        result = get_asset_count_trend(days=3, db_path=db)
        # Only last 3 days should be included
        assert len(result.points) <= 3

    def test_ascending_dates(self, tmp_path: Path):
        from bigr.analytics import get_asset_count_trend

        db = tmp_path / "test.db"
        _populate_test_db(db, days=5)
        result = get_asset_count_trend(days=30, db_path=db)
        dates = [p.date for p in result.points]
        assert dates == sorted(dates)


# ===========================================================================
# get_category_trends
# ===========================================================================


class TestGetCategoryTrends:
    def test_returns_list_of_series(self, tmp_path: Path):
        from bigr.analytics import TrendSeries, get_category_trends

        db = tmp_path / "test.db"
        _populate_test_db(db, days=3)
        result = get_category_trends(days=30, db_path=db)
        assert isinstance(result, list)
        assert all(isinstance(s, TrendSeries) for s in result)

    def test_one_series_per_category(self, tmp_path: Path):
        from bigr.analytics import get_category_trends

        db = tmp_path / "test.db"
        _populate_test_db(db, days=7)
        result = get_category_trends(days=30, db_path=db)
        names = {s.name for s in result}
        # The populate helper uses 4 categories
        assert len(names) >= 4
        assert "ag_ve_sistemler" in names
        assert "iot" in names
        assert "tasinabilir" in names
        assert "uygulamalar" in names

    def test_empty_db(self, tmp_path: Path):
        from bigr.analytics import get_category_trends

        db = tmp_path / "test.db"
        init_db(db)
        result = get_category_trends(days=30, db_path=db)
        assert result == []

    def test_correct_category_counts(self, tmp_path: Path):
        from bigr.analytics import get_category_trends

        db = tmp_path / "test.db"
        _populate_test_db(db, days=3)
        result = get_category_trends(days=30, db_path=db)
        # On day 0 we have 5 assets: indices 0-4 mapped to categories round-robin
        # categories[0]=ag_ve_sistemler, [1]=iot, [2]=tasinabilir, [3]=uygulamalar
        # So day 0 (5 assets): ag=2, iot=1, tasinabilir=1, uygulamalar=1
        # Total counts across all days for each category should be > 0
        for series in result:
            total = sum(p.value for p in series.points)
            assert total > 0


# ===========================================================================
# get_new_vs_removed_trend
# ===========================================================================


class TestGetNewVsRemovedTrend:
    def test_returns_trend_series(self, tmp_path: Path):
        from bigr.analytics import TrendSeries, get_new_vs_removed_trend

        db = tmp_path / "test.db"
        _populate_test_db(db, days=5)
        result = get_new_vs_removed_trend(days=30, db_path=db)
        assert isinstance(result, TrendSeries)

    def test_counts_new_assets(self, tmp_path: Path):
        from bigr.analytics import get_new_vs_removed_trend

        db = tmp_path / "test.db"
        _populate_test_db(db, days=5)
        result = get_new_vs_removed_trend(days=30, db_path=db)
        # We add changes for day_offset > 0, so 4 days with changes
        assert len(result.points) > 0
        # At least some points should have positive new count
        new_total = sum(p.value for p in result.points)
        assert new_total > 0

    def test_empty_db(self, tmp_path: Path):
        from bigr.analytics import get_new_vs_removed_trend

        db = tmp_path / "test.db"
        init_db(db)
        result = get_new_vs_removed_trend(days=30, db_path=db)
        assert result.points == []


# ===========================================================================
# get_most_changed_assets
# ===========================================================================


class TestGetMostChangedAssets:
    def test_returns_list(self, tmp_path: Path):
        from bigr.analytics import get_most_changed_assets

        db = tmp_path / "test.db"
        _populate_test_db(db, days=5)
        result = get_most_changed_assets(db_path=db)
        assert isinstance(result, list)

    def test_sorted_by_count(self, tmp_path: Path):
        from bigr.analytics import get_most_changed_assets

        db = tmp_path / "test.db"
        _populate_test_db(db, days=7)
        result = get_most_changed_assets(db_path=db)
        if len(result) >= 2:
            assert result[0]["change_count"] >= result[1]["change_count"]

    def test_limit_param(self, tmp_path: Path):
        from bigr.analytics import get_most_changed_assets

        db = tmp_path / "test.db"
        _populate_test_db(db, days=7)
        result = get_most_changed_assets(limit=2, db_path=db)
        assert len(result) <= 2

    def test_empty_db(self, tmp_path: Path):
        from bigr.analytics import get_most_changed_assets

        db = tmp_path / "test.db"
        init_db(db)
        result = get_most_changed_assets(db_path=db)
        assert result == []

    def test_has_required_fields(self, tmp_path: Path):
        from bigr.analytics import get_most_changed_assets

        db = tmp_path / "test.db"
        _populate_test_db(db, days=5)
        result = get_most_changed_assets(db_path=db)
        if result:
            entry = result[0]
            assert "ip" in entry
            assert "change_count" in entry


# ===========================================================================
# get_scan_frequency
# ===========================================================================


class TestGetScanFrequency:
    def test_returns_list(self, tmp_path: Path):
        from bigr.analytics import get_scan_frequency

        db = tmp_path / "test.db"
        _populate_test_db(db, days=5)
        result = get_scan_frequency(days=30, db_path=db)
        assert isinstance(result, list)

    def test_counts_per_day(self, tmp_path: Path):
        from bigr.analytics import get_scan_frequency

        db = tmp_path / "test.db"
        _populate_test_db(db, days=5)
        result = get_scan_frequency(days=30, db_path=db)
        # We have 1 scan per day for 5 days
        assert len(result) == 5
        for entry in result:
            assert entry["scan_count"] == 1

    def test_empty_db(self, tmp_path: Path):
        from bigr.analytics import get_scan_frequency

        db = tmp_path / "test.db"
        init_db(db)
        result = get_scan_frequency(days=30, db_path=db)
        assert result == []


# ===========================================================================
# get_full_analytics
# ===========================================================================


class TestGetFullAnalytics:
    def test_returns_analytics_result(self, tmp_path: Path):
        from bigr.analytics import AnalyticsResult, get_full_analytics

        db = tmp_path / "test.db"
        _populate_test_db(db, days=5)
        result = get_full_analytics(days=30, db_path=db)
        assert isinstance(result, AnalyticsResult)

    def test_all_fields_populated(self, tmp_path: Path):
        from bigr.analytics import get_full_analytics

        db = tmp_path / "test.db"
        _populate_test_db(db, days=5)
        result = get_full_analytics(days=30, db_path=db)
        assert result.asset_count_trend is not None
        assert len(result.category_trends) > 0
        assert result.new_vs_removed is not None
        assert len(result.most_changed_assets) > 0
        assert len(result.scan_frequency) > 0

    def test_empty_db(self, tmp_path: Path):
        from bigr.analytics import get_full_analytics

        db = tmp_path / "test.db"
        init_db(db)
        result = get_full_analytics(days=30, db_path=db)
        # Should not crash on empty DB
        assert result.asset_count_trend is not None
        assert result.asset_count_trend.points == []


# ===========================================================================
# CLI command
# ===========================================================================


class TestAnalyticsCli:
    def test_analytics_command(self, tmp_path: Path):
        from bigr.cli import app

        runner = CliRunner()
        db = tmp_path / "test.db"
        _populate_test_db(db, days=3)
        result = runner.invoke(app, ["analytics", "--days", "30", "--db-path", str(db)])
        assert result.exit_code == 0

    def test_analytics_json_format(self, tmp_path: Path):
        from bigr.cli import app

        runner = CliRunner()
        db = tmp_path / "test.db"
        _populate_test_db(db, days=3)
        result = runner.invoke(
            app, ["analytics", "--format", "json", "--days", "30", "--db-path", str(db)]
        )
        assert result.exit_code == 0
        # Output should contain valid JSON
        # Find JSON in output (may have leading whitespace or Rich formatting)
        output = result.output.strip()
        parsed = json.loads(output)
        assert "asset_count_trend" in parsed


# ===========================================================================
# API endpoints
# ===========================================================================


class TestAnalyticsApi:
    @pytest.fixture
    def api_app(self, tmp_path: Path):
        from bigr.dashboard.app import create_app

        db = tmp_path / "test.db"
        _populate_test_db(db, days=5)
        data_path = tmp_path / "assets.json"
        data_path.write_text(json.dumps({"assets": [], "category_summary": {}, "total_assets": 0}))
        return create_app(data_path=str(data_path), db_path=db)

    @pytest.mark.asyncio
    async def test_api_analytics_endpoint(self, api_app):
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=api_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/analytics")
            assert resp.status_code == 200
            data = resp.json()
            assert "asset_count_trend" in data

    @pytest.mark.asyncio
    async def test_analytics_page_returns_html(self, api_app):
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=api_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/analytics")
            assert resp.status_code == 200
            assert "text/html" in resp.headers.get("content-type", "")
            assert "Analytics" in resp.text or "analytics" in resp.text

    @pytest.mark.asyncio
    async def test_api_analytics_days_param(self, api_app):
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=api_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/analytics?days=7")
            assert resp.status_code == 200
            data = resp.json()
            assert "asset_count_trend" in data
