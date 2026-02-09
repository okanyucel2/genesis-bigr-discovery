"""Historical trending and analytics engine for BIGR Discovery."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass
class TrendPoint:
    """A single data point in a time series."""

    date: str  # ISO date "2026-02-09"
    value: float | int
    label: str | None = None


@dataclass
class TrendSeries:
    """A named time series."""

    name: str
    points: list[TrendPoint] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "points": [
                {"date": p.date, "value": p.value, "label": p.label}
                for p in self.points
            ],
        }


@dataclass
class AnalyticsResult:
    """Complete analytics result with multiple series."""

    asset_count_trend: TrendSeries | None = None
    category_trends: list[TrendSeries] = field(default_factory=list)
    new_vs_removed: TrendSeries | None = None
    most_changed_assets: list[dict] = field(default_factory=list)
    scan_frequency: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "asset_count_trend": self.asset_count_trend.to_dict()
            if self.asset_count_trend
            else None,
            "category_trends": [s.to_dict() for s in self.category_trends],
            "new_vs_removed": self.new_vs_removed.to_dict()
            if self.new_vs_removed
            else None,
            "most_changed_assets": self.most_changed_assets,
            "scan_frequency": self.scan_frequency,
        }


# ---------------------------------------------------------------------------
# DB connection helper (re-uses bigr.db pattern)
# ---------------------------------------------------------------------------


def _get_conn(db_path: Path | None = None) -> sqlite3.Connection:
    """Open a connection using the same logic as bigr.db."""
    from bigr.db import _connect, init_db

    init_db(db_path)
    conn = _connect(db_path)
    return conn


# ---------------------------------------------------------------------------
# Analytics query functions
# ---------------------------------------------------------------------------


def get_asset_count_trend(days: int = 30, db_path: Path | None = None) -> TrendSeries:
    """Get asset count over time (unique assets seen per day).

    SQL:
    SELECT DATE(s.started_at) as scan_date, COUNT(DISTINCT sa.asset_id) as asset_count
    FROM scan_assets sa
    JOIN scans s ON sa.scan_id = s.id
    WHERE s.started_at >= date('now', '-N days')
    GROUP BY DATE(s.started_at)
    ORDER BY scan_date
    """
    conn = _get_conn(db_path)
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        rows = conn.execute(
            """SELECT DATE(s.started_at) AS scan_date,
                      COUNT(DISTINCT sa.asset_id) AS asset_count
               FROM scan_assets sa
               JOIN scans s ON sa.scan_id = s.id
               WHERE s.started_at >= ?
               GROUP BY DATE(s.started_at)
               ORDER BY scan_date""",
            (cutoff,),
        ).fetchall()

        points = [
            TrendPoint(date=row["scan_date"], value=row["asset_count"])
            for row in rows
        ]
        return TrendSeries(name="asset_count", points=points)
    finally:
        conn.close()


def get_category_trends(
    days: int = 30, db_path: Path | None = None
) -> list[TrendSeries]:
    """Get category distribution over time.

    Returns one TrendSeries per BIGR category.

    SQL:
    SELECT DATE(s.started_at), sa.bigr_category, COUNT(*)
    FROM scan_assets sa
    JOIN scans s ON sa.scan_id = s.id
    WHERE s.started_at >= date('now', '-N days')
    GROUP BY DATE(s.started_at), sa.bigr_category
    ORDER BY DATE(s.started_at)
    """
    conn = _get_conn(db_path)
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        rows = conn.execute(
            """SELECT DATE(s.started_at) AS scan_date,
                      sa.bigr_category,
                      COUNT(*) AS cnt
               FROM scan_assets sa
               JOIN scans s ON sa.scan_id = s.id
               WHERE s.started_at >= ?
               GROUP BY DATE(s.started_at), sa.bigr_category
               ORDER BY scan_date""",
            (cutoff,),
        ).fetchall()

        if not rows:
            return []

        # Group by category
        categories: dict[str, list[TrendPoint]] = {}
        for row in rows:
            cat = row["bigr_category"]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(
                TrendPoint(date=row["scan_date"], value=row["cnt"])
            )

        return [
            TrendSeries(name=cat, points=pts)
            for cat, pts in sorted(categories.items())
        ]
    finally:
        conn.close()


def get_new_vs_removed_trend(
    days: int = 30, db_path: Path | None = None
) -> TrendSeries:
    """Get new vs removed device counts per day.

    SQL:
    SELECT DATE(detected_at) as change_date,
           SUM(CASE WHEN change_type = 'new_asset' THEN 1 ELSE 0 END) as new_count,
           SUM(CASE WHEN change_type = 'removed' THEN 1 ELSE 0 END) as removed_count
    FROM asset_changes
    WHERE detected_at >= date('now', '-N days')
    GROUP BY DATE(detected_at)
    """
    conn = _get_conn(db_path)
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        rows = conn.execute(
            """SELECT DATE(detected_at) AS change_date,
                      SUM(CASE WHEN change_type = 'new_asset' THEN 1 ELSE 0 END) AS new_count,
                      SUM(CASE WHEN change_type = 'removed' THEN 1 ELSE 0 END) AS removed_count
               FROM asset_changes
               WHERE detected_at >= ?
               GROUP BY DATE(detected_at)
               ORDER BY change_date""",
            (cutoff,),
        ).fetchall()

        points = [
            TrendPoint(
                date=row["change_date"],
                value=row["new_count"],
                label=f"new:{row['new_count']} removed:{row['removed_count']}",
            )
            for row in rows
        ]
        return TrendSeries(name="new_vs_removed", points=points)
    finally:
        conn.close()


def get_most_changed_assets(
    limit: int = 20, db_path: Path | None = None
) -> list[dict]:
    """Get assets with the most changes.

    Returns: [{"ip": str, "mac": str, "hostname": str, "change_count": int, "last_change": str}]

    SQL:
    SELECT a.ip, a.mac, a.hostname, COUNT(*) as change_count, MAX(ac.detected_at) as last_change
    FROM asset_changes ac
    JOIN assets a ON ac.asset_id = a.id
    GROUP BY a.ip
    ORDER BY change_count DESC
    LIMIT N
    """
    conn = _get_conn(db_path)
    try:
        rows = conn.execute(
            """SELECT a.ip, a.mac, a.hostname,
                      COUNT(*) AS change_count,
                      MAX(ac.detected_at) AS last_change
               FROM asset_changes ac
               JOIN assets a ON ac.asset_id = a.id
               GROUP BY a.ip
               ORDER BY change_count DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()

        return [
            {
                "ip": row["ip"],
                "mac": row["mac"],
                "hostname": row["hostname"],
                "change_count": row["change_count"],
                "last_change": row["last_change"],
            }
            for row in rows
        ]
    finally:
        conn.close()


def get_scan_frequency(
    days: int = 30, db_path: Path | None = None
) -> list[dict]:
    """Get scan frequency (scans per day).

    Returns: [{"date": str, "scan_count": int, "total_assets": int}]
    """
    conn = _get_conn(db_path)
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        rows = conn.execute(
            """SELECT DATE(started_at) AS scan_date,
                      COUNT(*) AS scan_count,
                      SUM(total_assets) AS total_assets
               FROM scans
               WHERE started_at >= ?
               GROUP BY DATE(started_at)
               ORDER BY scan_date""",
            (cutoff,),
        ).fetchall()

        return [
            {
                "date": row["scan_date"],
                "scan_count": row["scan_count"],
                "total_assets": row["total_assets"],
            }
            for row in rows
        ]
    finally:
        conn.close()


def get_full_analytics(
    days: int = 30, db_path: Path | None = None
) -> AnalyticsResult:
    """Run all analytics queries and return combined result."""
    return AnalyticsResult(
        asset_count_trend=get_asset_count_trend(days=days, db_path=db_path),
        category_trends=get_category_trends(days=days, db_path=db_path),
        new_vs_removed=get_new_vs_removed_trend(days=days, db_path=db_path),
        most_changed_assets=get_most_changed_assets(db_path=db_path),
        scan_frequency=get_scan_frequency(days=days, db_path=db_path),
    )
