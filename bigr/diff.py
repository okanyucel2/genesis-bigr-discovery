"""Scan diff engine - compares two scan results to detect changes."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AssetChange:
    """A single detected change on an asset between scans."""

    ip: str
    mac: str | None
    change_type: str  # 'new', 'removed', 'port_change', 'category_change', 'vendor_change', 'hostname_change'
    field: str | None = None
    old_value: str | None = None
    new_value: str | None = None


@dataclass
class DiffResult:
    """Result of comparing two scan asset lists."""

    new_assets: list[dict] = field(default_factory=list)
    removed_assets: list[dict] = field(default_factory=list)
    changed_assets: list[AssetChange] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def has_changes(self) -> bool:
        """True if any additions, removals, or field changes were detected."""
        return bool(self.new_assets or self.removed_assets or self.changed_assets)

    @property
    def summary(self) -> str:
        """Human-readable one-line summary of changes."""
        parts: list[str] = []
        if self.new_assets:
            parts.append(f"+{len(self.new_assets)} new")
        if self.removed_assets:
            parts.append(f"-{len(self.removed_assets)} removed")
        if self.changed_assets:
            parts.append(f"~{len(self.changed_assets)} changed")
        parts.append(f"={self.unchanged_count} unchanged")
        return ", ".join(parts)


def _asset_key(asset: dict) -> tuple[str, str | None]:
    """Build the comparison key for an asset dict: (ip, mac)."""
    return (asset.get("ip", ""), asset.get("mac"))


# Fields to compare and their corresponding change_type labels.
_TRACKED_FIELDS: dict[str, str] = {
    "open_ports": "port_change",
    "bigr_category": "category_change",
    "vendor": "vendor_change",
    "hostname": "hostname_change",
    "confidence_score": "confidence_change",
}


def _normalize_field(field_name: str, value: object) -> str | None:
    """Normalize a field value to a comparable string representation."""
    if value is None:
        return None
    if field_name == "open_ports":
        # Lists may come as list[int] or already-serialized strings
        if isinstance(value, list):
            return json.dumps(sorted(value))
        return str(value)
    if field_name == "confidence_score":
        try:
            return str(round(float(value), 4))
        except (TypeError, ValueError):
            return str(value)
    return str(value)


def diff_scans(
    current_assets: list[dict],
    previous_assets: list[dict],
) -> DiffResult:
    """Compare two asset lists and return a structured diff.

    Parameters
    ----------
    current_assets:
        Assets from the most recent scan.
    previous_assets:
        Assets from the previous scan to compare against.

    Returns
    -------
    DiffResult with new, removed, changed, and unchanged counts.
    """
    prev_map: dict[tuple[str, str | None], dict] = {
        _asset_key(a): a for a in previous_assets
    }
    curr_map: dict[tuple[str, str | None], dict] = {
        _asset_key(a): a for a in current_assets
    }

    prev_keys = set(prev_map.keys())
    curr_keys = set(curr_map.keys())

    result = DiffResult()

    # New assets: in current but not in previous
    for key in sorted(curr_keys - prev_keys):
        result.new_assets.append(curr_map[key])

    # Removed assets: in previous but not in current
    for key in sorted(prev_keys - curr_keys):
        result.removed_assets.append(prev_map[key])

    # Common assets: check for field changes
    for key in sorted(curr_keys & prev_keys):
        curr = curr_map[key]
        prev = prev_map[key]
        ip = curr.get("ip", "")
        mac = curr.get("mac")
        asset_changed = False

        for field_name, change_type in _TRACKED_FIELDS.items():
            old_val = _normalize_field(field_name, prev.get(field_name))
            new_val = _normalize_field(field_name, curr.get(field_name))
            if old_val != new_val:
                result.changed_assets.append(
                    AssetChange(
                        ip=ip,
                        mac=mac,
                        change_type=change_type,
                        field=field_name,
                        old_value=old_val,
                        new_value=new_val,
                    )
                )
                asset_changed = True

        if not asset_changed:
            result.unchanged_count += 1

    return result


def get_changes_from_db(
    limit: int = 50,
    db_path: Path | None = None,
) -> list[dict]:
    """Read recent asset changes from the asset_changes table.

    Parameters
    ----------
    limit:
        Maximum number of change records to return.
    db_path:
        Path to the SQLite database.  Falls back to the default
        ``~/.bigr/bigr.db`` when *None*.

    Returns
    -------
    List of change dicts with keys: id, asset_id, scan_id, change_type,
    field_name, old_value, new_value, detected_at, ip, mac.
    """
    from bigr.db import get_db_path, init_db

    path = db_path or get_db_path()
    init_db(path)

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """SELECT ac.*, a.ip, a.mac
               FROM asset_changes ac
               JOIN assets a ON a.id = ac.asset_id
               ORDER BY ac.detected_at DESC, ac.id DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
