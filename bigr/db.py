"""SQLite persistence layer for BİGR Discovery."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from bigr.models import Asset, BigrCategory, ScanMethod, ScanResult

_DEFAULT_DIR = Path.home() / ".bigr"


def get_db_path() -> Path:
    """Return default database path (~/.bigr/bigr.db), creating dir if needed."""
    _DEFAULT_DIR.mkdir(parents=True, exist_ok=True)
    return _DEFAULT_DIR / "bigr.db"


def _connect(db_path: Path | None = None) -> sqlite3.Connection:
    """Open a connection with row factory enabled."""
    path = db_path or get_db_path()
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: Path | None = None) -> None:
    """Create tables if they do not exist."""
    conn = _connect(db_path)
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id          TEXT PRIMARY KEY,
                target      TEXT NOT NULL,
                scan_method TEXT NOT NULL,
                started_at  TEXT NOT NULL,
                completed_at TEXT,
                total_assets INTEGER NOT NULL DEFAULT 0,
                is_root     INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS assets (
                id              TEXT PRIMARY KEY,
                ip              TEXT NOT NULL,
                mac             TEXT,
                hostname        TEXT,
                vendor          TEXT,
                os_hint         TEXT,
                bigr_category   TEXT NOT NULL DEFAULT 'unclassified',
                confidence_score REAL NOT NULL DEFAULT 0.0,
                scan_method     TEXT NOT NULL DEFAULT 'passive',
                first_seen      TEXT NOT NULL,
                last_seen       TEXT NOT NULL,
                manual_category TEXT,
                manual_note     TEXT,
                is_ignored      INTEGER NOT NULL DEFAULT 0,
                UNIQUE(ip, mac)
            );

            CREATE TABLE IF NOT EXISTS scan_assets (
                scan_id          TEXT NOT NULL,
                asset_id         TEXT NOT NULL,
                open_ports       TEXT,
                confidence_score REAL NOT NULL DEFAULT 0.0,
                bigr_category    TEXT NOT NULL DEFAULT 'unclassified',
                raw_evidence     TEXT,
                PRIMARY KEY (scan_id, asset_id),
                FOREIGN KEY (scan_id) REFERENCES scans(id),
                FOREIGN KEY (asset_id) REFERENCES assets(id)
            );

            CREATE TABLE IF NOT EXISTS asset_changes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id    TEXT NOT NULL,
                scan_id     TEXT NOT NULL,
                change_type TEXT NOT NULL,
                field_name  TEXT,
                old_value   TEXT,
                new_value   TEXT,
                detected_at TEXT NOT NULL,
                FOREIGN KEY (asset_id) REFERENCES assets(id),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS subnets (
                cidr          TEXT PRIMARY KEY,
                label         TEXT DEFAULT '',
                vlan_id       INTEGER,
                last_scanned  TEXT,
                asset_count   INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS switches (
                host        TEXT PRIMARY KEY,
                community   TEXT DEFAULT 'public',
                version     TEXT DEFAULT '2c',
                label       TEXT DEFAULT '',
                last_polled TEXT,
                mac_count   INTEGER DEFAULT 0
            );
        """)
        # Add switch columns to assets if they don't exist yet (migration-safe)
        _add_column_if_missing(conn, "assets", "switch_host", "TEXT")
        _add_column_if_missing(conn, "assets", "switch_port", "TEXT")
        _add_column_if_missing(conn, "assets", "switch_port_index", "INTEGER")

        conn.commit()
    finally:
        conn.close()


def _add_column_if_missing(
    conn: sqlite3.Connection, table: str, column: str, col_type: str
) -> None:
    """Add a column to a table if it doesn't already exist."""
    cursor = conn.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cursor.fetchall()}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")


def save_scan(scan_result: ScanResult, db_path: Path | None = None) -> str:
    """Save an entire scan result, upserting assets and detecting changes.

    Returns the generated scan_id.
    """
    init_db(db_path)
    conn = _connect(db_path)
    scan_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        # Insert scan record
        conn.execute(
            """INSERT INTO scans (id, target, scan_method, started_at, completed_at, total_assets, is_root)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                scan_result.target,
                scan_result.scan_method.value,
                scan_result.started_at.isoformat(),
                scan_result.completed_at.isoformat() if scan_result.completed_at else None,
                len(scan_result.assets),
                int(scan_result.is_root),
            ),
        )

        for asset in scan_result.assets:
            asset_id = _upsert_asset(conn, asset, scan_id, now_iso)

            # Insert scan_assets junction
            conn.execute(
                """INSERT INTO scan_assets (scan_id, asset_id, open_ports, confidence_score, bigr_category, raw_evidence)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    asset_id,
                    json.dumps(asset.open_ports),
                    asset.confidence_score,
                    asset.bigr_category.value,
                    json.dumps(asset.raw_evidence),
                ),
            )

        conn.commit()
        return scan_id
    finally:
        conn.close()


def _upsert_asset(
    conn: sqlite3.Connection,
    asset: Asset,
    scan_id: str,
    now_iso: str,
) -> str:
    """Insert or update an asset row. Detects and logs changes. Returns asset_id."""
    mac_val = asset.mac  # may be None
    # Look up existing asset by (ip, mac) — handle NULL mac with IS
    if mac_val is None:
        row = conn.execute(
            "SELECT * FROM assets WHERE ip = ? AND mac IS NULL", (asset.ip,)
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM assets WHERE ip = ? AND mac = ?", (asset.ip, mac_val)
        ).fetchone()

    if row is None:
        # New asset
        asset_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO assets
               (id, ip, mac, hostname, vendor, os_hint, bigr_category,
                confidence_score, scan_method, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                asset_id,
                asset.ip,
                mac_val,
                asset.hostname,
                asset.vendor,
                asset.os_hint,
                asset.bigr_category.value,
                asset.confidence_score,
                asset.scan_method.value,
                asset.first_seen.isoformat(),
                asset.last_seen.isoformat(),
            ),
        )
        # Log as new-asset change
        conn.execute(
            """INSERT INTO asset_changes
               (asset_id, scan_id, change_type, detected_at)
               VALUES (?, ?, 'new_asset', ?)""",
            (asset_id, scan_id, now_iso),
        )
        return asset_id

    # Existing asset — detect field changes and update
    asset_id = row["id"]
    tracked_fields = {
        "hostname": asset.hostname,
        "vendor": asset.vendor,
        "os_hint": asset.os_hint,
        "bigr_category": asset.bigr_category.value,
        "confidence_score": str(asset.confidence_score),
        "scan_method": asset.scan_method.value,
    }

    for field_name, new_value in tracked_fields.items():
        old_value = row[field_name]
        # Normalize for comparison
        old_str = str(old_value) if old_value is not None else None
        new_str = str(new_value) if new_value is not None else None
        if old_str != new_str:
            conn.execute(
                """INSERT INTO asset_changes
                   (asset_id, scan_id, change_type, field_name, old_value, new_value, detected_at)
                   VALUES (?, ?, 'field_changed', ?, ?, ?, ?)""",
                (asset_id, scan_id, field_name, old_str, new_str, now_iso),
            )

    # Update the living record (always update last_seen; update fields)
    conn.execute(
        """UPDATE assets SET
               hostname = ?,
               vendor = ?,
               os_hint = ?,
               bigr_category = ?,
               confidence_score = ?,
               scan_method = ?,
               last_seen = ?
           WHERE id = ?""",
        (
            asset.hostname,
            asset.vendor,
            asset.os_hint,
            asset.bigr_category.value,
            asset.confidence_score,
            asset.scan_method.value,
            asset.last_seen.isoformat(),
            asset_id,
        ),
    )
    return asset_id


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def get_latest_scan(target: str | None = None, db_path: Path | None = None) -> dict | None:
    """Return the most recent scan, optionally filtered by target.

    Includes nested assets list from scan_assets + assets join.
    """
    init_db(db_path)
    conn = _connect(db_path)
    try:
        if target:
            scan_row = conn.execute(
                "SELECT * FROM scans WHERE target = ? ORDER BY started_at DESC LIMIT 1",
                (target,),
            ).fetchone()
        else:
            scan_row = conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT 1"
            ).fetchone()

        if scan_row is None:
            return None

        return _scan_row_to_dict(conn, scan_row)
    finally:
        conn.close()


def get_asset_history(
    ip: str | None = None, mac: str | None = None, db_path: Path | None = None
) -> list[dict]:
    """Return an asset's scan-by-scan history."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        # Find matching asset(s)
        conditions: list[str] = []
        params: list[str] = []
        if ip:
            conditions.append("a.ip = ?")
            params.append(ip)
        if mac:
            conditions.append("a.mac = ?")
            params.append(mac)
        if not conditions:
            return []

        where = " AND ".join(conditions)
        rows = conn.execute(
            f"""SELECT sa.*, s.target, s.started_at AS scan_started, s.scan_method AS scan_scan_method,
                       a.ip, a.mac, a.hostname, a.vendor
                FROM scan_assets sa
                JOIN scans s ON s.id = sa.scan_id
                JOIN assets a ON a.id = sa.asset_id
                WHERE {where}
                ORDER BY s.started_at DESC""",
            params,
        ).fetchall()

        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_all_assets(db_path: Path | None = None) -> list[dict]:
    """Return all known assets from the living inventory."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        rows = conn.execute("SELECT * FROM assets ORDER BY last_seen DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_scan_list(limit: int = 20, db_path: Path | None = None) -> list[dict]:
    """Return recent scans (metadata only, no nested assets)."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def tag_asset(
    ip: str,
    category: str,
    note: str | None = None,
    db_path: Path | None = None,
) -> None:
    """Apply a manual category override to an asset identified by IP."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        conn.execute(
            "UPDATE assets SET manual_category = ?, manual_note = ? WHERE ip = ?",
            (category, note, ip),
        )
        conn.commit()
    finally:
        conn.close()


def untag_asset(ip: str, db_path: Path | None = None) -> None:
    """Remove manual category override from an asset."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        conn.execute(
            "UPDATE assets SET manual_category = NULL, manual_note = NULL WHERE ip = ?",
            (ip,),
        )
        conn.commit()
    finally:
        conn.close()


def get_tags(db_path: Path | None = None) -> list[dict]:
    """Return all assets that have manual overrides."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT ip, mac, hostname, manual_category, manual_note FROM assets WHERE manual_category IS NOT NULL"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Subnet management
# ---------------------------------------------------------------------------


def add_subnet(
    cidr: str, label: str = "", vlan_id: int | None = None, db_path: Path | None = None
) -> None:
    """Register a subnet. If CIDR already exists, update label/vlan."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        conn.execute(
            """INSERT INTO subnets (cidr, label, vlan_id)
               VALUES (?, ?, ?)
               ON CONFLICT(cidr) DO UPDATE SET label = excluded.label, vlan_id = excluded.vlan_id""",
            (cidr, label, vlan_id),
        )
        conn.commit()
    finally:
        conn.close()


def remove_subnet(cidr: str, db_path: Path | None = None) -> None:
    """Remove a registered subnet. No-op if it doesn't exist."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        conn.execute("DELETE FROM subnets WHERE cidr = ?", (cidr,))
        conn.commit()
    finally:
        conn.close()


def get_subnets(db_path: Path | None = None) -> list[dict]:
    """Return all registered subnets."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        rows = conn.execute("SELECT * FROM subnets ORDER BY cidr").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def update_subnet_stats(
    cidr: str, asset_count: int, db_path: Path | None = None
) -> None:
    """Update a subnet's scan statistics (last_scanned timestamp and asset_count)."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE subnets SET last_scanned = ?, asset_count = ? WHERE cidr = ?",
            (now_iso, asset_count, cidr),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _scan_row_to_dict(conn: sqlite3.Connection, scan_row: sqlite3.Row) -> dict:
    """Convert a scan row + its joined assets into a rich dict."""
    scan = dict(scan_row)
    scan["is_root"] = bool(scan["is_root"])

    # Compute duration
    if scan.get("completed_at") and scan.get("started_at"):
        started = datetime.fromisoformat(scan["started_at"])
        completed = datetime.fromisoformat(scan["completed_at"])
        scan["duration_seconds"] = (completed - started).total_seconds()
    else:
        scan["duration_seconds"] = None

    # Fetch assets for this scan
    asset_rows = conn.execute(
        """SELECT a.*, sa.open_ports AS sa_open_ports, sa.confidence_score AS sa_confidence,
                  sa.bigr_category AS sa_bigr_category, sa.raw_evidence AS sa_raw_evidence
           FROM scan_assets sa
           JOIN assets a ON a.id = sa.asset_id
           WHERE sa.scan_id = ?""",
        (scan["id"],),
    ).fetchall()

    assets = []
    category_summary: dict[str, int] = {}
    for ar in asset_rows:
        ard = dict(ar)
        # Use scan-time values from junction table
        bigr_cat = ard.get("sa_bigr_category", ard["bigr_category"])
        category_summary[bigr_cat] = category_summary.get(bigr_cat, 0) + 1

        # Build the BigrCategory label
        try:
            cat_enum = BigrCategory(bigr_cat)
            bigr_cat_tr = cat_enum.label_tr
        except ValueError:
            bigr_cat_tr = bigr_cat

        open_ports = json.loads(ard.get("sa_open_ports") or "[]")
        raw_evidence = json.loads(ard.get("sa_raw_evidence") or "{}")

        assets.append({
            "ip": ard["ip"],
            "mac": ard["mac"],
            "hostname": ard["hostname"],
            "vendor": ard["vendor"],
            "open_ports": open_ports,
            "os_hint": ard["os_hint"],
            "bigr_category": bigr_cat,
            "bigr_category_tr": bigr_cat_tr,
            "confidence_score": ard.get("sa_confidence", ard["confidence_score"]),
            "confidence_level": ConfidenceLevel_from_score(ard.get("sa_confidence", ard["confidence_score"])),
            "scan_method": ard["scan_method"],
            "first_seen": ard["first_seen"],
            "last_seen": ard["last_seen"],
            "raw_evidence": raw_evidence,
        })

    scan["assets"] = assets
    scan["category_summary"] = category_summary
    return scan


def ConfidenceLevel_from_score(score: float) -> str:
    """Map a confidence score to a level string."""
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    if score >= 0.3:
        return "low"
    return "unclassified"
