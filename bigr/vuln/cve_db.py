"""Local CVE database backed by SQLite."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from bigr.vuln.models import CveEntry


def get_cve_db_path() -> Path:
    """Return default CVE database path (~/.bigr/cve_cache.db)."""
    db_dir = Path.home() / ".bigr"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "cve_cache.db"


def _resolve_path(db_path: Path | None) -> Path:
    """Resolve database path, defaulting to ~/.bigr/cve_cache.db."""
    return db_path if db_path is not None else get_cve_db_path()


def _connect(db_path: Path) -> sqlite3.Connection:
    """Open a connection and return it."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_cve_db(db_path: Path | None = None) -> None:
    """Create CVE tables if they don't exist.

    Tables:
    - cves (cve_id PK, cvss_score, severity, description, affected_vendor,
            affected_product, cpe, published, fix_available, cisa_kev)
    - cve_sync_log (id, synced_at, source, entries_added)
    """
    resolved = _resolve_path(db_path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    conn = _connect(resolved)
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                cvss_score REAL NOT NULL DEFAULT 0.0,
                severity TEXT NOT NULL DEFAULT 'none',
                description TEXT NOT NULL DEFAULT '',
                affected_vendor TEXT NOT NULL DEFAULT '',
                affected_product TEXT NOT NULL DEFAULT '',
                cpe TEXT,
                published TEXT,
                fix_available INTEGER NOT NULL DEFAULT 0,
                cisa_kev INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS cve_sync_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                synced_at TEXT NOT NULL DEFAULT (datetime('now')),
                source TEXT NOT NULL DEFAULT '',
                entries_added INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_cves_vendor
                ON cves (affected_vendor COLLATE NOCASE);

            CREATE INDEX IF NOT EXISTS idx_cves_product
                ON cves (affected_vendor COLLATE NOCASE, affected_product COLLATE NOCASE);

            CREATE INDEX IF NOT EXISTS idx_cves_severity
                ON cves (severity);
        """)
        conn.commit()
    finally:
        conn.close()


def _row_to_entry(row: sqlite3.Row) -> CveEntry:
    """Convert a database row to CveEntry."""
    return CveEntry(
        cve_id=row["cve_id"],
        cvss_score=row["cvss_score"],
        severity=row["severity"],
        description=row["description"],
        affected_vendor=row["affected_vendor"],
        affected_product=row["affected_product"],
        cpe=row["cpe"],
        published=row["published"],
        fix_available=bool(row["fix_available"]),
        cisa_kev=bool(row["cisa_kev"]),
    )


def upsert_cve(entry: CveEntry, db_path: Path | None = None) -> None:
    """Insert or update a CVE entry."""
    resolved = _resolve_path(db_path)
    conn = _connect(resolved)
    try:
        conn.execute(
            """
            INSERT INTO cves (
                cve_id, cvss_score, severity, description,
                affected_vendor, affected_product, cpe, published,
                fix_available, cisa_kev
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                cvss_score = excluded.cvss_score,
                severity = excluded.severity,
                description = excluded.description,
                affected_vendor = excluded.affected_vendor,
                affected_product = excluded.affected_product,
                cpe = excluded.cpe,
                published = excluded.published,
                fix_available = excluded.fix_available,
                cisa_kev = excluded.cisa_kev
            """,
            (
                entry.cve_id,
                entry.cvss_score,
                entry.severity,
                entry.description,
                entry.affected_vendor,
                entry.affected_product,
                entry.cpe,
                entry.published,
                int(entry.fix_available),
                int(entry.cisa_kev),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def bulk_upsert_cves(entries: list[CveEntry], db_path: Path | None = None) -> int:
    """Bulk insert CVEs. Returns count inserted."""
    resolved = _resolve_path(db_path)
    conn = _connect(resolved)
    try:
        for entry in entries:
            conn.execute(
                """
                INSERT INTO cves (
                    cve_id, cvss_score, severity, description,
                    affected_vendor, affected_product, cpe, published,
                    fix_available, cisa_kev
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    cvss_score = excluded.cvss_score,
                    severity = excluded.severity,
                    description = excluded.description,
                    affected_vendor = excluded.affected_vendor,
                    affected_product = excluded.affected_product,
                    cpe = excluded.cpe,
                    published = excluded.published,
                    fix_available = excluded.fix_available,
                    cisa_kev = excluded.cisa_kev
                """,
                (
                    entry.cve_id,
                    entry.cvss_score,
                    entry.severity,
                    entry.description,
                    entry.affected_vendor,
                    entry.affected_product,
                    entry.cpe,
                    entry.published,
                    int(entry.fix_available),
                    int(entry.cisa_kev),
                ),
            )
        conn.commit()
        return len(entries)
    finally:
        conn.close()


def search_cves_by_vendor(vendor: str, db_path: Path | None = None) -> list[CveEntry]:
    """Search CVEs by vendor name (case-insensitive LIKE match)."""
    resolved = _resolve_path(db_path)
    conn = _connect(resolved)
    try:
        cursor = conn.execute(
            "SELECT * FROM cves WHERE affected_vendor LIKE ? COLLATE NOCASE",
            (vendor,),
        )
        return [_row_to_entry(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def search_cves_by_product(
    vendor: str, product: str, db_path: Path | None = None
) -> list[CveEntry]:
    """Search CVEs by vendor + product name."""
    resolved = _resolve_path(db_path)
    conn = _connect(resolved)
    try:
        cursor = conn.execute(
            """SELECT * FROM cves
               WHERE affected_vendor LIKE ? COLLATE NOCASE
                 AND affected_product LIKE ? COLLATE NOCASE""",
            (vendor, product),
        )
        return [_row_to_entry(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def search_cves_by_cpe(
    cpe_pattern: str, db_path: Path | None = None
) -> list[CveEntry]:
    """Search CVEs by CPE pattern (LIKE match)."""
    resolved = _resolve_path(db_path)
    conn = _connect(resolved)
    try:
        cursor = conn.execute(
            "SELECT * FROM cves WHERE cpe LIKE ?",
            (cpe_pattern,),
        )
        return [_row_to_entry(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_cve_stats(db_path: Path | None = None) -> dict:
    """Return stats: total CVEs, by severity, last sync date."""
    resolved = _resolve_path(db_path)
    conn = _connect(resolved)
    try:
        # Total count
        total = conn.execute("SELECT COUNT(*) as cnt FROM cves").fetchone()["cnt"]

        # By severity
        severity_rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM cves GROUP BY severity"
        ).fetchall()
        by_severity = {row["severity"]: row["cnt"] for row in severity_rows}

        # Last sync
        last_sync_row = conn.execute(
            "SELECT synced_at FROM cve_sync_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        last_sync = last_sync_row["synced_at"] if last_sync_row else None

        return {
            "total": total,
            "by_severity": by_severity,
            "last_sync": last_sync,
        }
    finally:
        conn.close()


def get_cve_by_id(cve_id: str, db_path: Path | None = None) -> CveEntry | None:
    """Retrieve a specific CVE by ID."""
    resolved = _resolve_path(db_path)
    conn = _connect(resolved)
    try:
        row = conn.execute(
            "SELECT * FROM cves WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if row is None:
            return None
        return _row_to_entry(row)
    finally:
        conn.close()
