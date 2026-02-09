"""Switch registration and MAC table management."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from bigr.db import _connect, init_db
from bigr.scanner.snmp import SnmpMacTableReader, SwitchConfig, SwitchMacEntry


def save_switch(config: SwitchConfig, db_path: Path | None = None) -> None:
    """Save/update a switch configuration to the database."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        conn.execute(
            """INSERT INTO switches (host, community, version, label)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(host) DO UPDATE SET
                   community = excluded.community,
                   version = excluded.version,
                   label = excluded.label""",
            (config.host, config.community, config.version, config.label),
        )
        conn.commit()
    finally:
        conn.close()


def remove_switch(host: str, db_path: Path | None = None) -> None:
    """Remove a switch from the database."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        conn.execute("DELETE FROM switches WHERE host = ?", (host,))
        conn.commit()
    finally:
        conn.close()


def get_switches(db_path: Path | None = None) -> list[dict]:
    """Return all registered switches."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        rows = conn.execute("SELECT * FROM switches ORDER BY host").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def scan_all_switches(db_path: Path | None = None) -> list[SwitchMacEntry]:
    """Read MAC tables from all registered switches."""
    switches = get_switches(db_path)
    all_entries: list[SwitchMacEntry] = []

    for sw in switches:
        config = SwitchConfig(
            host=sw["host"],
            community=sw["community"],
            version=sw["version"],
            label=sw["label"],
        )
        reader = SnmpMacTableReader(config)
        try:
            entries = reader.read_mac_table()
            all_entries.extend(entries)

            # Update switch stats
            init_db(db_path)
            conn = _connect(db_path)
            try:
                now_iso = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "UPDATE switches SET last_polled = ?, mac_count = ? WHERE host = ?",
                    (now_iso, len(entries), config.host),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass  # Skip unreachable switches

    return all_entries
