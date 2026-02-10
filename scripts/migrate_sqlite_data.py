#!/usr/bin/env python3
"""One-time migration: read legacy ~/.bigr/bigr.db → write to target DATABASE_URL.

Usage:
    # Migrate to Neon PostgreSQL
    DATABASE_URL=postgresql://user:pass@host/db python scripts/migrate_sqlite_data.py

    # Migrate to a different SQLite file
    DATABASE_URL=sqlite:///path/to/new.db python scripts/migrate_sqlite_data.py

    # Dry run (just count records, don't write)
    DATABASE_URL=... python scripts/migrate_sqlite_data.py --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _read_source(source_path: Path) -> dict[str, list[dict]]:
    """Read all rows from the legacy SQLite database."""
    if not source_path.exists():
        print(f"Source database not found: {source_path}")
        sys.exit(1)

    conn = sqlite3.connect(str(source_path))
    conn.row_factory = sqlite3.Row

    tables = {}
    # Read in dependency order (parent tables first)
    for table in ["scans", "assets", "scan_assets", "asset_changes",
                   "subnets", "switches", "certificates"]:
        try:
            cursor = conn.execute(f"SELECT * FROM {table}")  # noqa: S608
            rows = [dict(row) for row in cursor.fetchall()]
            tables[table] = rows
            print(f"  {table}: {len(rows)} rows")
        except sqlite3.OperationalError:
            tables[table] = []
            print(f"  {table}: table not found (skipped)")

    conn.close()
    return tables


async def _write_target(tables: dict[str, list[dict]]) -> None:
    """Write rows to the target database using SQLAlchemy async."""
    from sqlalchemy import text

    from bigr.core.database import Base, get_engine, get_session_factory

    engine = get_engine()

    # Create tables if they don't exist (Alembic should handle this,
    # but as a safety net for direct SQLite targets)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = get_session_factory()

    async with factory() as session:
        async with session.begin():
            # Insert in dependency order
            for table_name in ["scans", "assets", "scan_assets", "asset_changes",
                               "subnets", "switches", "certificates"]:
                rows = tables.get(table_name, [])
                if not rows:
                    continue

                # Build column list from first row
                columns = list(rows[0].keys())
                placeholders = ", ".join(f":{col}" for col in columns)
                col_names = ", ".join(columns)

                stmt = text(
                    f"INSERT INTO {table_name} ({col_names}) "  # noqa: S608
                    f"VALUES ({placeholders}) "
                    f"ON CONFLICT DO NOTHING"
                )

                for row in rows:
                    # Convert any JSON-encoded fields that might be Python objects
                    cleaned = {}
                    for k, v in row.items():
                        if isinstance(v, (list, dict)):
                            cleaned[k] = json.dumps(v)
                        else:
                            cleaned[k] = v
                    await session.execute(stmt, cleaned)

                print(f"  {table_name}: {len(rows)} rows migrated")

    await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate BİGR data from SQLite to target DB")
    parser.add_argument(
        "--source",
        type=Path,
        default=Path.home() / ".bigr" / "bigr.db",
        help="Source SQLite database (default: ~/.bigr/bigr.db)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only count records, don't write to target",
    )
    args = parser.parse_args()

    print(f"Source: {args.source}")
    print("Reading source database...")
    tables = _read_source(args.source)

    total = sum(len(rows) for rows in tables.values())
    print(f"\nTotal records: {total}")

    if args.dry_run:
        print("\n[DRY RUN] No data written.")
        return

    import os

    target_url = os.environ.get("DATABASE_URL", "")
    if not target_url:
        print("\nError: DATABASE_URL environment variable not set.")
        sys.exit(1)

    print(f"\nTarget: {target_url[:50]}...")
    print("Writing to target database...")
    asyncio.run(_write_target(tables))
    print("\nMigration complete.")


if __name__ == "__main__":
    main()
