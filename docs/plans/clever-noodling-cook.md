# BİGR Discovery - Neon PostgreSQL Integration

## Context

BİGR Discovery uses raw `sqlite3` in `bigr/db.py` (680 lines, 7 tables, ~30 functions). The dashboard API is FastAPI with async routes calling sync DB functions. Genesis production uses Neon PostgreSQL. This plan migrates to SQLAlchemy 2.0 async with dual-mode support: SQLite (local dev/CLI) and PostgreSQL (Neon production).

**Goal:** Deploy BİGR backend on Render with Neon PostgreSQL, keeping CLI + 1020 tests intact.

## Architecture Decision: Parallel Persistence Layer

Keep `bigr/db.py` untouched for CLI (sync sqlite3). Create `bigr/core/` for async SQLAlchemy layer (dashboard API). This avoids breaking 1020 existing tests and CLI commands while enabling PostgreSQL.

```
CLI (bigr scan) ──→ bigr/db.py (sync sqlite3)     ← UNCHANGED
Dashboard API   ──→ bigr/core/services.py (async)  ← NEW
                    bigr/core/database.py (engine)  ← NEW
                    bigr/core/models_db.py (ORM)    ← NEW
                    alembic/ (migrations)           ← NEW
```

## Reference Patterns

| Source | Pattern |
|--------|---------|
| `restaurant95-ai/.../database.py` | `get_database_url()`, engine creation, `async_sessionmaker`, `get_db()` dependency |
| `backend/core/database.py` | SSL context for Neon, pool config, SQLite FK enforcement via event listener |
| `restaurant95-ai/alembic/env.py` | Async Alembic with `run_async_migrations()` |
| `backend/core/settings.py` | Pydantic Settings with `DATABASE_URL` |

## Waves

### Wave 1: Foundation (Dependencies + Database Layer)

**Agent 1A: Settings + Database Engine**

Create:
- `bigr/core/__init__.py`
- `bigr/core/settings.py` - Pydantic Settings with `DATABASE_URL` (default: `sqlite:///~/.bigr/bigr.db`), `DEBUG`
- `bigr/core/database.py` - `get_database_url()` (postgresql→asyncpg, sqlite→aiosqlite, sslmode handling), lazy `get_engine()`, `get_session_factory()`, `get_db()` FastAPI dependency, `Base(DeclarativeBase)`

Modify:
- `pyproject.toml` - Add: `sqlalchemy[asyncio]>=2.0.0`, `aiosqlite>=0.19.0`, `asyncpg>=0.29.0`, `alembic>=1.13.0`, `pydantic-settings>=2.1.0`

Tests: `tests/test_core_database.py`
- URL conversion (sqlite→aiosqlite, postgresql→asyncpg, sslmode handling)
- Engine creation for SQLite and PostgreSQL
- Session factory yields working sessions
- SQLite FK enforcement via event listener

**Agent 1B: ORM Models (7 tables)**

Create:
- `bigr/core/models_db.py` - SQLAlchemy models matching existing schema exactly:

| Model | Table | PK | Key Fields |
|-------|-------|----|------------|
| `ScanDB` | scans | id (String) | target, scan_method, started_at, total_assets, is_root |
| `AssetDB` | assets | id (String) | ip, mac (UNIQUE ip+mac), bigr_category, confidence_score, switch_host/port/port_index |
| `ScanAssetDB` | scan_assets | (scan_id, asset_id) | open_ports (JSON/Text), raw_evidence (JSON/Text) |
| `AssetChangeDB` | asset_changes | id (autoincrement) | asset_id, scan_id, change_type, field_name, old_value, new_value |
| `SubnetDB` | subnets | cidr | label, vlan_id, last_scanned, asset_count |
| `SwitchDB` | switches | host | community, version, label, last_polled, mac_count |
| `CertificateDB` | certificates | id (autoincrement) | ip+port (UNIQUE), cn, issuer, valid_to, san (JSON/Text) |

Relationships: `ScanDB.scan_assets ↔ ScanAssetDB`, `AssetDB.scan_assets ↔ ScanAssetDB`, `AssetDB.asset_changes ↔ AssetChangeDB`

Tests: `tests/test_core_models.py`
- Model instantiation with all fields
- Relationship loading (scan → scan_assets → asset)
- Unique constraints (ip+mac, ip+port)
- JSON field serialization (open_ports, raw_evidence, san)

**Exit:** `pip install -e ".[dev]"` works, models import without error, all tests pass.

---

### Wave 2: Alembic Migrations

**Agent 2A: Alembic Setup + Initial Migration**

Create:
- `alembic.ini` - Standard config, `script_location = alembic`
- `alembic/env.py` - Async pattern: imports `get_database_url()` and `Base.metadata`, uses `create_async_engine()` with `pool.NullPool`, runs `connection.run_sync(do_run_migrations)`
- `alembic/script.py.mako` - Standard template
- `alembic/versions/` - Empty dir
- `scripts/alembic.sh` - Dev wrapper: `DATABASE_URL=sqlite:///~/.bigr/bigr.db alembic "$@"`

Generate: `alembic revision --autogenerate -m "initial schema"` - Creates all 7 tables

Tests: `tests/test_alembic.py`
- `alembic upgrade head` on fresh SQLite → all 7 tables exist
- `alembic downgrade base` → all tables dropped
- Schema matches `Base.metadata` (no drift)

**Exit:** `./scripts/alembic.sh upgrade head` works, creates all 7 tables in SQLite.

---

### Wave 3: Async Service Layer

**Agent 3A: Read Services**

Create:
- `bigr/core/services.py` - Async functions mirroring `bigr/db.py` query API:

| Function | Mirrors | Key Logic |
|----------|---------|-----------|
| `get_latest_scan(session, target?)` | `db.get_latest_scan()` | `selectinload(Scan.scan_assets.asset)`, dict conversion |
| `get_all_assets(session)` | `db.get_all_assets()` | `select(Asset).order_by(desc(last_seen))` |
| `get_scan_list(session, limit)` | `db.get_scan_list()` | Metadata only, no asset loading |
| `get_asset_history(session, ip?, mac?)` | `db.get_asset_history()` | Join scan_assets + scans + assets |
| `get_tags_async(session)` | `db.get_tags()` | `where(manual_category.isnot(None))` |
| `get_subnets_async(session)` | `db.get_subnets()` | Simple select, order by cidr |
| `get_switches_async(session)` | via switch_map | Simple select |
| `get_certificates_async(session)` | `db.get_certificates()` | JSON parse for san field |
| `get_expiring_certs_async(session, days)` | `db.get_expiring_certificates()` | `where(days_until_expiry <= days)` |

All functions return `list[dict]` or `dict | None` matching existing API response shapes.

Tests: `tests/test_core_services.py`
- Each function with seeded test data
- Empty database returns `[]` or `None`
- Dict output matches existing `bigr/db.py` format

**Agent 3B: Write Services**

Add to `bigr/core/services.py`:

| Function | Mirrors | Key Logic |
|----------|---------|-----------|
| `save_scan_async(session, scan_result)` | `db.save_scan()` | UUID gen, upsert assets, change detection |
| `_upsert_asset_async(session, asset, scan_id, now)` | `db._upsert_asset()` | Query by ip+mac, track 6 field changes, log to asset_changes |
| `tag_asset_async(session, ip, category, note?)` | `db.tag_asset()` | Update manual_category/note |
| `untag_asset_async(session, ip)` | `db.untag_asset()` | Set NULL |
| `add_subnet_async(session, cidr, label, vlan_id?)` | `db.add_subnet()` | UPSERT via merge() |
| `remove_subnet_async(session, cidr)` | `db.remove_subnet()` | Delete |
| `save_certificate_async(session, cert)` | `db.save_certificate()` | UPSERT on ip+port |

Tests: `tests/test_core_services.py`
- `save_scan_async` creates scan + assets + scan_assets + asset_changes
- Upsert detects field changes (hostname change → asset_change row)
- Tag/untag operations
- Certificate upsert on ip+port conflict

**Exit:** All service functions tested with seeded data, output matches `bigr/db.py` format.

---

### Wave 4: Dashboard API Migration

**Agent 4A: Core API Routes**

Modify `bigr/dashboard/app.py`:
- Add `from bigr.core.database import get_db`
- Add `from bigr.core import services`
- Add `from fastapi import Depends`
- Convert routes to use `db: AsyncSession = Depends(get_db)`:

| Route | Before | After |
|-------|--------|-------|
| `GET /api/data` | `get_all_assets(db_path=_db_path)` | `await services.get_all_assets(db)` |
| `GET /api/scans` | `get_scan_list(limit=50, db_path=_db_path)` | `await services.get_scan_list(db, 50)` |
| `GET /api/assets/{ip}` | `get_asset_history(ip=ip, db_path=_db_path)` | `await services.get_asset_history(db, ip=ip)` |
| `GET /api/changes` | `get_changes_from_db(db_path=_db_path)` | `await services.get_changes_async(db, limit)` |
| `GET /api/subnets` | `get_subnets(db_path=_db_path)` | `await services.get_subnets_async(db)` |
| `GET /api/switches` | `get_switches(db_path=_db_path)` | `await services.get_switches_async(db)` |
| `GET /api/certificates` | `get_certificates(db_path=_db_path)` | `await services.get_certificates_async(db)` |
| `GET /api/compliance` | computed from assets | Same logic, async source |
| `GET /api/analytics` | `analytics.get_trend_data()` | `await services.get_analytics_async(db)` |
| `GET /api/risk` | `risk_scorer.calculate()` | `await services.get_risk_async(db)` |
| `GET /api/vulnerabilities` | `vuln_matcher.match()` | `await services.get_vulns_async(db)` |

Keep `_load_data()` file fallback for backward compat. Add lifespan for startup migrations:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Run Alembic migrations on PostgreSQL only
    if "postgresql" in (settings.DATABASE_URL or ""):
        subprocess.run(["alembic", "upgrade", "head"], check=True)
    yield
```

Modify `create_app()` signature: remove `db_path` parameter (use env var instead).

Tests: `tests/test_dashboard_async.py`
- All 13 API endpoints return 200 with seeded data
- Empty database returns valid empty responses
- Subnet filter works on `/api/data?subnet=...`

**Exit:** Dashboard starts, all endpoints work with async SQLAlchemy, existing Shield API unaffected.

---

### Wave 5: Render Deployment

**Agent 5A: Backend Service + Neon**

Create:
- `render.yaml`:
  ```yaml
  services:
    - type: web
      name: bigr-discovery-api
      runtime: python
      region: frankfurt
      plan: starter
      buildCommand: "pip install -e . && alembic upgrade head"
      startCommand: "uvicorn bigr.dashboard.app:create_app --host 0.0.0.0 --port $PORT --factory"
      envVars:
        - key: DATABASE_URL
          sync: false  # Set manually (Neon connection string)
        - key: GENESIS_ALLOW_POSTGRES
          value: "true"
        - key: PYTHON_VERSION
          value: "3.12"
  ```
- `.env.example`:
  ```
  DATABASE_URL=sqlite:///~/.bigr/bigr.db
  # DATABASE_URL=postgresql://user:pass@ep-xxx.eu-central-1.aws.neon.tech/bigr_discovery?sslmode=require
  ```

Modify `bigr/dashboard/app.py`:
- Ensure `create_app` works as uvicorn factory (no args needed, reads from env)
- Add `/api/health` deep check (DB connectivity, migration status)

Modify frontend:
- `frontend/src/lib/api.ts` - Add `VITE_API_URL` support: `baseURL: import.meta.env.VITE_API_URL || ''`
- When `VITE_API_URL` is set AND `VITE_DEMO_MODE` is not true → use real API

**Agent 5B: CI + Frontend Wiring**

Create:
- `.github/workflows/test.yml` - pytest on push, Alembic migration smoke test
- `scripts/migrate_sqlite_data.py` - One-time script: read legacy `~/.bigr/bigr.db` → write to target `DATABASE_URL`

Update Render static site env:
- Set `VITE_API_URL=https://bigr-discovery-api.onrender.com` to point frontend at backend
- Keep `VITE_DEMO_MODE=true` as fallback (if API unreachable, use mock data)

**Exit:** Backend deployed on Render, Neon DB connected, frontend talks to real API.

---

## Critical Files

| File | Action | Lines (est.) |
|------|--------|-------------|
| `bigr/core/__init__.py` | Create | 0 |
| `bigr/core/settings.py` | Create | ~20 |
| `bigr/core/database.py` | Create | ~100 |
| `bigr/core/models_db.py` | Create | ~200 |
| `bigr/core/services.py` | Create | ~400 |
| `alembic.ini` | Create | ~30 |
| `alembic/env.py` | Create | ~60 |
| `alembic/versions/001_initial.py` | Generate | ~100 |
| `bigr/dashboard/app.py` | Modify | ~200 lines changed |
| `pyproject.toml` | Modify | +5 deps |
| `render.yaml` | Create | ~20 |
| `scripts/alembic.sh` | Create | ~5 |
| `scripts/migrate_sqlite_data.py` | Create | ~80 |
| `.env.example` | Create | ~5 |
| `tests/test_core_database.py` | Create | ~80 |
| `tests/test_core_models.py` | Create | ~120 |
| `tests/test_core_services.py` | Create | ~300 |
| `tests/test_dashboard_async.py` | Create | ~200 |
| `tests/test_alembic.py` | Create | ~50 |

**Total:** ~19 files, ~1800 lines new code, ~200 lines modified

## What Stays Unchanged

- `bigr/db.py` (680 lines) - CLI sync layer, untouched
- `bigr/models.py` (161 lines) - Domain dataclasses, untouched
- `bigr/shield/` - All Shield modules, untouched (in-memory)
- `bigr/scanner/` - All scanner modules, untouched
- `bigr/cli.py` - CLI entrypoint, untouched
- `frontend/` - SPA code unchanged (only env var config)
- All 1020 existing tests - Must continue passing

## Verification

After each wave:
1. `pytest` - All existing + new tests pass
2. `alembic upgrade head` - Migrations apply cleanly (Wave 2+)
3. `uvicorn bigr.dashboard.app:create_app --factory` - Dashboard starts (Wave 4+)
4. `curl /api/health` - Returns 200 with DB status (Wave 4+)

After Wave 5:
5. Render deploy succeeds, `/api/health` returns PostgreSQL status
6. Frontend at demo site loads data from real API
7. `bigr scan` CLI still works with local SQLite
