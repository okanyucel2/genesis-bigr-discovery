# BİGR Discovery - Hybrid Agent Architecture

## Context

BİGR Discovery backend runs on Render (cloud) with Neon PostgreSQL. The frontend is a Vue 3 SPA on Render static. **Problem:** Cloud backend cannot scan local networks (192.168.x.x) — scans timeout because Render has no access to customer LAN. **Solution:** A lightweight local agent that runs on the customer's network, performs discovery + security scans, and pushes results to the cloud API via authenticated HTTPS. The cloud dashboard becomes the multi-site control plane.

```
┌─ Customer Site A ───────┐       HTTPS        ┌─ Cloud (Render) ──────────┐
│  bigr agent start       │ ==================> │  FastAPI + Neon PostgreSQL│
│  - ARP sweep, nmap      │  POST /api/ingest/* │  Vue 3 SPA dashboard      │
│  - Shield modules       │  POST /api/agents/* │                           │
│  - Heartbeat every 60s  │                     │  Shows ALL sites          │
└─────────────────────────┘                     └───────────────────────────┘
┌─ Customer Site B ───────┐       HTTPS        │
│  bigr agent start       │ ==================> │
└─────────────────────────┘                     │
```

## Key Design Decisions

1. **Reuse `save_scan_async`** — Ingest endpoints pass results through the existing service layer. No persistence rewrite needed.
2. **Bearer token auth** — SHA-256 hashed tokens in `agents` table. Simple, no JWT complexity.
3. **Site tagging via nullable columns** — Add `agent_id` + `site_name` to `scans` and `assets`. Existing data keeps NULL (= "direct/local").
4. **Agent daemon reuses WatcherDaemon pattern** — PID file management, periodic scan loop from `bigr/watcher.py`.
5. **httpx for agent HTTP client** — Already a dev dependency, move to main deps.

---

## Wave 1: Agent Model + Auth + Ingest Endpoints

**Delivers:** Cloud API accepts scan results from authenticated agents.

### Create

| File | Purpose |
|------|---------|
| `bigr/agent/__init__.py` | Package init |
| `bigr/agent/models.py` | Pydantic schemas: `AgentRegisterRequest`, `AgentRegisterResponse`, `AgentHeartbeatRequest`, `IngestDiscoveryRequest`, `IngestShieldRequest` |
| `bigr/agent/auth.py` | `generate_token()`, `hash_token()`, `verify_agent_token()` FastAPI dependency using `HTTPBearer` |
| `bigr/agent/routes.py` | Agent API router with 5 endpoints (see below) |
| `alembic/versions/xxxx_add_agents_table.py` | Migration: agents table + agent_id/site_name columns |
| `tests/test_agent_auth.py` | Token generation, hashing, verification |
| `tests/test_agent_routes.py` | All 5 endpoints with httpx TestClient |

### Modify

| File | Change |
|------|--------|
| `bigr/core/models_db.py` | Add `AgentDB` model (id, name, site_name, location, token_hash, is_active, registered_at, last_seen, status, version, subnets). Add nullable `agent_id` (FK) + `site_name` to `ScanDB` and `AssetDB` |
| `bigr/core/services.py` | In `save_scan_async`: pass through `agent_id` and `site_name` from scan_result dict to `ScanDB` and `AssetDB` creation |
| `bigr/core/settings.py` | Add `AGENT_REGISTRATION_SECRET: str = ""` |
| `bigr/dashboard/app.py` | `app.include_router(agent_router)` |

### Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/agents/register` | Optional secret | Register agent, return token (shown once) |
| POST | `/api/agents/heartbeat` | Bearer token | Update last_seen + status |
| GET | `/api/agents` | None | List all agents with status |
| POST | `/api/ingest/discovery` | Bearer token | Accept discovery scan results → `save_scan_async()` |
| POST | `/api/ingest/shield` | Bearer token | Accept shield scan results (store findings) |

### Verification
- `pytest tests/test_agent_*.py` — All pass
- `alembic upgrade head` — agents table created, new columns added
- `curl -X POST /api/agents/register -d '{"name":"test","site_name":"HQ"}'` — Returns agent_id + token
- `curl -H "Authorization: Bearer <token>" -X POST /api/ingest/discovery -d '{...}'` — Returns 200 + scan_id

---

## Wave 2: Agent CLI Daemon

**Delivers:** Local agent runnable via `bigr agent start --api-url ... --token ...`

### Create

| File | Purpose |
|------|---------|
| `bigr/agent/daemon.py` | `AgentDaemon` class: init with api_url/token/targets, `_run_single_cycle()` (scan → classify → push), `_send_heartbeat()`, `start()/stop()` with PID file |
| `bigr/agent/config.py` | `AgentConfig` dataclass + `~/.bigr/agent.yaml` load/save |
| `tests/test_agent_daemon.py` | Daemon with mocked httpx (scan cycle, heartbeat, PID lifecycle) |
| `tests/test_agent_cli.py` | CLI commands with mocked HTTP |

### Modify

| File | Change |
|------|--------|
| `bigr/cli.py` | Add `agent` sub-app: `agent start`, `agent stop`, `agent status`, `agent register` |
| `pyproject.toml` | Move `httpx>=0.27.0` from `[dev]` to main `dependencies` |

### CLI Commands

```bash
# One-time registration
bigr agent register --api-url https://bigr-discovery-api.onrender.com \
  --name "istanbul-scanner" --site "Istanbul Office"
# → Saves token to ~/.bigr/agent.yaml

# Start daemon (reads config from agent.yaml)
bigr agent start 192.168.1.0/24 --interval 5m

# Or with explicit params
bigr agent start 192.168.1.0/24 10.0.0.0/16 \
  --api-url https://bigr-discovery-api.onrender.com \
  --token <token> --interval 5m --shield

# Status / stop
bigr agent status
bigr agent stop
```

### Agent Daemon Flow
```
start() → write PID → _run_loop()
  │
  ├─ _run_single_cycle():
  │   ├─ run_hybrid_scan(target)      # existing scanner
  │   ├─ classify_assets(result)       # existing classifier
  │   ├─ _push_discovery_results()     # POST /api/ingest/discovery
  │   ├─ (optional) shield scan        # existing shield modules
  │   └─ _push_shield_results()        # POST /api/ingest/shield
  │
  ├─ _send_heartbeat()                 # POST /api/agents/heartbeat
  └─ sleep(interval) → repeat
```

### Verification
- `bigr agent register --api-url http://localhost:8090 --name test --site HQ` — Registers, saves yaml
- `bigr agent start 192.168.1.0/24 --interval 1m` — Scans, pushes, heartbeats visible in cloud
- `bigr agent status` — Shows PID + last scan time
- `bigr agent stop` — Clean shutdown

---

## Wave 3: Multi-Site Dashboard

**Delivers:** Frontend shows site information, site-level filtering, agent status page.

### Backend Changes

| File | Change |
|------|--------|
| `bigr/core/services.py` | Add `get_all_assets(session, site_name=None)` filter, `get_sites_summary(session)`, `get_agents_list(session)` |
| `bigr/dashboard/app.py` | Add `site` query param to `GET /api/data`, `GET /api/changes`, etc. Add `GET /api/sites` endpoint |
| `tests/test_site_filtering.py` | Site filter on data endpoints, sites summary |

### Frontend Changes

| File | Change |
|------|---------|
| `frontend/src/types/api.ts` | Add `Agent`, `SiteSummary` interfaces |
| `frontend/src/lib/api.ts` | Add `getAgents()`, `getSites()`, update `getAssets(subnet?, site?)` |
| `frontend/src/composables/useAgents.ts` | New composable for agent list + status |
| `frontend/src/views/AgentsView.vue` | New page: agent cards with status indicators, site info, subnets, last seen |
| `frontend/src/components/dashboard/SiteFilter.vue` | Dropdown: "All Sites" + per-site options |
| `frontend/src/stores/ui.ts` | Add `selectedSite` to global state |
| `frontend/src/router/index.ts` | Add `/agents` route |

### Verification
- Dashboard shows site filter dropdown
- Selecting a site filters assets/changes/topology
- `/agents` page shows registered agents with online/offline indicators
- `GET /api/data?site=Istanbul` returns only that site's data

---

## Wave 4: Resilience + Shield Persistence + Hardening

**Delivers:** Offline queue, retry logic, shield DB persistence, agent config management.

### Create

| File | Purpose |
|------|---------|
| `bigr/agent/queue.py` | `OfflineQueue`: file-based queue (`~/.bigr/queue/`), `enqueue()` on push failure, `drain()` at cycle start |
| `alembic/versions/xxxx_add_shield_tables.py` | Migration: `shield_scans` + `shield_findings` tables |
| `tests/test_offline_queue.py` | Enqueue/drain, partial drain, cleanup |
| `tests/test_shield_ingest.py` | Shield findings persisted to DB |

### Modify

| File | Change |
|------|--------|
| `bigr/core/models_db.py` | Add `ShieldScanDB`, `ShieldFindingDB` models |
| `bigr/agent/daemon.py` | Wrap push calls with try/except → enqueue on failure, drain at cycle start |
| `bigr/agent/routes.py` | `POST /api/ingest/shield` → persist to `shield_scans` + `shield_findings` |
| `.env.example` | Add `AGENT_REGISTRATION_SECRET` |
| `render.yaml` | Add `AGENT_REGISTRATION_SECRET` env var |

### Verification
- Kill network → agent queues results to `~/.bigr/queue/`
- Restore network → next cycle drains queue successfully
- Shield findings visible in cloud DB after ingest
- `GET /api/agents` shows stale status for agents offline > 5min

---

## Critical Files Summary

| File | Waves | Action |
|------|-------|--------|
| `bigr/agent/__init__.py` | 1 | Create |
| `bigr/agent/models.py` | 1 | Create |
| `bigr/agent/auth.py` | 1 | Create |
| `bigr/agent/routes.py` | 1, 4 | Create, modify |
| `bigr/agent/daemon.py` | 2, 4 | Create, modify |
| `bigr/agent/config.py` | 2 | Create |
| `bigr/agent/queue.py` | 4 | Create |
| `bigr/core/models_db.py` | 1, 4 | Modify |
| `bigr/core/services.py` | 1, 3 | Modify |
| `bigr/core/settings.py` | 1 | Modify |
| `bigr/dashboard/app.py` | 1, 3 | Modify |
| `bigr/cli.py` | 2 | Modify |
| `pyproject.toml` | 2 | Modify |
| `bigr/watcher.py` | — | Reference only (daemon pattern) |

## What Stays Unchanged

- `bigr/scanner/` — All scanner modules (agent reuses them as-is)
- `bigr/shield/modules/` — All shield modules (agent reuses them as-is)
- `bigr/shield/orchestrator.py` — Shield orchestrator (agent calls it locally)
- `bigr/db.py` — Legacy sync DB layer
- `bigr/models.py` — Domain dataclasses
- Frontend existing components (only additions, no modifications to existing views)
