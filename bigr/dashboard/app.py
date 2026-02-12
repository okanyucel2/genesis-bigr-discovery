"""FastAPI API server for BİGR Discovery."""

from __future__ import annotations

import ipaddress
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.agent.routes import router as agent_router
from bigr.ai.api import router as ai_router
from bigr.collective.api import router as collective_router
from bigr.core import services
from bigr.core.database import get_db
from bigr.core.models_db import AssetDB
from bigr.core.settings import settings
from bigr.family.api import router as family_router
from bigr.language.api import router as language_router
from bigr.onboarding.api import router as onboarding_router
from bigr.shield.api.routes import router as shield_router
from bigr.subscription.api import router as subscription_router
from bigr.remediation.api import router as remediation_router
from bigr.firewall.api import router as firewall_router
from bigr.threat.abuseipdb_api import router as abuseipdb_router
from bigr.threat.api import router as threat_router
from bigr.guardian.api.routes import router as guardian_router
from bigr.engagement.api import router as engagement_router
from bigr.watcher_api import router as watcher_router
from bigr.topology import build_subnet_topology, build_topology


def _ip_in_subnet(ip: str, network, subnet_cidr: str | None = None) -> bool:
    """Check if an IP belongs to a subnet, using subnet_cidr tag or IP range check."""
    # If asset has a subnet_cidr tag, use exact match
    if subnet_cidr:
        return subnet_cidr == str(network)
    # Otherwise check if IP is in the network range
    try:
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False


def create_app(data_path: str = "assets.json", db_path: Path | None = None) -> FastAPI:
    """Create dashboard FastAPI app.

    The ``db_path`` parameter is kept for backward compatibility with CLI usage.
    When running on Render, ``DATABASE_URL`` env var is used instead.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Run Alembic migrations on PostgreSQL at startup (production only)
        if "postgresql" in (settings.DATABASE_URL or "") and os.environ.get("RENDER"):
            import subprocess
            import logging

            try:
                subprocess.run(["alembic", "upgrade", "head"], check=True)
            except subprocess.CalledProcessError:
                logging.getLogger(__name__).warning(
                    "Alembic migration failed — continuing with existing schema"
                )
        yield

    app = FastAPI(title="BİGR Discovery API", lifespan=lifespan)

    # CORS — allow frontend on separate domain (Render Static Site, etc.)
    allowed_origins = [
        origin.strip()
        for origin in os.environ.get("CORS_ORIGINS", "").split(",")
        if origin.strip()
    ]
    # Always allow localhost for local development (safe — only reachable locally)
    for local in ("http://localhost:5173", "http://localhost:19978", "http://127.0.0.1:19978"):
        if local not in allowed_origins:
            allowed_origins.append(local)
    if allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.include_router(shield_router)
    app.include_router(agent_router)
    app.include_router(ai_router)
    app.include_router(collective_router)
    app.include_router(language_router)
    app.include_router(threat_router)
    app.include_router(abuseipdb_router)
    app.include_router(onboarding_router)
    app.include_router(remediation_router)
    app.include_router(subscription_router)
    app.include_router(family_router)
    app.include_router(firewall_router)
    app.include_router(guardian_router)
    app.include_router(engagement_router)
    app.include_router(watcher_router)
    _data_path = Path(data_path)

    async def _load_data_async(db: AsyncSession) -> dict:
        """Load scan data from database, falling back to JSON file."""
        # Prefer database (kept up-to-date by ingest pipeline)
        try:
            latest = await services.get_latest_scan(db)
            if latest and latest.get("assets"):
                return latest
        except Exception:
            pass
        # Fallback to static JSON file (initial/demo data)
        if _data_path.exists():
            with _data_path.open(encoding="utf-8") as f:
                return json.load(f)
        return {"assets": [], "category_summary": {}, "total_assets": 0}

    @app.get("/api/data", response_class=JSONResponse)
    async def api_data(
        subnet: str | None = None,
        site: str | None = None,
        network: str | None = None,
        db: AsyncSession = Depends(get_db),
    ):
        # Try DB first (always up-to-date from ingest pipeline)
        try:
            assets = await services.get_all_assets(
                db, site_name=site, network_id=network,
            )
            if assets:
                data = {"assets": assets, "total_assets": len(assets)}
            else:
                data = await _load_data_async(db)
        except Exception:
            data = await _load_data_async(db)
        # Enrich assets with manual_override flag
        try:
            tagged = await services.get_tags_async(db)
            tagged_ips = {t["ip"] for t in tagged}
        except Exception:
            tagged_ips = set()
        for asset in data.get("assets", []):
            asset["manual_override"] = asset.get("ip", "") in tagged_ips
        # Filter by subnet if requested
        if subnet:
            try:
                network = ipaddress.ip_network(subnet, strict=False)
                data["assets"] = [
                    a for a in data.get("assets", [])
                    if _ip_in_subnet(a.get("ip", ""), network, a.get("subnet_cidr"))
                ]
            except ValueError:
                pass
        return data

    @app.get("/api/subnets", response_class=JSONResponse)
    async def api_subnets(db: AsyncSession = Depends(get_db)):
        """Return all registered subnets."""
        try:
            subnet_list = await services.get_subnets_async(db)
            return {"subnets": subnet_list}
        except Exception:
            return {"subnets": []}

    @app.get("/api/scans", response_class=JSONResponse)
    async def api_scans(db: AsyncSession = Depends(get_db)):
        """Return scan history from the database."""
        try:
            scans = await services.get_scan_list(db, limit=50)
            return {"scans": scans}
        except Exception:
            return {"scans": []}

    @app.get("/api/assets/{ip}", response_class=JSONResponse)
    async def api_asset_detail(ip: str, db: AsyncSession = Depends(get_db)):
        """Return single asset details and scan history."""
        try:
            all_assets = await services.get_all_assets(db)
            asset = next((a for a in all_assets if a["ip"] == ip), None)
            if asset is None:
                return JSONResponse({"error": "Asset not found"}, status_code=404)
            history = await services.get_asset_history(db, ip=ip)
            return {"asset": asset, "history": history}
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

    @app.patch("/api/assets/{ip}/sensitivity", response_class=JSONResponse)
    async def api_update_sensitivity(
        ip: str,
        sensitivity: str,
        db: AsyncSession = Depends(get_db),
    ):
        """Update an asset's sensitivity level."""
        valid = {"fragile", "cautious", "safe"}
        if sensitivity not in valid:
            return JSONResponse(
                {"error": f"Invalid sensitivity. Valid: {', '.join(sorted(valid))}"},
                status_code=400,
            )
        try:
            updated = await services.update_asset_sensitivity(db, ip, sensitivity)
            if not updated:
                return JSONResponse({"error": "Asset not found"}, status_code=404)
            return {"ip": ip, "sensitivity_level": sensitivity}
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

    async def _resolve_mac(db: AsyncSession, ip: str) -> str | None:
        """Find MAC address for an IP. MAC is the stable device identifier."""
        result = await db.execute(
            select(AssetDB.mac).where(AssetDB.ip == ip).limit(1)
        )
        return result.scalar_one_or_none()

    @app.post("/api/assets/{ip}/acknowledge", response_class=JSONResponse)
    async def api_acknowledge_asset(ip: str, db: AsyncSession = Depends(get_db)):
        """Mark an asset as acknowledged (known device). Uses MAC for persistence across IP changes."""
        try:
            mac = await _resolve_mac(db, ip)
            if mac:
                # Tag ALL records with this MAC (covers IP changes)
                stmt = (
                    update(AssetDB)
                    .where(AssetDB.mac == mac)
                    .values(manual_category="acknowledged", manual_note="Kullanici tarafindan tanindi")
                )
                await db.execute(stmt)
                await db.commit()
            else:
                # Fallback to IP if no MAC (rare edge case)
                await services.tag_asset_async(db, ip, "acknowledged", "Kullanici tarafindan tanindi")
            return {"status": "ok", "ip": ip, "message": "Cihaz tanindi."}
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

    @app.post("/api/assets/{ip}/ignore", response_class=JSONResponse)
    async def api_ignore_asset(ip: str, db: AsyncSession = Depends(get_db)):
        """Mark an asset as ignored (blocked/hidden). Uses MAC for persistence across IP changes."""
        try:
            mac = await _resolve_mac(db, ip)
            where_clause = AssetDB.mac == mac if mac else AssetDB.ip == ip
            stmt = (
                update(AssetDB)
                .where(where_clause)
                .values(is_ignored=1, manual_note="Kullanici tarafindan engellendi")
            )
            result = await db.execute(stmt)
            await db.commit()
            if result.rowcount == 0:
                return JSONResponse({"error": "Asset not found"}, status_code=404)
            return {"status": "ok", "ip": ip, "message": "Cihaz engellendi."}
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

    @app.get("/api/changes", response_class=JSONResponse)
    async def api_changes(
        limit: int = 50,
        site: str | None = None,
        db: AsyncSession = Depends(get_db),
    ):
        """Return recent asset changes from the database."""
        try:
            changes = await services.get_changes_async(db, limit=limit, site_name=site)
            return {"changes": changes}
        except Exception:
            return {"changes": []}

    @app.get("/api/sites", response_class=JSONResponse)
    async def api_sites(db: AsyncSession = Depends(get_db)):
        """Return summary of all known sites with asset counts."""
        try:
            sites = await services.get_sites_summary(db)
            return {"sites": sites}
        except Exception:
            return {"sites": []}

    @app.get("/api/switches", response_class=JSONResponse)
    async def api_switches(db: AsyncSession = Depends(get_db)):
        """Return all registered switches."""
        try:
            switch_list = await services.get_switches_async(db)
            return {"switches": switch_list}
        except Exception:
            return {"switches": []}

    @app.get("/api/topology", response_class=JSONResponse)
    async def api_topology(db: AsyncSession = Depends(get_db)):
        """Return network topology graph data."""
        data = await _load_data_async(db)
        assets = data.get("assets", [])
        graph = build_topology(assets)
        return graph.to_dict()

    @app.get("/api/topology/subnet/{cidr:path}", response_class=JSONResponse)
    async def api_topology_subnet(cidr: str, db: AsyncSession = Depends(get_db)):
        """Return topology for a specific subnet."""
        data = await _load_data_async(db)
        assets = data.get("assets", [])
        graph = build_subnet_topology(assets, cidr)
        return graph.to_dict()

    @app.get("/api/certificates", response_class=JSONResponse)
    async def api_certificates(db: AsyncSession = Depends(get_db)):
        """Return all discovered TLS certificates."""
        try:
            cert_list = await services.get_certificates_async(db)
            return {"certificates": cert_list}
        except Exception:
            return {"certificates": []}

    @app.get("/api/compliance", response_class=JSONResponse)
    async def api_compliance(db: AsyncSession = Depends(get_db)):
        """Return compliance metrics."""
        from bigr.compliance import calculate_compliance, calculate_subnet_compliance

        data = await _load_data_async(db)
        assets = data.get("assets", [])

        report = calculate_compliance(assets)

        # Calculate subnet compliance if subnets are registered
        try:
            subnet_list = await services.get_subnets_async(db)
            if subnet_list:
                report.subnet_compliance = calculate_subnet_compliance(assets, subnet_list)
        except Exception:
            pass

        return report.to_dict()

    @app.get("/api/analytics", response_class=JSONResponse)
    async def api_analytics(days: int = 30, db: AsyncSession = Depends(get_db)):
        """Return analytics data."""
        from bigr.analytics import get_full_analytics

        try:
            result = get_full_analytics(days=days, db_path=None)
            return result.to_dict()
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

    @app.get("/api/risk", response_class=JSONResponse)
    async def api_risk(db: AsyncSession = Depends(get_db)):
        """Return risk assessment data."""
        from bigr.risk.scorer import assess_network_risk

        try:
            all_assets = await services.get_all_assets(db)
        except Exception:
            all_assets = []

        # Fall back to file-based data if DB has no assets
        if not all_assets:
            data = await _load_data_async(db)
            all_assets = data.get("assets", [])

        asset_dicts = []
        for a in all_assets:
            asset_dicts.append({
                "ip": a.get("ip", ""),
                "mac": a.get("mac"),
                "hostname": a.get("hostname"),
                "vendor": a.get("vendor"),
                "bigr_category": a.get("bigr_category", "unclassified"),
                "confidence_score": a.get("confidence_score", 0.0),
                "open_ports": a.get("open_ports", []),
                "first_seen": a.get("first_seen"),
            })

        report = assess_network_risk(asset_dicts)
        return report.to_dict()

    @app.get("/api/vulnerabilities", response_class=JSONResponse)
    async def api_vulnerabilities(db: AsyncSession = Depends(get_db)):
        """Return vulnerability scan results for all known assets."""
        from bigr.vuln.cve_db import get_cve_stats, init_cve_db
        from bigr.vuln.matcher import scan_all_vulnerabilities
        from bigr.vuln.nvd_sync import seed_cve_database

        try:
            # Initialize and seed CVE DB if needed
            init_cve_db(None)
            stats = get_cve_stats(db_path=None)
            if stats["total"] == 0:
                seed_cve_database(db_path=None)

            # Get assets
            data = await _load_data_async(db)
            assets = data.get("assets", [])

            summaries = scan_all_vulnerabilities(assets, db_path=None)
            return {
                "summaries": [s.to_dict() for s in summaries],
                "total_assets_scanned": len(assets),
                "total_vulnerable": len(summaries),
                "cve_db_stats": get_cve_stats(db_path=None),
            }
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

    @app.get("/api/health")
    async def health(db: AsyncSession = Depends(get_db)):
        """Deep health check with DB connectivity."""
        db_status = "unknown"
        db_type = "unknown"
        try:
            from sqlalchemy import text

            result = await db.execute(text("SELECT 1"))
            result.scalar()
            db_status = "connected"
            dialect = db.bind.dialect.name if db.bind else "unknown"
            db_type = dialect
        except Exception as exc:
            db_status = f"error: {exc}"

        return {
            "status": "ok" if db_status == "connected" else "degraded",
            "database": {"status": db_status, "type": db_type},
            "data_file": str(_data_path),
            "data_file_exists": _data_path.exists(),
        }

    return app
