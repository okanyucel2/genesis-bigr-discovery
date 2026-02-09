"""FastAPI web dashboard for BİGR Discovery scan results."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from bigr.db import (
    get_all_assets,
    get_asset_history,
    get_latest_scan,
    get_scan_list,
    get_subnets,
    get_tags,
)
from bigr.diff import get_changes_from_db
from bigr.scanner.switch_map import get_switches
from bigr.shield.api.routes import router as shield_router
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
    """Create dashboard FastAPI app."""
    app = FastAPI(title="BİGR Discovery Dashboard")
    app.include_router(shield_router)
    _data_path = Path(data_path)
    _db_path = db_path

    def _load_data() -> dict:
        """Load scan data from file, falling back to database."""
        if _data_path.exists():
            with _data_path.open(encoding="utf-8") as f:
                return json.load(f)
        # Fall back to latest scan from database
        try:
            latest = get_latest_scan()
            if latest:
                return latest
        except Exception:
            pass
        return {"assets": [], "category_summary": {}, "total_assets": 0}

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        data = _load_data()
        return HTMLResponse(content=_render_dashboard(data))

    @app.get("/api/data", response_class=JSONResponse)
    async def api_data(subnet: str | None = None):
        data = _load_data()
        # Enrich assets with manual_override flag
        try:
            tagged = get_tags(db_path=_db_path)
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
    async def api_subnets():
        """Return all registered subnets."""
        try:
            subnet_list = get_subnets(db_path=_db_path)
            return {"subnets": subnet_list}
        except Exception:
            return {"subnets": []}

    @app.get("/api/scans", response_class=JSONResponse)
    async def api_scans():
        """Return scan history from the database."""
        try:
            scans = get_scan_list(limit=50)
            return {"scans": scans}
        except Exception:
            return {"scans": []}

    @app.get("/api/assets/{ip}", response_class=JSONResponse)
    async def api_asset_detail(ip: str):
        """Return single asset details and scan history."""
        try:
            all_assets = get_all_assets()
            asset = next((a for a in all_assets if a["ip"] == ip), None)
            if asset is None:
                return JSONResponse({"error": "Asset not found"}, status_code=404)
            history = get_asset_history(ip=ip)
            return {"asset": asset, "history": history}
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

    @app.get("/api/changes", response_class=JSONResponse)
    async def api_changes(limit: int = 50):
        """Return recent asset changes from the database."""
        try:
            changes = get_changes_from_db(limit=limit)
            return {"changes": changes}
        except Exception:
            return {"changes": []}

    @app.get("/api/switches", response_class=JSONResponse)
    async def api_switches():
        """Return all registered switches."""
        try:
            switch_list = get_switches(db_path=_db_path)
            return {"switches": switch_list}
        except Exception:
            return {"switches": []}

    @app.get("/api/topology", response_class=JSONResponse)
    async def api_topology():
        """Return network topology graph data."""
        data = _load_data()
        assets = data.get("assets", [])
        graph = build_topology(assets)
        return graph.to_dict()

    @app.get("/api/topology/subnet/{cidr:path}", response_class=JSONResponse)
    async def api_topology_subnet(cidr: str):
        """Return topology for a specific subnet."""
        data = _load_data()
        assets = data.get("assets", [])
        graph = build_subnet_topology(assets, cidr)
        return graph.to_dict()

    @app.get("/topology", response_class=HTMLResponse)
    async def topology_page():
        """Serve network topology visualization page."""
        return HTMLResponse(content=_render_topology_page())

    @app.get("/api/certificates", response_class=JSONResponse)
    async def api_certificates():
        """Return all discovered TLS certificates."""
        from bigr.db import get_certificates

        try:
            cert_list = get_certificates(db_path=_db_path)
            return {"certificates": cert_list}
        except Exception:
            return {"certificates": []}

    @app.get("/api/compliance", response_class=JSONResponse)
    async def api_compliance():
        """Return compliance metrics."""
        from bigr.compliance import calculate_compliance, calculate_subnet_compliance

        data = _load_data()
        assets = data.get("assets", [])

        report = calculate_compliance(assets)

        # Calculate subnet compliance if subnets are registered
        try:
            subnet_list = get_subnets(db_path=_db_path)
            if subnet_list:
                report.subnet_compliance = calculate_subnet_compliance(assets, subnet_list)
        except Exception:
            pass

        return report.to_dict()

    @app.get("/compliance", response_class=HTMLResponse)
    async def compliance_page():
        """Serve compliance dashboard with charts."""
        from bigr.compliance import calculate_compliance

        data = _load_data()
        assets = data.get("assets", [])
        report = calculate_compliance(assets)
        return HTMLResponse(content=_render_compliance_page(report))

    @app.get("/api/analytics", response_class=JSONResponse)
    async def api_analytics(days: int = 30):
        """Return analytics data."""
        from bigr.analytics import get_full_analytics

        try:
            result = get_full_analytics(days=days, db_path=_db_path)
            return result.to_dict()
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

    @app.get("/analytics", response_class=HTMLResponse)
    async def analytics_page():
        """Serve analytics dashboard with trend charts."""
        return HTMLResponse(content=_render_analytics_page())

    @app.get("/api/risk", response_class=JSONResponse)
    async def api_risk():
        """Return risk assessment data."""
        from bigr.risk.scorer import assess_network_risk

        try:
            all_assets = get_all_assets(db_path=_db_path)
        except Exception:
            all_assets = []

        # Fall back to file-based data if DB has no assets
        if not all_assets:
            data = _load_data()
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

    @app.get("/risk", response_class=HTMLResponse)
    async def risk_page():
        """Serve risk assessment dashboard page."""
        from bigr.risk.scorer import assess_network_risk

        try:
            all_assets = get_all_assets(db_path=_db_path)
        except Exception:
            all_assets = []

        if not all_assets:
            data = _load_data()
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
        return HTMLResponse(content=_render_risk_page(report))

    @app.get("/api/vulnerabilities", response_class=JSONResponse)
    async def api_vulnerabilities():
        """Return vulnerability scan results for all known assets."""
        from bigr.vuln.cve_db import get_cve_stats, init_cve_db
        from bigr.vuln.matcher import scan_all_vulnerabilities
        from bigr.vuln.nvd_sync import seed_cve_database

        try:
            # Initialize and seed CVE DB if needed
            init_cve_db(_db_path)
            stats = get_cve_stats(db_path=_db_path)
            if stats["total"] == 0:
                seed_cve_database(db_path=_db_path)

            # Get assets
            data = _load_data()
            assets = data.get("assets", [])

            summaries = scan_all_vulnerabilities(assets, db_path=_db_path)
            return {
                "summaries": [s.to_dict() for s in summaries],
                "total_assets_scanned": len(assets),
                "total_vulnerable": len(summaries),
                "cve_db_stats": get_cve_stats(db_path=_db_path),
            }
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

    @app.get("/vulnerabilities", response_class=HTMLResponse)
    async def vulnerabilities_page():
        """Serve vulnerability dashboard page."""
        return HTMLResponse(content=_render_vulnerabilities_page())

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "data_file": str(_data_path), "exists": _data_path.exists()}

    return app


def _render_dashboard(data: dict) -> str:
    """Render single-page HTML dashboard."""
    assets = data.get("assets", [])
    summary = data.get("category_summary", {})
    total = data.get("total_assets", len(assets))
    scan_method = data.get("scan_method", "unknown")
    duration = data.get("duration_seconds")
    target = data.get("target", "-")

    category_info = {
        "ag_ve_sistemler": {"label": "Ag ve Sistemler", "color": "#3b82f6", "icon": "&#128429;"},
        "uygulamalar": {"label": "Uygulamalar", "color": "#8b5cf6", "icon": "&#127760;"},
        "iot": {"label": "IoT", "color": "#10b981", "icon": "&#128247;"},
        "tasinabilir": {"label": "Tasinabilir", "color": "#f59e0b", "icon": "&#128187;"},
        "unclassified": {"label": "Siniflandirilmamis", "color": "#6b7280", "icon": "&#10067;"},
    }

    # Build category cards
    cards_html = ""
    for cat_key, info in category_info.items():
        count = summary.get(cat_key, 0)
        if count > 0 or cat_key != "unclassified":
            cards_html += f"""
            <div class="card" data-category="{cat_key}" onclick="filterCategory('{cat_key}')"
                 style="border-top: 3px solid {info['color']}">
                <div class="card-icon">{info['icon']}</div>
                <div class="card-count">{count}</div>
                <div class="card-label">{info['label']}</div>
            </div>"""

    # Determine which IPs have manual overrides
    try:
        tagged = get_tags()
        tagged_ips = {t["ip"] for t in tagged}
    except Exception:
        tagged_ips = set()

    # Build asset table rows
    rows_html = ""
    for asset in assets:
        conf = asset.get("confidence_score", 0)
        conf_class = "high" if conf >= 0.7 else "medium" if conf >= 0.4 else "low"
        ports = ", ".join(str(p) for p in asset.get("open_ports", [])) or "-"
        cat_key = asset.get("bigr_category", "unclassified")
        cat_color = category_info.get(cat_key, {}).get("color", "#6b7280")
        is_manual = asset.get("ip", "") in tagged_ips
        manual_badge = ' <span class="badge-manual">Manual</span>' if is_manual else ""

        rows_html += f"""
            <tr data-category="{cat_key}">
                <td>{asset.get('ip', '-')}</td>
                <td><code>{asset.get('mac', '-')}</code></td>
                <td>{asset.get('hostname') or '-'}</td>
                <td>{asset.get('vendor') or '-'}</td>
                <td><code>{ports}</code></td>
                <td><span class="badge" style="background:{cat_color}">{asset.get('bigr_category_tr', '-')}</span>{manual_badge}</td>
                <td><span class="conf conf-{conf_class}">{conf:.2f}</span></td>
                <td>{asset.get('os_hint') or '-'}</td>
            </tr>"""

    duration_str = f"{duration:.1f}s" if duration else "-"

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BIGR Discovery Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }}
        .header {{
            background: #1e293b;
            border-bottom: 1px solid #334155;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{
            font-size: 1.25rem;
            font-weight: 600;
            color: #f1f5f9;
        }}
        .header-meta {{
            font-size: 0.8rem;
            color: #94a3b8;
        }}
        .header-meta span {{ margin-left: 1rem; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 1.5rem; }}
        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }}
        .card {{
            background: #1e293b;
            border-radius: 8px;
            padding: 1.25rem;
            cursor: pointer;
            transition: transform 0.15s, box-shadow 0.15s;
            text-align: center;
        }}
        .card:hover {{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
        .card.active {{ box-shadow: 0 0 0 2px #60a5fa; }}
        .card-icon {{ font-size: 1.5rem; margin-bottom: 0.5rem; }}
        .card-count {{ font-size: 2rem; font-weight: 700; color: #f1f5f9; }}
        .card-label {{ font-size: 0.8rem; color: #94a3b8; margin-top: 0.25rem; }}
        .toolbar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }}
        .toolbar-left {{ display: flex; gap: 0.5rem; align-items: center; }}
        .search-input {{
            background: #1e293b;
            border: 1px solid #334155;
            color: #e2e8f0;
            padding: 0.5rem 0.75rem;
            border-radius: 6px;
            font-size: 0.85rem;
            width: 250px;
        }}
        .search-input:focus {{ outline: none; border-color: #60a5fa; }}
        .btn {{
            background: #334155;
            color: #e2e8f0;
            border: 1px solid #475569;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.8rem;
            transition: background 0.15s;
        }}
        .btn:hover {{ background: #475569; }}
        .btn-primary {{ background: #3b82f6; border-color: #3b82f6; }}
        .btn-primary:hover {{ background: #2563eb; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #1e293b;
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            background: #0f172a;
            padding: 0.75rem 1rem;
            text-align: left;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #94a3b8;
            border-bottom: 1px solid #334155;
            cursor: pointer;
        }}
        th:hover {{ color: #e2e8f0; }}
        td {{
            padding: 0.65rem 1rem;
            border-bottom: 1px solid #1e293b;
            font-size: 0.85rem;
        }}
        tr:hover {{ background: #334155; }}
        tr.hidden {{ display: none; }}
        code {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem; }}
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 500;
            color: #fff;
        }}
        .conf {{
            font-weight: 600;
            padding: 0.15rem 0.4rem;
            border-radius: 3px;
        }}
        .conf-high {{ color: #22c55e; }}
        .conf-medium {{ color: #eab308; }}
        .conf-low {{ color: #ef4444; }}
        .badge-manual {{
            display: inline-block;
            padding: 0.15rem 0.4rem;
            border-radius: 3px;
            font-size: 0.65rem;
            font-weight: 600;
            color: #06b6d4;
            border: 1px solid #06b6d4;
            margin-left: 0.35rem;
            vertical-align: middle;
        }}
        .total-bar {{
            text-align: center;
            padding: 0.5rem;
            font-size: 0.8rem;
            color: #64748b;
        }}
        .subnet-select {{
            background: #1e293b;
            border: 1px solid #334155;
            color: #e2e8f0;
            padding: 0.5rem 0.75rem;
            border-radius: 6px;
            font-size: 0.85rem;
            cursor: pointer;
        }}
        .subnet-select:focus {{ outline: none; border-color: #60a5fa; }}
    </style>
</head>
<body>
    <div class="header">
        <div style="display:flex;align-items:center;gap:1rem;">
            <h1>BIGR Discovery Dashboard</h1>
            <a href="/topology" class="btn btn-primary" style="text-decoration:none;font-size:0.8rem;">Topology Map</a>
        </div>
        <div class="header-meta">
            <span>Target: <strong>{target}</strong></span>
            <span>Mode: <strong>{scan_method}</strong></span>
            <span>Duration: <strong>{duration_str}</strong></span>
            <span>Assets: <strong>{total}</strong></span>
        </div>
    </div>
    <div class="container">
        <div class="cards">{cards_html}
        </div>
        <div class="toolbar">
            <div class="toolbar-left">
                <input type="text" class="search-input" placeholder="Search IP, hostname, vendor..."
                       oninput="searchAssets(this.value)">
                <select id="subnet-filter" class="subnet-select" onchange="filterSubnet(this.value)">
                    <option value="">All Subnets</option>
                </select>
                <button class="btn" onclick="filterCategory('all')">Show All</button>
            </div>
            <div>
                <button class="btn" onclick="exportJSON()">JSON Export</button>
                <button class="btn" onclick="exportCSV()">CSV Export</button>
            </div>
        </div>
        <table>
            <thead>
                <tr>
                    <th onclick="sortTable(0)">IP</th>
                    <th onclick="sortTable(1)">MAC</th>
                    <th onclick="sortTable(2)">Hostname</th>
                    <th onclick="sortTable(3)">Vendor</th>
                    <th onclick="sortTable(4)">Ports</th>
                    <th onclick="sortTable(5)">BIGR Group</th>
                    <th onclick="sortTable(6)">Confidence</th>
                    <th onclick="sortTable(7)">OS Hint</th>
                </tr>
            </thead>
            <tbody id="asset-table">{rows_html}
            </tbody>
        </table>
        <div class="total-bar" id="total-bar">Showing {total} of {total} assets</div>

        <!-- Changes Section -->
        <div style="margin-top: 2rem;">
            <h2 style="font-size: 1.1rem; font-weight: 600; margin-bottom: 0.75rem; color: #f1f5f9;">
                Recent Changes
                <button class="btn" onclick="loadChanges()" style="margin-left: 0.5rem; font-size: 0.7rem;">Refresh</button>
            </h2>
            <table id="changes-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>IP</th>
                        <th>Change Type</th>
                        <th>Field</th>
                        <th>Old Value</th>
                        <th>New Value</th>
                    </tr>
                </thead>
                <tbody id="changes-body">
                    <tr><td colspan="6" style="text-align:center; color:#64748b;">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>
    <script>
        let activeCategory = 'all';
        let searchTerm = '';

        function filterCategory(cat) {{
            activeCategory = cat;
            document.querySelectorAll('.card').forEach(c => c.classList.remove('active'));
            if (cat !== 'all') {{
                document.querySelector(`.card[data-category="${{cat}}"]`)?.classList.add('active');
            }}
            applyFilters();
        }}

        function searchAssets(term) {{
            searchTerm = term.toLowerCase();
            applyFilters();
        }}

        function applyFilters() {{
            const rows = document.querySelectorAll('#asset-table tr');
            let visible = 0;
            rows.forEach(row => {{
                const catMatch = activeCategory === 'all' || row.dataset.category === activeCategory;
                const text = row.textContent.toLowerCase();
                const searchMatch = !searchTerm || text.includes(searchTerm);
                if (catMatch && searchMatch) {{
                    row.classList.remove('hidden');
                    visible++;
                }} else {{
                    row.classList.add('hidden');
                }}
            }});
            document.getElementById('total-bar').textContent =
                `Showing ${{visible}} of {total} assets`;
        }}

        function sortTable(col) {{
            const tbody = document.getElementById('asset-table');
            const rows = Array.from(tbody.rows);
            const isNum = col === 6;
            rows.sort((a, b) => {{
                let va = a.cells[col].textContent.trim();
                let vb = b.cells[col].textContent.trim();
                if (isNum) return parseFloat(vb) - parseFloat(va);
                return va.localeCompare(vb);
            }});
            rows.forEach(r => tbody.appendChild(r));
        }}

        function exportJSON() {{
            fetch('/api/data').then(r => r.json()).then(data => {{
                const blob = new Blob([JSON.stringify(data, null, 2)], {{type: 'application/json'}});
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = 'bigr_assets.json';
                a.click();
            }});
        }}

        function exportCSV() {{
            fetch('/api/data').then(r => r.json()).then(data => {{
                const headers = ['ip','mac','hostname','vendor','open_ports','bigr_category','confidence_score','os_hint'];
                let csv = headers.join(',') + '\\n';
                (data.assets || []).forEach(a => {{
                    csv += headers.map(h => {{
                        let v = a[h];
                        if (Array.isArray(v)) v = v.join(';');
                        if (typeof v === 'string' && v.includes(',')) v = '"' + v + '"';
                        return v ?? '';
                    }}).join(',') + '\\n';
                }});
                const blob = new Blob([csv], {{type: 'text/csv'}});
                const el = document.createElement('a');
                el.href = URL.createObjectURL(blob);
                el.download = 'bigr_assets.csv';
                el.click();
            }});
        }}

        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.textContent;
        }}

        function loadChanges() {{
            fetch('/api/changes?limit=50').then(r => r.json()).then(data => {{
                const tbody = document.getElementById('changes-body');
                const changes = data.changes || [];
                // Clear existing rows
                while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
                if (changes.length === 0) {{
                    const row = document.createElement('tr');
                    const cell = document.createElement('td');
                    cell.colSpan = 6;
                    cell.style.textAlign = 'center';
                    cell.style.color = '#64748b';
                    cell.textContent = 'No changes recorded yet.';
                    row.appendChild(cell);
                    tbody.appendChild(row);
                    return;
                }}
                const badgeColors = {{
                    'new_asset': '#22c55e',
                    'field_changed': '#eab308',
                    'removed': '#ef4444'
                }};
                changes.forEach(c => {{
                    const tr = document.createElement('tr');
                    const ts = (c.detected_at || '-').substring(0, 19).replace('T', ' ');
                    const ct = c.change_type || '-';
                    const color = badgeColors[ct] || '#94a3b8';
                    const fieldVal = ct === 'new_asset' ? '-' : (c.field_name || '-');
                    const oldVal = ct === 'new_asset' ? '-' : (c.old_value || '-');
                    const newVal = ct === 'new_asset' ? '-' : (c.new_value || '-');

                    const tdTs = document.createElement('td');
                    tdTs.style.color = '#94a3b8';
                    tdTs.textContent = ts;
                    tr.appendChild(tdTs);

                    const tdIp = document.createElement('td');
                    tdIp.style.color = '#67e8f9';
                    tdIp.textContent = c.ip || '-';
                    tr.appendChild(tdIp);

                    const tdType = document.createElement('td');
                    const badge = document.createElement('span');
                    badge.className = 'badge';
                    badge.style.background = color;
                    badge.textContent = ct;
                    tdType.appendChild(badge);
                    tr.appendChild(tdType);

                    const tdField = document.createElement('td');
                    tdField.textContent = fieldVal;
                    tr.appendChild(tdField);

                    const tdOld = document.createElement('td');
                    tdOld.textContent = oldVal;
                    tr.appendChild(tdOld);

                    const tdNew = document.createElement('td');
                    tdNew.textContent = newVal;
                    tr.appendChild(tdNew);

                    tbody.appendChild(tr);
                }});
            }}).catch(() => {{
                const tbody = document.getElementById('changes-body');
                while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
                const row = document.createElement('tr');
                const cell = document.createElement('td');
                cell.colSpan = 6;
                cell.style.textAlign = 'center';
                cell.style.color = '#ef4444';
                cell.textContent = 'Failed to load changes.';
                row.appendChild(cell);
                tbody.appendChild(row);
            }});
        }}

        function filterSubnet(subnet) {{
            // Reload data filtered by subnet
            const url = subnet ? `/api/data?subnet=${{encodeURIComponent(subnet)}}` : '/api/data';
            fetch(url).then(r => r.json()).then(data => {{
                const tbody = document.getElementById('asset-table');
                while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
                (data.assets || []).forEach(a => {{
                    const tr = document.createElement('tr');
                    const conf = a.confidence_score || 0;
                    const confClass = conf >= 0.7 ? 'high' : conf >= 0.4 ? 'medium' : 'low';
                    const ports = (a.open_ports || []).join(', ') || '-';
                    const catKey = a.bigr_category || 'unclassified';
                    tr.dataset.category = catKey;
                    tr.innerHTML = `<td>${{a.ip || '-'}}</td>` +
                        `<td><code>${{a.mac || '-'}}</code></td>` +
                        `<td>${{a.hostname || '-'}}</td>` +
                        `<td>${{a.vendor || '-'}}</td>` +
                        `<td><code>${{ports}}</code></td>` +
                        `<td><span class="badge">${{a.bigr_category_tr || '-'}}</span></td>` +
                        `<td><span class="conf conf-${{confClass}}">${{conf.toFixed(2)}}</span></td>` +
                        `<td>${{a.os_hint || '-'}}</td>`;
                    tbody.appendChild(tr);
                }});
                document.getElementById('total-bar').textContent =
                    `Showing ${{data.assets?.length || 0}} of {total} assets`;
            }});
        }}

        function loadSubnets() {{
            fetch('/api/subnets').then(r => r.json()).then(data => {{
                const sel = document.getElementById('subnet-filter');
                (data.subnets || []).forEach(s => {{
                    const opt = document.createElement('option');
                    opt.value = s.cidr;
                    opt.textContent = s.label ? `${{s.cidr}} (${{s.label}})` : s.cidr;
                    sel.appendChild(opt);
                }});
            }}).catch(() => {{}});
        }}

        // Auto-load changes and subnets on page load
        loadChanges();
        loadSubnets();
    </script>
</body>
</html>"""


def _render_topology_page() -> str:
    """Render the D3.js network topology visualization page."""
    return """<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BIGR Discovery - Network Topology</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
            overflow: hidden;
        }
        .header {
            background: #1e293b;
            border-bottom: 1px solid #334155;
            padding: 0.75rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            z-index: 10;
            position: relative;
        }
        .header h1 { font-size: 1.1rem; font-weight: 600; color: #f1f5f9; }
        .header-left { display: flex; align-items: center; gap: 1rem; }
        .btn {
            background: #334155;
            color: #e2e8f0;
            border: 1px solid #475569;
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.75rem;
            transition: background 0.15s;
            text-decoration: none;
        }
        .btn:hover { background: #475569; }
        .btn-primary { background: #3b82f6; border-color: #3b82f6; }
        .btn-primary:hover { background: #2563eb; }
        #topology-container {
            width: 100%;
            height: calc(100vh - 52px);
            position: relative;
        }
        svg { width: 100%; height: 100%; }
        .node-label {
            font-size: 10px;
            fill: #94a3b8;
            pointer-events: none;
            text-anchor: middle;
        }
        .edge-line {
            stroke: #334155;
            stroke-opacity: 0.6;
        }
        .edge-line.gateway { stroke: #60a5fa; stroke-width: 2; }
        .edge-line.switch { stroke: #a78bfa; stroke-width: 1.5; stroke-dasharray: 4; }
        .edge-line.subnet { stroke: #475569; stroke-width: 1; }
        .tooltip {
            position: absolute;
            background: #1e293b;
            border: 1px solid #475569;
            border-radius: 8px;
            padding: 0.75rem 1rem;
            font-size: 0.8rem;
            color: #e2e8f0;
            pointer-events: none;
            z-index: 100;
            max-width: 300px;
            display: none;
            box-shadow: 0 4px 12px rgba(0,0,0,0.4);
        }
        .tooltip .tip-row { margin: 0.2rem 0; }
        .tooltip .tip-label { color: #94a3b8; margin-right: 0.3rem; }
        .legend {
            position: absolute;
            bottom: 1.5rem;
            left: 1.5rem;
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 0.75rem 1rem;
            z-index: 10;
        }
        .legend h3 { font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.05em; }
        .legend-item { display: flex; align-items: center; gap: 0.5rem; margin: 0.3rem 0; font-size: 0.75rem; }
        .legend-dot { width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }
        .stats-bar {
            position: absolute;
            top: 0.75rem;
            right: 1.5rem;
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 0.5rem 1rem;
            z-index: 10;
            font-size: 0.75rem;
            color: #94a3b8;
        }
        .stats-bar span { margin-left: 1rem; color: #e2e8f0; font-weight: 600; }
        .highlight-ring {
            fill: none;
            stroke: #fbbf24;
            stroke-width: 3;
            stroke-opacity: 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-left">
            <h1>Network Topology</h1>
            <a href="/" class="btn">Dashboard</a>
        </div>
        <div>
            <button class="btn" onclick="resetZoom()">Reset View</button>
            <button class="btn" onclick="toggleLabels()">Toggle Labels</button>
        </div>
    </div>
    <div id="topology-container">
        <svg id="topology-svg"></svg>
        <div class="tooltip" id="tooltip"></div>
        <div class="legend" id="legend">
            <h3>BIGR Categories</h3>
            <div class="legend-item"><div class="legend-dot" style="background:#3b82f6"></div> Ag ve Sistemler</div>
            <div class="legend-item"><div class="legend-dot" style="background:#8b5cf6"></div> Uygulamalar</div>
            <div class="legend-item"><div class="legend-dot" style="background:#10b981"></div> IoT</div>
            <div class="legend-item"><div class="legend-dot" style="background:#f59e0b"></div> Tasinabilir</div>
            <div class="legend-item"><div class="legend-dot" style="background:#6b7280"></div> Unclassified</div>
            <h3 style="margin-top:0.75rem;">Node Types</h3>
            <div class="legend-item"><div class="legend-dot" style="background:#60a5fa;width:18px;height:18px;"></div> Gateway</div>
            <div class="legend-item"><div class="legend-dot" style="background:#a78bfa;width:15px;height:15px;border-radius:3px;"></div> Switch</div>
            <div class="legend-item"><div class="legend-dot" style="background:#334155;width:14px;height:14px;border-radius:3px;"></div> Subnet</div>
        </div>
        <div class="stats-bar" id="stats-bar">Loading...</div>
    </div>
    <script>
    (function() {
        const width = window.innerWidth;
        const height = window.innerHeight - 52;
        let showLabels = true;

        const svg = d3.select('#topology-svg');
        const g = svg.append('g');

        // Zoom
        const zoom = d3.zoom()
            .scaleExtent([0.1, 8])
            .on('zoom', (event) => g.attr('transform', event.transform));
        svg.call(zoom);

        window.resetZoom = function() {
            svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
        };

        window.toggleLabels = function() {
            showLabels = !showLabels;
            g.selectAll('.node-label').style('display', showLabels ? 'block' : 'none');
        };

        const tooltip = d3.select('#tooltip');

        fetch('/api/topology')
            .then(r => r.json())
            .then(data => {
                // Update stats
                const stats = data.stats || {};
                document.getElementById('stats-bar').innerHTML =
                    'Nodes: <span>' + stats.total_nodes + '</span>' +
                    'Edges: <span>' + stats.total_edges + '</span>';

                if (!data.nodes || data.nodes.length === 0) {
                    document.getElementById('stats-bar').innerHTML = 'No topology data available.';
                    return;
                }

                // Build simulation
                const simulation = d3.forceSimulation(data.nodes)
                    .force('link', d3.forceLink(data.edges).id(d => d.id).distance(d => {
                        if (d.type === 'gateway') return 60;
                        if (d.type === 'switch') return 80;
                        return 100;
                    }))
                    .force('charge', d3.forceManyBody().strength(-200))
                    .force('center', d3.forceCenter(width / 2, height / 2))
                    .force('collision', d3.forceCollide().radius(d => (d.size || 10) + 5));

                // Draw edges
                const link = g.append('g')
                    .selectAll('line')
                    .data(data.edges)
                    .join('line')
                    .attr('class', d => 'edge-line ' + (d.type || ''));

                // Draw nodes
                const node = g.append('g')
                    .selectAll('g')
                    .data(data.nodes)
                    .join('g')
                    .call(d3.drag()
                        .on('start', dragStarted)
                        .on('drag', dragged)
                        .on('end', dragEnded));

                // Highlight ring (hidden by default)
                node.append('circle')
                    .attr('class', 'highlight-ring')
                    .attr('r', d => (d.size || 10) + 5);

                // Node shape depends on type
                node.each(function(d) {
                    const el = d3.select(this);
                    if (d.type === 'subnet') {
                        el.append('rect')
                            .attr('width', d.size * 2)
                            .attr('height', d.size)
                            .attr('x', -d.size)
                            .attr('y', -d.size / 2)
                            .attr('rx', 4)
                            .attr('fill', d.color || '#334155')
                            .attr('stroke', '#475569')
                            .attr('stroke-width', 1);
                    } else {
                        el.append('circle')
                            .attr('r', d.size || 10)
                            .attr('fill', d.color || '#6b7280')
                            .attr('stroke', d.type === 'gateway' ? '#93c5fd' : '#475569')
                            .attr('stroke-width', d.type === 'gateway' ? 2 : 1);
                    }
                });

                // Labels
                node.append('text')
                    .attr('class', 'node-label')
                    .attr('dy', d => (d.size || 10) + 14)
                    .text(d => d.label || d.id);

                // Tooltip
                node.on('mouseover', function(event, d) {
                    let html = '<div class="tip-row"><span class="tip-label">ID:</span>' + d.id + '</div>';
                    if (d.ip) html += '<div class="tip-row"><span class="tip-label">IP:</span>' + d.ip + '</div>';
                    if (d.hostname) html += '<div class="tip-row"><span class="tip-label">Host:</span>' + d.hostname + '</div>';
                    if (d.vendor) html += '<div class="tip-row"><span class="tip-label">Vendor:</span>' + d.vendor + '</div>';
                    if (d.mac) html += '<div class="tip-row"><span class="tip-label">MAC:</span>' + d.mac + '</div>';
                    html += '<div class="tip-row"><span class="tip-label">Type:</span>' + d.type + '</div>';
                    html += '<div class="tip-row"><span class="tip-label">Category:</span>' + d.bigr_category + '</div>';
                    if (d.open_ports && d.open_ports.length > 0) {
                        html += '<div class="tip-row"><span class="tip-label">Ports:</span>' + d.open_ports.join(', ') + '</div>';
                    }
                    if (d.confidence > 0) {
                        html += '<div class="tip-row"><span class="tip-label">Confidence:</span>' + d.confidence.toFixed(2) + '</div>';
                    }
                    tooltip.html(html)
                        .style('display', 'block')
                        .style('left', (event.pageX + 15) + 'px')
                        .style('top', (event.pageY - 10) + 'px');
                })
                .on('mousemove', function(event) {
                    tooltip.style('left', (event.pageX + 15) + 'px')
                        .style('top', (event.pageY - 10) + 'px');
                })
                .on('mouseout', function() {
                    tooltip.style('display', 'none');
                });

                // Click to highlight connected nodes
                node.on('click', function(event, d) {
                    // Reset all highlights
                    g.selectAll('.highlight-ring').attr('stroke-opacity', 0);
                    link.attr('stroke-opacity', 0.2);

                    // Find connected node IDs
                    const connectedIds = new Set();
                    connectedIds.add(d.id);
                    data.edges.forEach(e => {
                        const src = typeof e.source === 'object' ? e.source.id : e.source;
                        const tgt = typeof e.target === 'object' ? e.target.id : e.target;
                        if (src === d.id) connectedIds.add(tgt);
                        if (tgt === d.id) connectedIds.add(src);
                    });

                    // Highlight connected
                    g.selectAll('.highlight-ring')
                        .attr('stroke-opacity', function(n) {
                            return connectedIds.has(n.id) ? 0.8 : 0;
                        });
                    link.attr('stroke-opacity', function(e) {
                        const src = typeof e.source === 'object' ? e.source.id : e.source;
                        const tgt = typeof e.target === 'object' ? e.target.id : e.target;
                        return (src === d.id || tgt === d.id) ? 1 : 0.1;
                    });
                });

                // Click background to reset
                svg.on('click', function(event) {
                    if (event.target.tagName === 'svg' || event.target === svg.node()) {
                        g.selectAll('.highlight-ring').attr('stroke-opacity', 0);
                        link.attr('stroke-opacity', 0.6);
                    }
                });

                // Simulation tick
                simulation.on('tick', () => {
                    link
                        .attr('x1', d => d.source.x)
                        .attr('y1', d => d.source.y)
                        .attr('x2', d => d.target.x)
                        .attr('y2', d => d.target.y);
                    node.attr('transform', d => `translate(${d.x},${d.y})`);
                });

                function dragStarted(event, d) {
                    if (!event.active) simulation.alphaTarget(0.3).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                }
                function dragged(event, d) {
                    d.fx = event.x;
                    d.fy = event.y;
                }
                function dragEnded(event, d) {
                    if (!event.active) simulation.alphaTarget(0);
                    d.fx = null;
                    d.fy = null;
                }
            })
            .catch(err => {
                document.getElementById('stats-bar').innerHTML =
                    '<span style="color:#ef4444;">Failed to load topology data.</span>';
                console.error('Topology load error:', err);
            });
    })();
    </script>
</body>
</html>"""


def _render_compliance_page(report) -> str:
    """Render the BİGR Compliance Dashboard page."""
    score = report.breakdown.compliance_score
    grade = report.breakdown.grade
    b = report.breakdown
    dist = report.distribution

    grade_colors = {"A": "#22c55e", "B": "#3b82f6", "C": "#eab308", "D": "#f97316", "F": "#ef4444"}
    grade_color = grade_colors.get(grade, "#6b7280")

    # Build category distribution bars
    pct = dist.percentages()
    category_info = {
        "ag_ve_sistemler": {"label": "Ag ve Sistemler", "color": "#3b82f6"},
        "uygulamalar": {"label": "Uygulamalar", "color": "#8b5cf6"},
        "iot": {"label": "IoT", "color": "#10b981"},
        "tasinabilir": {"label": "Tasinabilir", "color": "#f59e0b"},
        "unclassified": {"label": "Siniflandirilmamis", "color": "#6b7280"},
    }

    dist_bars_html = ""
    for key, info in category_info.items():
        count = getattr(dist, key)
        percentage = pct.get(key, 0)
        if count > 0 or key == "unclassified":
            dist_bars_html += f"""
            <div class="dist-row">
                <span class="dist-label">{info['label']}</span>
                <div class="dist-bar-bg">
                    <div class="dist-bar" style="width:{percentage}%;background:{info['color']}"></div>
                </div>
                <span class="dist-count">{count} ({percentage}%)</span>
            </div>"""

    # Build subnet table rows
    subnet_rows = ""
    for sc in report.subnet_compliance:
        sc_color = grade_colors.get(sc.breakdown.grade, "#6b7280")
        subnet_rows += f"""
            <tr>
                <td>{sc.cidr}</td>
                <td>{sc.label or '-'}</td>
                <td style="color:{sc_color};font-weight:600;">{sc.breakdown.compliance_score}%</td>
                <td style="color:{sc_color};font-weight:600;">{sc.breakdown.grade}</td>
                <td>{sc.breakdown.total_assets}</td>
            </tr>"""

    subnet_section = ""
    if report.subnet_compliance:
        subnet_section = f"""
        <div class="section">
            <h2>Subnet Compliance</h2>
            <table>
                <thead>
                    <tr>
                        <th>CIDR</th>
                        <th>Label</th>
                        <th>Score</th>
                        <th>Grade</th>
                        <th>Assets</th>
                    </tr>
                </thead>
                <tbody>{subnet_rows}</tbody>
            </table>
        </div>"""

    # Build action items
    action_rows = ""
    pri_colors_map = {"critical": "#ef4444", "high": "#f97316", "normal": "#94a3b8"}
    for item in report.action_items[:30]:
        pri = item.get("priority", "normal")
        pri_color = pri_colors_map.get(pri, "#94a3b8")
        action_rows += f"""
            <tr>
                <td><span class="priority-badge" style="background:{pri_color}">{pri}</span></td>
                <td>{item.get('type', '-')}</td>
                <td style="color:#67e8f9;">{item.get('ip', '-')}</td>
                <td>{item.get('reason', '-')}</td>
            </tr>"""

    action_section = ""
    if report.action_items:
        action_section = f"""
        <div class="section">
            <h2>Action Items ({len(report.action_items)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Type</th>
                        <th>IP</th>
                        <th>Reason</th>
                    </tr>
                </thead>
                <tbody>{action_rows}</tbody>
            </table>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BIGR Compliance Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }}
        .header {{
            background: #1e293b;
            border-bottom: 1px solid #334155;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{ font-size: 1.25rem; font-weight: 600; color: #f1f5f9; }}
        .btn {{
            background: #334155; color: #e2e8f0; border: 1px solid #475569;
            padding: 0.4rem 0.8rem; border-radius: 6px; cursor: pointer;
            font-size: 0.75rem; text-decoration: none; transition: background 0.15s;
        }}
        .btn:hover {{ background: #475569; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 1.5rem; }}
        .score-gauge {{
            text-align: center; padding: 2rem; margin-bottom: 1.5rem;
            background: #1e293b; border-radius: 12px; border: 1px solid #334155;
        }}
        .score-value {{
            font-size: 4rem; font-weight: 800; color: {grade_color};
        }}
        .score-grade {{
            font-size: 2rem; font-weight: 700; color: {grade_color};
            margin-top: 0.25rem;
        }}
        .score-label {{ color: #94a3b8; margin-top: 0.5rem; }}
        .cards {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem; margin-bottom: 1.5rem;
        }}
        .card {{
            background: #1e293b; border-radius: 8px; padding: 1.25rem;
            text-align: center; border: 1px solid #334155;
        }}
        .card-count {{ font-size: 2rem; font-weight: 700; color: #f1f5f9; }}
        .card-label {{ font-size: 0.8rem; color: #94a3b8; margin-top: 0.25rem; }}
        .section {{
            background: #1e293b; border-radius: 8px; padding: 1.25rem;
            margin-bottom: 1.5rem; border: 1px solid #334155;
        }}
        .section h2 {{ font-size: 1rem; font-weight: 600; margin-bottom: 1rem; color: #f1f5f9; }}
        .dist-row {{ display: flex; align-items: center; gap: 0.75rem; margin: 0.5rem 0; }}
        .dist-label {{ width: 150px; font-size: 0.8rem; color: #94a3b8; text-align: right; }}
        .dist-bar-bg {{
            flex: 1; height: 20px; background: #0f172a; border-radius: 4px; overflow: hidden;
        }}
        .dist-bar {{ height: 100%; border-radius: 4px; transition: width 0.5s; }}
        .dist-count {{ width: 100px; font-size: 0.8rem; color: #e2e8f0; }}
        table {{
            width: 100%; border-collapse: collapse; background: #1e293b;
            border-radius: 8px; overflow: hidden;
        }}
        th {{
            background: #0f172a; padding: 0.6rem 0.8rem; text-align: left;
            font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em;
            color: #94a3b8; border-bottom: 1px solid #334155;
        }}
        td {{ padding: 0.5rem 0.8rem; border-bottom: 1px solid #1e293b; font-size: 0.8rem; }}
        tr:hover {{ background: #334155; }}
        .priority-badge {{
            display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
            font-size: 0.7rem; font-weight: 600; color: #fff;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div style="display:flex;align-items:center;gap:1rem;">
            <h1>BIGR Compliance Dashboard</h1>
            <a href="/" class="btn">Asset Dashboard</a>
            <a href="/topology" class="btn">Topology Map</a>
        </div>
    </div>
    <div class="container">
        <div class="score-gauge">
            <div class="score-value">{score}%</div>
            <div class="score-grade">Grade: {grade}</div>
            <div class="score-label">BİGR Compliance Score</div>
        </div>

        <div class="cards">
            <div class="card" style="border-top: 3px solid #22c55e;">
                <div class="card-count">{b.fully_classified}</div>
                <div class="card-label">Fully Classified</div>
            </div>
            <div class="card" style="border-top: 3px solid #eab308;">
                <div class="card-count">{b.partially_classified}</div>
                <div class="card-label">Partially Classified</div>
            </div>
            <div class="card" style="border-top: 3px solid #ef4444;">
                <div class="card-count">{b.unclassified}</div>
                <div class="card-label">Unclassified</div>
            </div>
            <div class="card" style="border-top: 3px solid #06b6d4;">
                <div class="card-count">{b.manual_overrides}</div>
                <div class="card-label">Manual Overrides</div>
            </div>
        </div>

        <div class="section">
            <h2>Category Distribution</h2>
            {dist_bars_html}
        </div>

        {subnet_section}
        {action_section}
    </div>
</body>
</html>"""


def _render_analytics_page() -> str:
    """Render the analytics dashboard page with trend charts."""
    return """<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BIGR Discovery - Analytics</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }
        .header {
            background: #1e293b;
            border-bottom: 1px solid #334155;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { font-size: 1.25rem; font-weight: 600; color: #f1f5f9; }
        .header-left { display: flex; align-items: center; gap: 1rem; }
        .btn {
            background: #334155; color: #e2e8f0; border: 1px solid #475569;
            padding: 0.4rem 0.8rem; border-radius: 6px; cursor: pointer;
            font-size: 0.75rem; transition: background 0.15s; text-decoration: none;
        }
        .btn:hover { background: #475569; }
        .btn.active { background: #3b82f6; border-color: #3b82f6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 1.5rem; }
        .range-selector { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; }
        .section {
            background: #1e293b; border-radius: 8px; padding: 1.25rem;
            margin-bottom: 1.5rem; border: 1px solid #334155;
        }
        .section h2 { font-size: 1rem; font-weight: 600; margin-bottom: 1rem; color: #f1f5f9; }
        .chart-area { width: 100%; overflow-x: auto; }
        .bar-chart { display: flex; align-items: flex-end; gap: 4px; height: 180px; padding: 0 0.5rem; }
        .bar-wrapper { display: flex; flex-direction: column; align-items: center; flex: 1; min-width: 24px; }
        .bar {
            width: 100%; min-width: 16px; background: #3b82f6; border-radius: 3px 3px 0 0;
            transition: height 0.3s;
        }
        .bar-label { font-size: 0.6rem; color: #94a3b8; margin-top: 4px; text-align: center; white-space: nowrap; }
        .bar-value { font-size: 0.65rem; color: #e2e8f0; margin-bottom: 2px; }
        table { width: 100%; border-collapse: collapse; }
        th {
            background: #0f172a; padding: 0.5rem 0.75rem; text-align: left;
            font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em;
            color: #94a3b8; border-bottom: 1px solid #334155;
        }
        td { padding: 0.5rem 0.75rem; border-bottom: 1px solid #1e293b; font-size: 0.8rem; }
        tr:hover { background: #334155; }
        .badge {
            display: inline-block; padding: 0.15rem 0.4rem; border-radius: 3px;
            font-size: 0.7rem; font-weight: 500;
        }
        .loading { text-align: center; color: #64748b; padding: 2rem; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
        @media (max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-left">
            <h1>Analytics &amp; Trends</h1>
            <a href="/" class="btn">Dashboard</a>
            <a href="/topology" class="btn">Topology</a>
        </div>
    </div>
    <div class="container">
        <div class="range-selector">
            <button class="btn" onclick="loadData(7)" id="btn-7">7 Days</button>
            <button class="btn active" onclick="loadData(30)" id="btn-30">30 Days</button>
            <button class="btn" onclick="loadData(90)" id="btn-90">90 Days</button>
        </div>

        <div class="section">
            <h2>Asset Count Trend</h2>
            <div class="chart-area" id="asset-chart"><div class="loading">Loading...</div></div>
        </div>

        <div class="grid-2">
            <div class="section">
                <h2>Category Trends</h2>
                <div id="category-chart"><div class="loading">Loading...</div></div>
            </div>
            <div class="section">
                <h2>New vs Removed Devices</h2>
                <div id="new-removed-chart"><div class="loading">Loading...</div></div>
            </div>
        </div>

        <div class="grid-2">
            <div class="section">
                <h2>Most Changed Assets</h2>
                <div id="changed-table"><div class="loading">Loading...</div></div>
            </div>
            <div class="section">
                <h2>Scan Frequency</h2>
                <div id="scan-freq"><div class="loading">Loading...</div></div>
            </div>
        </div>
    </div>
    <script>
    let currentDays = 30;
    const catColors = {
        'ag_ve_sistemler': '#3b82f6',
        'uygulamalar': '#8b5cf6',
        'iot': '#10b981',
        'tasinabilir': '#f59e0b',
        'unclassified': '#6b7280'
    };

    function loadData(days) {
        currentDays = days;
        document.querySelectorAll('.range-selector .btn').forEach(b => b.classList.remove('active'));
        document.getElementById('btn-' + days).classList.add('active');

        fetch('/api/analytics?days=' + days)
            .then(r => r.json())
            .then(data => {
                renderAssetChart(data.asset_count_trend);
                renderCategoryChart(data.category_trends);
                renderNewRemoved(data.new_vs_removed);
                renderChangedTable(data.most_changed_assets);
                renderScanFreq(data.scan_frequency);
            })
            .catch(() => {
                document.getElementById('asset-chart').innerHTML = '<div class="loading">Failed to load data.</div>';
            });
    }

    function renderBarChart(containerId, points, color) {
        const el = document.getElementById(containerId);
        if (!points || points.length === 0) {
            el.innerHTML = '<div class="loading">No data available.</div>';
            return;
        }
        const maxVal = Math.max(...points.map(p => p.value), 1);
        let html = '<div class="bar-chart">';
        points.forEach(p => {
            const h = Math.max((p.value / maxVal) * 160, 2);
            const dateLabel = p.date ? p.date.substring(5) : '';
            html += '<div class="bar-wrapper">' +
                '<div class="bar-value">' + p.value + '</div>' +
                '<div class="bar" style="height:' + h + 'px;background:' + color + '"></div>' +
                '<div class="bar-label">' + dateLabel + '</div></div>';
        });
        html += '</div>';
        el.innerHTML = html;
    }

    function renderAssetChart(trend) {
        renderBarChart('asset-chart', trend ? trend.points : [], '#3b82f6');
    }

    function renderCategoryChart(trends) {
        const el = document.getElementById('category-chart');
        if (!trends || trends.length === 0) {
            el.innerHTML = '<div class="loading">No data.</div>';
            return;
        }
        let html = '<table><thead><tr><th>Category</th><th>Total</th></tr></thead><tbody>';
        trends.forEach(s => {
            const total = s.points.reduce((a, p) => a + p.value, 0);
            const color = catColors[s.name] || '#6b7280';
            html += '<tr><td><span class="badge" style="background:' + color + '">' + s.name + '</span></td>' +
                '<td>' + total + '</td></tr>';
        });
        html += '</tbody></table>';
        el.innerHTML = html;
    }

    function renderNewRemoved(trend) {
        renderBarChart('new-removed-chart', trend ? trend.points : [], '#22c55e');
    }

    function renderChangedTable(assets) {
        const el = document.getElementById('changed-table');
        if (!assets || assets.length === 0) {
            el.innerHTML = '<div class="loading">No changes recorded.</div>';
            return;
        }
        let html = '<table><thead><tr><th>IP</th><th>Changes</th><th>Last Change</th></tr></thead><tbody>';
        assets.forEach(a => {
            const lc = (a.last_change || '-').substring(0, 19).replace('T', ' ');
            html += '<tr><td style="color:#67e8f9">' + a.ip + '</td>' +
                '<td>' + a.change_count + '</td><td style="color:#94a3b8">' + lc + '</td></tr>';
        });
        html += '</tbody></table>';
        el.innerHTML = html;
    }

    function renderScanFreq(freq) {
        const el = document.getElementById('scan-freq');
        if (!freq || freq.length === 0) {
            el.innerHTML = '<div class="loading">No scan data.</div>';
            return;
        }
        let html = '<table><thead><tr><th>Date</th><th>Scans</th><th>Assets</th></tr></thead><tbody>';
        freq.forEach(f => {
            html += '<tr><td>' + f.date + '</td><td>' + f.scan_count + '</td>' +
                '<td>' + (f.total_assets || 0) + '</td></tr>';
        });
        html += '</tbody></table>';
        el.innerHTML = html;
    }

    // Load initial data
    loadData(30);
    </script>
</body>
</html>"""


def _render_risk_page(report) -> str:
    """Render the Risk Assessment Dashboard page."""
    from bigr.risk.models import RiskReport

    avg = report.average_risk
    mx = report.max_risk

    # Gauge color based on average risk
    if avg >= 8.0:
        gauge_color = "#ef4444"
    elif avg >= 6.0:
        gauge_color = "#f97316"
    elif avg >= 4.0:
        gauge_color = "#eab308"
    else:
        gauge_color = "#22c55e"

    # Build top 10 rows
    level_colors = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#22c55e",
        "info": "#94a3b8",
    }

    top_rows = ""
    for p in report.top_risks:
        lvl_color = level_colors.get(p.risk_level, "#94a3b8")
        top_rows += f"""
            <tr>
                <td style="color:#67e8f9;">{p.ip}</td>
                <td>{p.vendor or '-'}</td>
                <td>{p.bigr_category}</td>
                <td style="font-weight:700;">{p.risk_score:.1f}</td>
                <td><span class="risk-badge" style="background:{lvl_color}">{p.risk_level.upper()}</span></td>
                <td>{p.top_cve or '-'}</td>
            </tr>"""

    # Category risk comparison
    category_scores: dict[str, list[float]] = {}
    for p in report.profiles:
        cat = p.bigr_category
        category_scores.setdefault(cat, []).append(p.risk_score)

    cat_colors = {
        "ag_ve_sistemler": "#3b82f6",
        "uygulamalar": "#8b5cf6",
        "iot": "#10b981",
        "tasinabilir": "#f59e0b",
        "unclassified": "#6b7280",
    }

    cat_bars = ""
    max_cat_avg = 10.0
    for cat, scores in sorted(category_scores.items()):
        cat_avg = sum(scores) / len(scores)
        pct = (cat_avg / max_cat_avg) * 100
        color = cat_colors.get(cat, "#6b7280")
        cat_bars += f"""
            <div class="dist-row">
                <span class="dist-label">{cat}</span>
                <div class="dist-bar-bg">
                    <div class="dist-bar" style="width:{pct}%;background:{color}"></div>
                </div>
                <span class="dist-count">{cat_avg:.1f} avg ({len(scores)} assets)</span>
            </div>"""

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BIGR Discovery - Risk Assessment</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }}
        .header {{
            background: #1e293b;
            border-bottom: 1px solid #334155;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{ font-size: 1.25rem; font-weight: 600; color: #f1f5f9; }}
        .btn {{
            background: #334155; color: #e2e8f0; border: 1px solid #475569;
            padding: 0.4rem 0.8rem; border-radius: 6px; cursor: pointer;
            font-size: 0.75rem; text-decoration: none; transition: background 0.15s;
        }}
        .btn:hover {{ background: #475569; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 1.5rem; }}
        .score-gauge {{
            text-align: center; padding: 2rem; margin-bottom: 1.5rem;
            background: #1e293b; border-radius: 12px; border: 1px solid #334155;
        }}
        .score-value {{
            font-size: 4rem; font-weight: 800; color: {gauge_color};
        }}
        .score-label {{ color: #94a3b8; margin-top: 0.5rem; }}
        .cards {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem; margin-bottom: 1.5rem;
        }}
        .card {{
            background: #1e293b; border-radius: 8px; padding: 1.25rem;
            text-align: center; border: 1px solid #334155;
        }}
        .card-count {{ font-size: 2rem; font-weight: 700; color: #f1f5f9; }}
        .card-label {{ font-size: 0.8rem; color: #94a3b8; margin-top: 0.25rem; }}
        .section {{
            background: #1e293b; border-radius: 8px; padding: 1.25rem;
            margin-bottom: 1.5rem; border: 1px solid #334155;
        }}
        .section h2 {{ font-size: 1rem; font-weight: 600; margin-bottom: 1rem; color: #f1f5f9; }}
        table {{
            width: 100%; border-collapse: collapse; background: #1e293b;
            border-radius: 8px; overflow: hidden;
        }}
        th {{
            background: #0f172a; padding: 0.6rem 0.8rem; text-align: left;
            font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em;
            color: #94a3b8; border-bottom: 1px solid #334155;
        }}
        td {{ padding: 0.5rem 0.8rem; border-bottom: 1px solid #1e293b; font-size: 0.8rem; }}
        tr:hover {{ background: #334155; }}
        .risk-badge {{
            display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
            font-size: 0.7rem; font-weight: 600; color: #fff;
        }}
        .dist-row {{ display: flex; align-items: center; gap: 0.75rem; margin: 0.5rem 0; }}
        .dist-label {{ width: 150px; font-size: 0.8rem; color: #94a3b8; text-align: right; }}
        .dist-bar-bg {{
            flex: 1; height: 20px; background: #0f172a; border-radius: 4px; overflow: hidden;
        }}
        .dist-bar {{ height: 100%; border-radius: 4px; transition: width 0.5s; }}
        .dist-count {{ width: 180px; font-size: 0.8rem; color: #e2e8f0; }}
    </style>
</head>
<body>
    <div class="header">
        <div style="display:flex;align-items:center;gap:1rem;">
            <h1>Risk Assessment Dashboard</h1>
            <a href="/" class="btn">Asset Dashboard</a>
            <a href="/topology" class="btn">Topology</a>
            <a href="/compliance" class="btn">Compliance</a>
        </div>
    </div>
    <div class="container">
        <div class="score-gauge">
            <div class="score-value">{avg:.1f}</div>
            <div class="score-label">Network Average Risk Score (Max: {mx:.1f})</div>
        </div>

        <div class="cards">
            <div class="card" style="border-top: 3px solid #ef4444;">
                <div class="card-count">{report.critical_count}</div>
                <div class="card-label">Critical</div>
            </div>
            <div class="card" style="border-top: 3px solid #f97316;">
                <div class="card-count">{report.high_count}</div>
                <div class="card-label">High</div>
            </div>
            <div class="card" style="border-top: 3px solid #eab308;">
                <div class="card-count">{report.medium_count}</div>
                <div class="card-label">Medium</div>
            </div>
            <div class="card" style="border-top: 3px solid #22c55e;">
                <div class="card-count">{report.low_count}</div>
                <div class="card-label">Low</div>
            </div>
        </div>

        <div class="section">
            <h2>Top 10 Riskiest Assets</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Vendor</th>
                        <th>Category</th>
                        <th>Risk Score</th>
                        <th>Risk Level</th>
                        <th>Top CVE</th>
                    </tr>
                </thead>
                <tbody>{top_rows}</tbody>
            </table>
        </div>

        <div class="section">
            <h2>Category Risk Comparison</h2>
            {cat_bars}
        </div>
    </div>
</body>
</html>"""


def _render_vulnerabilities_page() -> str:
    """Render the vulnerability scanning dashboard page."""
    return """<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BIGR Discovery - Vulnerabilities</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: #0f172a; color: #e2e8f0; min-height: 100vh;
        }
        .header {
            background: #1e293b; border-bottom: 1px solid #334155;
            padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center;
        }
        .header h1 { font-size: 1.25rem; font-weight: 600; color: #f1f5f9; }
        .header-left { display: flex; align-items: center; gap: 1rem; }
        .btn {
            background: #334155; color: #e2e8f0; border: 1px solid #475569;
            padding: 0.4rem 0.8rem; border-radius: 6px; cursor: pointer;
            font-size: 0.75rem; text-decoration: none; transition: background 0.15s;
        }
        .btn:hover { background: #475569; }
        .container { max-width: 1400px; margin: 0 auto; padding: 1.5rem; }
        .cards {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem; margin-bottom: 1.5rem;
        }
        .card {
            background: #1e293b; border-radius: 8px; padding: 1.25rem;
            text-align: center; border: 1px solid #334155;
        }
        .card-count { font-size: 2rem; font-weight: 700; color: #f1f5f9; }
        .card-label { font-size: 0.8rem; color: #94a3b8; margin-top: 0.25rem; }
        .section {
            background: #1e293b; border-radius: 8px; padding: 1.25rem;
            margin-bottom: 1.5rem; border: 1px solid #334155;
        }
        .section h2 { font-size: 1rem; font-weight: 600; margin-bottom: 1rem; color: #f1f5f9; }
        table { width: 100%; border-collapse: collapse; }
        th {
            background: #0f172a; padding: 0.6rem 0.8rem; text-align: left;
            font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em;
            color: #94a3b8; border-bottom: 1px solid #334155;
        }
        td { padding: 0.5rem 0.8rem; border-bottom: 1px solid #1e293b; font-size: 0.8rem; }
        tr:hover { background: #334155; }
        .badge {
            display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
            font-size: 0.7rem; font-weight: 600; color: #fff;
        }
        .sev-critical { background: #dc2626; }
        .sev-high { background: #ea580c; }
        .sev-medium { background: #ca8a04; }
        .sev-low { background: #6b7280; }
        .loading { text-align: center; color: #64748b; padding: 2rem; }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-left">
            <h1>Vulnerability Scanner</h1>
            <a href="/" class="btn">Dashboard</a>
            <a href="/risk" class="btn">Risk</a>
        </div>
    </div>
    <div class="container">
        <div class="cards" id="stats-cards">
            <div class="card"><div class="card-count" id="total-scanned">-</div><div class="card-label">Assets Scanned</div></div>
            <div class="card" style="border-top:3px solid #dc2626"><div class="card-count" id="total-vulnerable">-</div><div class="card-label">Vulnerable Assets</div></div>
            <div class="card"><div class="card-count" id="total-cves">-</div><div class="card-label">CVEs in Database</div></div>
        </div>
        <div class="section">
            <h2>Vulnerable Assets</h2>
            <div id="vuln-table"><div class="loading">Loading vulnerability data...</div></div>
        </div>
    </div>
    <script>
    fetch('/api/vulnerabilities')
        .then(r => r.json())
        .then(data => {
            document.getElementById('total-scanned').textContent = data.total_assets_scanned || 0;
            document.getElementById('total-vulnerable').textContent = data.total_vulnerable || 0;
            document.getElementById('total-cves').textContent = (data.cve_db_stats || {}).total || 0;

            const summaries = data.summaries || [];
            const el = document.getElementById('vuln-table');
            if (summaries.length === 0) {
                el.innerHTML = '<div class="loading">No vulnerabilities detected.</div>';
                return;
            }
            let html = '<table><thead><tr><th>IP</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Max CVSS</th></tr></thead><tbody>';
            summaries.forEach(s => {
                html += '<tr><td style="color:#67e8f9">' + s.ip + '</td>'
                    + '<td>' + s.total_vulns + '</td>'
                    + '<td><span class="badge sev-critical">' + s.critical_count + '</span></td>'
                    + '<td><span class="badge sev-high">' + s.high_count + '</span></td>'
                    + '<td><span class="badge sev-medium">' + s.medium_count + '</span></td>'
                    + '<td><span class="badge sev-low">' + s.low_count + '</span></td>'
                    + '<td>' + s.max_cvss.toFixed(1) + '</td></tr>';
            });
            html += '</tbody></table>';
            el.innerHTML = html;
        })
        .catch(() => {
            document.getElementById('vuln-table').innerHTML = '<div class="loading" style="color:#ef4444">Failed to load vulnerability data.</div>';
        });
    </script>
</body>
</html>"""
