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
