"""Report generation engine for BİGR compliance reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from bigr.report.charts import generate_bar_chart_svg, generate_pie_chart_svg


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CATEGORY_LABELS: dict[str, str] = {
    "ag_ve_sistemler": "Ağ ve Sistemler",
    "uygulamalar": "Uygulamalar",
    "iot": "IoT",
    "tasinabilir": "Taşınabilir Cihazlar",
    "unclassified": "Sınıflandırılmamış",
}

CATEGORY_COLORS: dict[str, str] = {
    "ag_ve_sistemler": "#3b82f6",
    "uygulamalar": "#10b981",
    "iot": "#f59e0b",
    "tasinabilir": "#ef4444",
    "unclassified": "#6b7280",
}


def _esc(text: str) -> str:
    """Escape HTML entities."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    organization: str = "BİGR Discovery"
    author: str = "BİGR Discovery Agent"
    logo_path: str | None = None
    include_charts: bool = True
    include_action_items: bool = True
    include_changes: bool = True
    days_lookback: int = 30


@dataclass
class ReportSection:
    """A section in the report."""

    title: str
    content: str  # HTML content
    order: int = 0


@dataclass
class GeneratedReport:
    """A generated report ready for output."""

    title: str
    html_content: str
    generated_at: datetime = field(default_factory=datetime.now)
    format: str = "html"

    def save(self, path: str) -> str:
        """Save report to file. Returns the path."""
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.html_content, encoding="utf-8")
        return str(out)


# ---------------------------------------------------------------------------
# Section generators
# ---------------------------------------------------------------------------


def generate_executive_summary(assets: list[dict], compliance_data: dict) -> str:
    """Generate executive summary section HTML.

    Contains: total assets, compliance score, scan date, key findings.
    """
    total = len(assets)
    score = compliance_data.get("score", 0)
    grade = compliance_data.get("grade", "N/A")
    scan_date = compliance_data.get("scan_date", datetime.now().strftime("%Y-%m-%d"))
    total_classified = compliance_data.get("total_classified", 0)
    total_unclassified = compliance_data.get("total_unclassified", 0)

    # Category counts
    dist = compliance_data.get("category_distribution", {})
    cat_lines = []
    for key, count in dist.items():
        label = CATEGORY_LABELS.get(key, key)
        cat_lines.append(f"<li>{_esc(label)}: <strong>{count}</strong></li>")
    cat_html = "<ul>" + "\n".join(cat_lines) + "</ul>" if cat_lines else ""

    return f"""
    <section class="executive-summary">
        <h2>Yönetici Özeti</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-value">{total}</div>
                <div class="summary-label">Toplam Varlık</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">{score}</div>
                <div class="summary-label">Uyumluluk Skoru</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">{_esc(str(grade))}</div>
                <div class="summary-label">Not</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">{_esc(str(scan_date))}</div>
                <div class="summary-label">Tarama Tarihi</div>
            </div>
        </div>
        <div class="summary-details">
            <p>Sınıflandırılmış: <strong>{total_classified}</strong> |
               Sınıflandırılmamış: <strong>{total_unclassified}</strong></p>
            {cat_html}
        </div>
    </section>
    """


def generate_category_section(distribution: dict) -> str:
    """Generate BİGR category distribution section with pie chart SVG."""
    pie_svg = generate_pie_chart_svg(distribution, CATEGORY_COLORS, size=220)
    bar_svg = generate_bar_chart_svg(distribution, CATEGORY_COLORS, width=400, height=180)

    rows = []
    total = sum(distribution.values())
    for key, count in distribution.items():
        label = CATEGORY_LABELS.get(key, key)
        pct = (count / total * 100) if total > 0 else 0
        color = CATEGORY_COLORS.get(key, "#6b7280")
        rows.append(
            f"<tr>"
            f'<td><span class="color-dot" style="background:{color}"></span> {_esc(label)}</td>'
            f"<td>{count}</td>"
            f"<td>{pct:.1f}%</td>"
            f"</tr>"
        )

    table_html = (
        '<table class="category-table">'
        "<thead><tr><th>Kategori</th><th>Sayı</th><th>Oran</th></tr></thead>"
        "<tbody>" + "\n".join(rows) + "</tbody></table>"
    )

    return f"""
    <section class="category-distribution">
        <h2>BİGR Kategori Dağılımı</h2>
        <div class="chart-row">
            <div class="chart-container">{pie_svg}</div>
            <div class="chart-container">{bar_svg}</div>
        </div>
        {table_html}
    </section>
    """


def generate_asset_table_section(
    assets: list[dict], category: str | None = None
) -> str:
    """Generate asset inventory table section.

    If category specified, filter to that category only.
    """
    filtered = assets
    if category:
        filtered = [a for a in assets if a.get("bigr_category") == category]

    section_title = "Varlık Envanteri"
    if category:
        label = CATEGORY_LABELS.get(category, category)
        section_title = f"Varlık Envanteri - {label}"

    if not filtered:
        return f"""
        <section class="asset-table-section">
            <h2>{_esc(section_title)}</h2>
            <p class="empty-message">Varlık bulunamadı.</p>
            <table class="asset-table">
                <thead>
                    <tr>
                        <th>IP</th><th>MAC</th><th>Hostname</th>
                        <th>Vendor</th><th>BİGR Kategori</th><th>Güven</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </section>
        """

    rows = []
    for asset in filtered:
        ip = asset.get("ip", "-")
        mac = asset.get("mac", "-") or "-"
        hostname = asset.get("hostname", "-") or "-"
        vendor = asset.get("vendor", "-") or "-"
        cat_tr = asset.get("bigr_category_tr", asset.get("bigr_category", "-"))
        conf = asset.get("confidence_score", 0)
        conf_level = asset.get("confidence_level", "unclassified")
        conf_class = {
            "high": "confidence-high",
            "medium": "confidence-medium",
            "low": "confidence-low",
        }.get(conf_level, "confidence-unknown")

        rows.append(
            f"<tr>"
            f"<td>{_esc(ip)}</td>"
            f"<td><code>{_esc(mac)}</code></td>"
            f"<td>{_esc(hostname)}</td>"
            f"<td>{_esc(vendor)}</td>"
            f"<td>{_esc(cat_tr)}</td>"
            f'<td class="{conf_class}">{conf:.2f}</td>'
            f"</tr>"
        )

    return f"""
    <section class="asset-table-section">
        <h2>{_esc(section_title)}</h2>
        <table class="asset-table">
            <thead>
                <tr>
                    <th>IP</th><th>MAC</th><th>Hostname</th>
                    <th>Vendor</th><th>BİGR Kategori</th><th>Güven</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
    </section>
    """


def generate_changes_section(changes: list[dict], days: int = 30) -> str:
    """Generate changes/diff section showing new/removed/changed assets."""
    if not changes:
        return """
        <section class="changes-section">
            <h2>Değişiklik Raporu</h2>
            <p class="empty-message">Son taramalarda değişiklik tespit edilmedi.</p>
        </section>
        """

    rows = []
    for change in changes:
        change_type = change.get("change_type", "-")
        ip = change.get("ip", "-")
        detected = change.get("detected_at", "-")

        if change_type == "new_asset":
            badge = '<span class="badge badge-new">Yeni</span>'
            detail = f"MAC: {_esc(change.get('mac', '-') or '-')}"
        elif change_type == "field_changed":
            badge = '<span class="badge badge-changed">Değişiklik</span>'
            field_name = change.get("field_name", "-")
            old_val = change.get("old_value", "-")
            new_val = change.get("new_value", "-")
            detail = f"{_esc(field_name)}: {_esc(str(old_val))} &rarr; {_esc(str(new_val))}"
        elif change_type == "removed_asset":
            badge = '<span class="badge badge-removed">Kaldırıldı</span>'
            detail = f"MAC: {_esc(change.get('mac', '-') or '-')}"
        else:
            badge = f'<span class="badge">{_esc(change_type)}</span>'
            detail = "-"

        rows.append(
            f"<tr>"
            f"<td>{badge}</td>"
            f"<td>{_esc(ip)}</td>"
            f"<td>{detail}</td>"
            f"<td>{_esc(str(detected))}</td>"
            f"</tr>"
        )

    return f"""
    <section class="changes-section">
        <h2>Değişiklik Raporu</h2>
        <table class="changes-table">
            <thead><tr><th>Tür</th><th>IP</th><th>Detay</th><th>Tarih</th></tr></thead>
            <tbody>{"".join(rows)}</tbody>
        </table>
    </section>
    """


def generate_action_items_section(action_items: list[dict]) -> str:
    """Generate action items section with priority badges."""
    if not action_items:
        return """
        <section class="action-items-section">
            <h2>Aksiyon Önerileri</h2>
            <p class="empty-message">Bekleyen aksiyon yok.</p>
        </section>
        """

    items_html = []
    for item in action_items:
        priority = item.get("priority", "normal")
        title = item.get("title", "-")
        description = item.get("description", "")
        ip = item.get("ip", "")

        badge_class = "badge-critical" if priority == "critical" else "badge-normal"
        priority_label = "Kritik" if priority == "critical" else "Normal"

        items_html.append(
            f'<div class="action-item">'
            f'<span class="badge {badge_class}">{priority_label}</span> '
            f"<strong>{_esc(title)}</strong>"
            f"{f' <code>{_esc(ip)}</code>' if ip else ''}"
            f"<p>{_esc(description)}</p>"
            f"</div>"
        )

    return f"""
    <section class="action-items-section">
        <h2>Aksiyon Önerileri</h2>
        {"".join(items_html)}
    </section>
    """


# ---------------------------------------------------------------------------
# Full report builder
# ---------------------------------------------------------------------------


def build_full_report(
    assets: list[dict],
    compliance_data: dict,
    changes: list[dict] | None = None,
    config: ReportConfig | None = None,
) -> GeneratedReport:
    """Build a complete BİGR compliance report.

    Sections:
    1. Yönetici Özeti (Executive Summary)
    2. BİGR Kategori Dağılımı (Category Distribution)
    3. Varlık Tablosu (Asset Inventory)
    4. Değişiklik Raporu (Changes)
    5. Aksiyon Önerileri (Action Items)
    """
    if config is None:
        config = ReportConfig()

    # Build distribution from assets if not in compliance data
    distribution = compliance_data.get("category_distribution", {})
    if not distribution:
        for asset in assets:
            cat = asset.get("bigr_category", "unclassified")
            distribution[cat] = distribution.get(cat, 0) + 1

    # Gather sections
    body_parts: list[str] = []

    # 1. Executive summary
    body_parts.append(generate_executive_summary(assets, compliance_data))

    # 2. Category distribution
    if config.include_charts:
        body_parts.append(generate_category_section(distribution))

    # 3. Asset inventory
    body_parts.append(generate_asset_table_section(assets))

    # 4. Changes
    if config.include_changes and changes:
        body_parts.append(generate_changes_section(changes, days=config.days_lookback))

    # 5. Action items - auto-generate from unclassified/low-confidence assets
    if config.include_action_items:
        action_items = _derive_action_items(assets)
        if action_items:
            body_parts.append(generate_action_items_section(action_items))

    body_html = "\n".join(body_parts)
    title = f"BİGR Uyumluluk Raporu - {config.organization}"
    full_html = build_html_wrapper(title, body_html, config=config)

    return GeneratedReport(
        title=title,
        html_content=full_html,
    )


def _derive_action_items(assets: list[dict]) -> list[dict]:
    """Auto-generate action items from asset data."""
    items: list[dict] = []
    for asset in assets:
        cat = asset.get("bigr_category", "unclassified")
        conf = asset.get("confidence_score", 0)
        ip = asset.get("ip", "")

        if cat == "unclassified":
            items.append(
                {
                    "priority": "critical",
                    "title": "Sınıflandırılmamış varlık tespit edildi",
                    "description": f"{ip} adresindeki varlık BİGR sınıflandırması yapılmamış.",
                    "ip": ip,
                }
            )
        elif conf < 0.5:
            items.append(
                {
                    "priority": "normal",
                    "title": "Düşük güven skoru",
                    "description": f"{ip} adresindeki varlığın güven skoru düşük ({conf:.2f}).",
                    "ip": ip,
                }
            )
    return items


# ---------------------------------------------------------------------------
# HTML wrapper
# ---------------------------------------------------------------------------


def build_html_wrapper(
    title: str, body: str, config: ReportConfig | None = None
) -> str:
    """Wrap report body in full HTML document with styling.

    Includes:
    - Professional report CSS (print-friendly)
    - Header with organization name, date, logo
    - Footer with page numbers
    - Turkish character support (UTF-8)
    """
    if config is None:
        config = ReportConfig()

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    org = _esc(config.organization)
    author = _esc(config.author)

    logo_html = ""
    if config.logo_path:
        logo_html = f'<img src="{_esc(config.logo_path)}" alt="Logo" class="report-logo" />'

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="author" content="{author}" />
    <title>{_esc(title)}</title>
    <style>
        /* ---- Base ---- */
        *, *::before, *::after {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                         "Helvetica Neue", Arial, sans-serif;
            color: #1f2937;
            background: #ffffff;
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }}
        .report-container {{
            max-width: 1000px;
            margin: 0 auto;
            padding: 40px 32px;
        }}
        h1 {{ font-size: 1.8rem; color: #111827; margin-bottom: 4px; }}
        h2 {{
            font-size: 1.3rem;
            color: #374151;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 8px;
            margin-top: 36px;
        }}
        /* ---- Header ---- */
        .report-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 3px solid #3b82f6;
            padding-bottom: 16px;
            margin-bottom: 32px;
        }}
        .report-header .org-name {{ font-size: 1.6rem; font-weight: 700; color: #1e40af; }}
        .report-header .report-date {{ color: #6b7280; font-size: 0.9rem; }}
        .report-logo {{ height: 48px; }}
        /* ---- Summary grid ---- */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
            margin: 20px 0;
        }}
        .summary-card {{
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}
        .summary-value {{ font-size: 1.6rem; font-weight: 700; color: #1e40af; }}
        .summary-label {{ font-size: 0.85rem; color: #6b7280; margin-top: 4px; }}
        /* ---- Charts ---- */
        .chart-row {{
            display: flex;
            gap: 24px;
            flex-wrap: wrap;
            justify-content: center;
            margin: 20px 0;
        }}
        .chart-container {{ flex: 0 0 auto; }}
        /* ---- Tables ---- */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
            font-size: 0.9rem;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }}
        th {{
            background: #f3f4f6;
            font-weight: 600;
            color: #374151;
        }}
        tr:hover {{ background: #f9fafb; }}
        code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }}
        /* ---- Confidence ---- */
        .confidence-high {{ color: #059669; font-weight: 600; }}
        .confidence-medium {{ color: #d97706; }}
        .confidence-low {{ color: #dc2626; }}
        .confidence-unknown {{ color: #6b7280; }}
        /* ---- Badges ---- */
        .badge {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.78rem;
            font-weight: 600;
        }}
        .badge-new {{ background: #dcfce7; color: #166534; }}
        .badge-changed {{ background: #fef3c7; color: #92400e; }}
        .badge-removed {{ background: #fee2e2; color: #991b1b; }}
        .badge-critical {{ background: #fee2e2; color: #991b1b; }}
        .badge-normal {{ background: #dbeafe; color: #1e40af; }}
        /* ---- Color dot ---- */
        .color-dot {{
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            vertical-align: middle;
            margin-right: 6px;
        }}
        /* ---- Action items ---- */
        .action-item {{
            border-left: 4px solid #3b82f6;
            padding: 12px 16px;
            margin: 12px 0;
            background: #f9fafb;
            border-radius: 0 8px 8px 0;
        }}
        .action-item p {{ margin: 6px 0 0; color: #4b5563; font-size: 0.9rem; }}
        .empty-message {{ color: #9ca3af; font-style: italic; }}
        /* ---- Footer ---- */
        .report-footer {{
            margin-top: 48px;
            padding-top: 16px;
            border-top: 1px solid #e5e7eb;
            color: #9ca3af;
            font-size: 0.8rem;
            text-align: center;
        }}
        /* ---- Print ---- */
        @media print {{
            body {{ font-size: 11pt; }}
            .report-container {{ padding: 0; max-width: none; }}
            .summary-card {{ break-inside: avoid; }}
            table {{ page-break-inside: auto; }}
            tr {{ page-break-inside: avoid; }}
            h2 {{ page-break-after: avoid; }}
            .report-footer::after {{ content: " | Sayfa " counter(page); }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <header class="report-header">
            <div>
                <div class="org-name">{org}</div>
                <div class="report-date">{now} | {author}</div>
            </div>
            {logo_html}
        </header>

        <h1>{_esc(title)}</h1>

        {body}

        <footer class="report-footer">
            {org} &mdash; Oluşturulma: {now} &mdash; {author}
        </footer>
    </div>
</body>
</html>"""
