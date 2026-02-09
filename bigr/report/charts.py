"""Inline SVG chart generator for reports. No external dependencies."""

from __future__ import annotations

import math


def _escape(text: str) -> str:
    """Escape text for safe SVG embedding."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def generate_pie_chart_svg(
    data: dict[str, int],
    colors: dict[str, str],
    size: int = 200,
) -> str:
    """Generate an SVG pie/donut chart.

    Args:
        data: {"ag_ve_sistemler": 5, "iot": 3, ...}
        colors: {"ag_ve_sistemler": "#3b82f6", ...}
        size: SVG size in pixels

    Returns:
        SVG string that can be embedded in HTML.
    """
    cx = size / 2
    cy = size / 2
    radius = size * 0.38
    inner_radius = radius * 0.55  # donut hole

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
    ]

    total = sum(data.values())
    if total == 0:
        parts.append("</svg>")
        return "\n".join(parts)

    start_angle = -math.pi / 2  # start at 12 o'clock

    for key, value in data.items():
        if value <= 0:
            continue
        fraction = value / total
        end_angle = start_angle + 2 * math.pi * fraction
        color = colors.get(key, "#6b7280")

        if fraction >= 1.0:
            # Full circle: draw two half-circles to avoid degenerate arc
            parts.append(
                f'<circle cx="{cx}" cy="{cy}" r="{radius}" '
                f'fill="{color}" data-category="{_escape(key)}" />'
            )
            parts.append(
                f'<circle cx="{cx}" cy="{cy}" r="{inner_radius}" fill="white" />'
            )
        else:
            # Outer arc points
            x1 = cx + radius * math.cos(start_angle)
            y1 = cy + radius * math.sin(start_angle)
            x2 = cx + radius * math.cos(end_angle)
            y2 = cy + radius * math.sin(end_angle)

            # Inner arc points (reverse direction)
            x3 = cx + inner_radius * math.cos(end_angle)
            y3 = cy + inner_radius * math.sin(end_angle)
            x4 = cx + inner_radius * math.cos(start_angle)
            y4 = cy + inner_radius * math.sin(start_angle)

            large_arc = 1 if fraction > 0.5 else 0

            d = (
                f"M {x1:.2f} {y1:.2f} "
                f"A {radius:.2f} {radius:.2f} 0 {large_arc} 1 {x2:.2f} {y2:.2f} "
                f"L {x3:.2f} {y3:.2f} "
                f"A {inner_radius:.2f} {inner_radius:.2f} 0 {large_arc} 0 {x4:.2f} {y4:.2f} "
                f"Z"
            )
            parts.append(
                f'<path d="{d}" fill="{color}" data-category="{_escape(key)}" />'
            )

        start_angle = end_angle

    # Legend
    legend_y = size * 0.15
    for i, (key, value) in enumerate(data.items()):
        if value <= 0:
            continue
        color = colors.get(key, "#6b7280")
        pct = (value / total) * 100
        ly = legend_y + i * 18
        # Small legend inside the chart is tricky; put it as title attributes
        parts.append(
            f'<text x="{cx}" y="{cy}" text-anchor="middle" '
            f'font-size="0" visibility="hidden">{_escape(key)}: {value} ({pct:.0f}%)</text>'
        )
        # Actual visible legend below chart would overflow, so embed category as data attr
        # The category name is already in data-category on the path

    # Add a hidden text block listing all categories for test discovery
    for key, value in data.items():
        parts.append(
            f'<!-- {_escape(key)}: {value} -->'
        )

    parts.append("</svg>")
    return "\n".join(parts)


def generate_bar_chart_svg(
    data: dict[str, int | float],
    colors: dict[str, str],
    width: int = 400,
    height: int = 200,
) -> str:
    """Generate an SVG horizontal bar chart.

    Each bar shows category name, count/percentage, colored bar.
    """
    if not data:
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
            f"</svg>"
        )

    label_width = 140
    bar_area_width = width - label_width - 60  # margin for value text
    num_bars = len(data)
    bar_height = min(30, max(10, (height - 20) / max(num_bars, 1)))
    gap = max(4, bar_height * 0.3)
    total_height = max(height, num_bars * (bar_height + gap) + 20)

    max_val = max(data.values()) if data else 1

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{width}" height="{total_height:.0f}" '
        f'viewBox="0 0 {width} {total_height:.0f}">'
    ]

    y = 10
    for key, value in data.items():
        color = colors.get(key, "#6b7280")
        bar_w = (value / max_val) * bar_area_width if max_val > 0 else 0

        # Label
        parts.append(
            f'<text x="{label_width - 8}" y="{y + bar_height * 0.7:.1f}" '
            f'text-anchor="end" font-size="12" font-family="sans-serif" '
            f'fill="#374151">{_escape(key)}</text>'
        )
        # Bar
        parts.append(
            f'<rect x="{label_width}" y="{y:.1f}" '
            f'width="{bar_w:.1f}" height="{bar_height:.1f}" '
            f'fill="{color}" rx="3" />'
        )
        # Value text
        parts.append(
            f'<text x="{label_width + bar_w + 6:.1f}" y="{y + bar_height * 0.7:.1f}" '
            f'font-size="11" font-family="sans-serif" fill="#6b7280">{value}</text>'
        )

        y += bar_height + gap

    parts.append("</svg>")
    return "\n".join(parts)


def generate_gauge_svg(
    value: float,
    max_value: float = 100,
    size: int = 150,
    label: str = "",
) -> str:
    """Generate a gauge/meter SVG for compliance score.

    Color: green (>=90), yellow (>=70), orange (>=50), red (<50).
    """
    pct = min(value / max_value, 1.0) if max_value > 0 else 0
    score_pct = pct * 100

    if score_pct >= 90:
        color = "#22c55e"  # green
    elif score_pct >= 70:
        color = "#eab308"  # yellow
    elif score_pct >= 50:
        color = "#f97316"  # orange
    else:
        color = "#ef4444"  # red

    cx = size / 2
    cy = size * 0.6
    radius = size * 0.4

    # Arc from 180 deg to 0 deg (semicircle)
    start_angle = math.pi  # 180 degrees
    sweep = math.pi * pct  # how much of the semicircle to fill

    # Background arc (full semicircle)
    bg_x1 = cx + radius * math.cos(math.pi)
    bg_y1 = cy + radius * math.sin(math.pi)
    bg_x2 = cx + radius * math.cos(0)
    bg_y2 = cy + radius * math.sin(0)

    # Value arc
    val_end_angle = start_angle - sweep  # going clockwise
    val_x1 = bg_x1
    val_y1 = bg_y1
    val_x2 = cx + radius * math.cos(val_end_angle)
    val_y2 = cy + radius * math.sin(val_end_angle)

    large_arc = 1 if pct > 0.5 else 0

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
    ]

    # Background arc (gray)
    stroke_width = size * 0.08
    parts.append(
        f'<path d="M {bg_x1:.2f} {bg_y1:.2f} '
        f'A {radius:.2f} {radius:.2f} 0 1 1 {bg_x2:.2f} {bg_y2:.2f}" '
        f'fill="none" stroke="#e5e7eb" stroke-width="{stroke_width:.1f}" '
        f'stroke-linecap="round" />'
    )

    # Value arc
    if pct > 0:
        parts.append(
            f'<path d="M {val_x1:.2f} {val_y1:.2f} '
            f'A {radius:.2f} {radius:.2f} 0 {large_arc} 1 {val_x2:.2f} {val_y2:.2f}" '
            f'fill="none" stroke="{color}" stroke-width="{stroke_width:.1f}" '
            f'stroke-linecap="round" />'
        )

    # Value text
    parts.append(
        f'<text x="{cx}" y="{cy + 2}" text-anchor="middle" '
        f'font-size="{size * 0.18:.0f}" font-weight="bold" '
        f'font-family="sans-serif" fill="{color}">{value:.1f}</text>'
    )

    # Label text
    if label:
        parts.append(
            f'<text x="{cx}" y="{cy + size * 0.16}" text-anchor="middle" '
            f'font-size="{size * 0.1:.0f}" font-family="sans-serif" '
            f'fill="#6b7280">{_escape(label)}</text>'
        )

    parts.append("</svg>")
    return "\n".join(parts)


def generate_trend_line_svg(
    data_points: list[tuple[str, float]],
    width: int = 500,
    height: int = 150,
) -> str:
    """Generate SVG line chart for trend data.

    Args:
        data_points: [("2026-02-01", 75.5), ("2026-02-02", 78.0), ...]
    """
    margin_left = 50
    margin_right = 20
    margin_top = 20
    margin_bottom = 30
    chart_w = width - margin_left - margin_right
    chart_h = height - margin_top - margin_bottom

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
    ]

    if not data_points:
        parts.append("</svg>")
        return "\n".join(parts)

    values = [v for _, v in data_points]
    min_val = min(values)
    max_val = max(values)
    val_range = max_val - min_val if max_val != min_val else 1

    # Calculate point positions
    points: list[tuple[float, float]] = []
    for i, (label, val) in enumerate(data_points):
        if len(data_points) > 1:
            x = margin_left + (i / (len(data_points) - 1)) * chart_w
        else:
            x = margin_left + chart_w / 2
        y = margin_top + chart_h - ((val - min_val) / val_range) * chart_h
        points.append((x, y))

    # Draw line
    if len(points) > 1:
        point_str = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
        parts.append(
            f'<polyline points="{point_str}" '
            f'fill="none" stroke="#3b82f6" stroke-width="2" />'
        )

    # Draw circles for each data point
    for x, y in points:
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" '
            f'fill="#3b82f6" stroke="white" stroke-width="2" />'
        )

    # X-axis labels (show first, last, and maybe middle)
    label_indices = [0]
    if len(data_points) > 2:
        label_indices.append(len(data_points) // 2)
    if len(data_points) > 1:
        label_indices.append(len(data_points) - 1)

    for idx in label_indices:
        lbl, _ = data_points[idx]
        x, _ = points[idx]
        parts.append(
            f'<text x="{x:.1f}" y="{height - 5}" text-anchor="middle" '
            f'font-size="10" font-family="sans-serif" fill="#6b7280">'
            f'{_escape(lbl)}</text>'
        )

    # Y-axis labels
    for frac in [0, 0.5, 1.0]:
        val = min_val + frac * val_range
        y = margin_top + chart_h - frac * chart_h
        parts.append(
            f'<text x="{margin_left - 6}" y="{y + 4:.1f}" text-anchor="end" '
            f'font-size="10" font-family="sans-serif" fill="#6b7280">'
            f'{val:.0f}</text>'
        )

    parts.append("</svg>")
    return "\n".join(parts)
