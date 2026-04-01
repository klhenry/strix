"""Pure Python SVG chart generators for inline embedding in HTML reports."""

from __future__ import annotations

import math


SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#0284c7",
}

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def severity_bar_chart(counts: dict[str, int], width: int = 500, height: int = 40) -> str:
    """Generate an inline SVG horizontal stacked bar chart of severity distribution."""
    total = sum(counts.values())
    if total == 0:
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">'
            f'<rect width="{width}" height="{height}" rx="6" fill="#e5e7eb"/>'
            f'<text x="{width // 2}" y="{height // 2 + 5}" text-anchor="middle" '
            f'font-family="system-ui, sans-serif" font-size="13" fill="#6b7280">'
            f"No vulnerabilities found</text></svg>"
        )

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height + 24}">'
    )
    # Background
    parts.append(f'<rect width="{width}" height="{height}" rx="6" fill="#f3f4f6"/>')

    # Clip path for rounded corners
    parts.append(
        f'<defs><clipPath id="bar-clip">'
        f'<rect width="{width}" height="{height}" rx="6"/>'
        f"</clipPath></defs>"
    )
    parts.append('<g clip-path="url(#bar-clip)">')

    x = 0.0
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count == 0:
            continue
        bar_width = (count / total) * width
        color = SEVERITY_COLORS[sev]
        parts.append(
            f'<rect x="{x:.1f}" y="0" width="{bar_width:.1f}" height="{height}" fill="{color}"/>'
        )
        # Label inside bar if wide enough
        if bar_width > 30:
            text_x = x + bar_width / 2
            text_y = height // 2 + 5
            parts.append(
                f'<text x="{text_x:.1f}" y="{text_y}"'
                f' text-anchor="middle"'
                f' font-family="system-ui, sans-serif"'
                f' font-size="12" font-weight="600"'
                f' fill="white">{count}</text>'
            )
        x += bar_width

    parts.append("</g>")

    # Legend below the bar
    legend_x = 0.0
    legend_y = height + 16
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count == 0:
            continue
        color = SEVERITY_COLORS[sev]
        dot_y = legend_y - 8
        parts.append(
            f'<rect x="{legend_x:.1f}" y="{dot_y}"'
            f' width="10" height="10" rx="2" fill="{color}"/>'
        )
        parts.append(
            f'<text x="{legend_x + 14:.1f}" y="{legend_y + 1}" '
            f'font-family="system-ui, sans-serif" font-size="11" fill="#374151">'
            f"{sev.capitalize()}: {count}</text>"
        )
        legend_x += len(f"{sev.capitalize()}: {count}") * 7 + 28

    parts.append("</svg>")
    return "".join(parts)


def cvss_gauge(score: float, size: int = 60) -> str:
    """Generate an inline SVG semicircle gauge for a CVSS score."""
    if score < 0.1:
        color = "#6b7280"
    elif score < 4.0:
        color = SEVERITY_COLORS["low"]
    elif score < 7.0:
        color = SEVERITY_COLORS["medium"]
    elif score < 9.0:
        color = SEVERITY_COLORS["high"]
    else:
        color = SEVERITY_COLORS["critical"]

    cx = size // 2
    cy = size // 2 + 4
    radius = size // 2 - 6
    stroke_width = 6

    # Background arc (180 degrees)
    bg_path = _arc_path(cx, cy, radius, 180, 360)
    # Score arc (proportional to 0-10 scale)
    angle = 180 + (score / 10.0) * 180
    score_path = _arc_path(cx, cy, radius, 180, angle)

    svg_h = size // 2 + 16
    sw = stroke_width
    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg"'
        f' width="{size}" height="{svg_h}">',
        f'<path d="{bg_path}" fill="none" stroke="#e5e7eb"'
        f' stroke-width="{sw}" stroke-linecap="round"/>',
        f'<path d="{score_path}" fill="none" stroke="{color}"'
        f' stroke-width="{sw}" stroke-linecap="round"/>',
        f'<text x="{cx}" y="{cy + 2}" text-anchor="middle"'
        f' font-family="system-ui, sans-serif"'
        f' font-size="14" font-weight="700" fill="{color}">'
        f"{score:.1f}</text>",
        "</svg>",
    ]
    return "".join(parts)


def _arc_path(cx: float, cy: float, r: float, start_angle: float, end_angle: float) -> str:
    """Generate an SVG arc path from start_angle to end_angle (in degrees)."""
    start_rad = math.radians(start_angle)
    end_rad = math.radians(end_angle)

    x1 = cx + r * math.cos(start_rad)
    y1 = cy + r * math.sin(start_rad)
    x2 = cx + r * math.cos(end_rad)
    y2 = cy + r * math.sin(end_rad)

    large_arc = 1 if (end_angle - start_angle) > 180 else 0

    return f"M {x1:.1f} {y1:.1f} A {r} {r} 0 {large_arc} 1 {x2:.1f} {y2:.1f}"
