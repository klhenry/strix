from __future__ import annotations

import base64
import contextlib
import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markdown_it import MarkdownIt
from markupsafe import Markup

from strix.reporting.evidence import collect_evidence, normalize_screenshot
from strix.reporting.svg_charts import cvss_gauge, severity_bar_chart
from strix.utils.resource_paths import get_strix_resource_path


if TYPE_CHECKING:
    from pathlib import Path

    from strix.reporting.models import ScanReport


logger = logging.getLogger(__name__)


def _render_markdown(value: object) -> Markup:
    # Escape raw HTML, reject dangerous link protocols, and never load remote images.
    renderer = MarkdownIt("commonmark", {"html": False}).enable("table").disable("image")
    return Markup(renderer.render(str(value or "")))  # noqa: S704 # nosec B704


def generate_html_report(
    report: ScanReport,
    output_path: Path,
    client_name: str | None = None,
) -> Path:
    """Generate a self-contained HTML penetration test report."""
    template_dir = get_strix_resource_path("reporting", "templates")

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(enabled_extensions=("html", "jinja"), default_for_string=True),
    )

    env.filters["markdown"] = _render_markdown
    template = env.get_template("report.html.jinja")

    # Read CSS for inline embedding
    css_path = template_dir / "_styles.css"
    styles_css = css_path.read_text(encoding="utf-8") if css_path.exists() else ""

    # Generate severity chart SVG
    severity_chart = severity_bar_chart(report.severity_counts)

    # Generate per-vulnerability CVSS gauges
    cvss_gauges: dict[str, str] = {}
    for vuln in report.vulnerabilities:
        if vuln.cvss is not None:
            cvss_gauges[vuln.id] = cvss_gauge(vuln.cvss)

    # Collect evidence images
    evidence: dict[str, list[dict[str, str]]] = {}
    run_dir = output_path.parent
    evidence_dir = run_dir / "evidence"
    if evidence_dir.exists():
        raw_evidence = collect_evidence(run_dir)
        for key, paths in raw_evidence.items():
            evidence[key] = []
            for path in paths:
                try:
                    if path.stat().st_size > 10 * 1024 * 1024:
                        continue
                    payload = normalize_screenshot(path.read_bytes())
                except (OSError, ValueError):
                    logger.warning("Skipping unreadable screenshot evidence: %s", path.name)
                    continue
                caption = "Captured assessment evidence"
                metadata = path.with_suffix(".json")
                if metadata.is_file() and not metadata.is_symlink():
                    with contextlib.suppress(OSError, ValueError, KeyError, TypeError):
                        caption = str(json.loads(metadata.read_text(encoding="utf-8"))["caption"])
                evidence[key].append(
                    {"data": base64.b64encode(payload).decode("ascii"), "caption": caption}
                )

    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Load logo image
    logo_path = template_dir / "_logo.png"
    if logo_path.exists():
        logo_b64 = base64.b64encode(logo_path.read_bytes()).decode("ascii")
    else:
        logo_b64 = ""

    html_content = template.render(
        report=report,
        styles_css=styles_css,
        severity_chart=severity_chart,
        cvss_gauges=cvss_gauges,
        evidence=evidence,
        generated_at=generated_at,
        client_name=client_name or "",
        logo_b64=logo_b64,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content, encoding="utf-8")

    logger.info("Generated HTML report: %s", output_path)
    return output_path
