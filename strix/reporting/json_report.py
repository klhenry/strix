from __future__ import annotations

import json
from pathlib import Path

from strix.reporting.models import ScanReport


def generate_json_summary(report: ScanReport, output_path: Path) -> Path:
    """Generate a structured JSON summary of the scan results."""
    data = {
        "metadata": {
            "run_id": report.metadata.run_id,
            "run_name": report.metadata.run_name,
            "start_time": report.metadata.start_time,
            "end_time": report.metadata.end_time,
            "duration": report.metadata.duration_display,
            "targets": report.metadata.targets,
            "status": report.metadata.status,
        },
        "statistics": {
            "total_vulnerabilities": report.total_vulnerabilities,
            "severity_counts": report.severity_counts,
            "average_cvss": report.average_cvss,
        },
        "vulnerabilities": [
            _serialize_vulnerability(v) for v in report.vulnerabilities
        ],
        "executive_summary": report.executive_summary,
        "methodology": report.methodology,
        "technical_analysis": report.technical_analysis,
        "recommendations": report.recommendations,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return output_path


def _serialize_vulnerability(v: object) -> dict:
    """Serialize a VulnerabilityReport to a plain dict."""
    from strix.reporting.models import VulnerabilityReport

    assert isinstance(v, VulnerabilityReport)
    data = v.model_dump(mode="json")
    # Remove empty evidence_images to keep output clean
    if not data.get("evidence_images"):
        data.pop("evidence_images", None)
    return data
