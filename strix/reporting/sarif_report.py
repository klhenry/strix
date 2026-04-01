from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from strix.reporting.models import ScanReport, VulnerabilityReport


_SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def generate_sarif_report(report: ScanReport, output_path: Path) -> Path:
    """Generate a SARIF v2.1.0 report for CI/CD integration."""
    sarif: dict[str, Any] = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [_build_run(report)],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)

    return output_path


def _build_run(report: ScanReport) -> dict[str, Any]:
    rules = [_build_rule(v) for v in report.vulnerabilities]
    results = [_build_result(v) for v in report.vulnerabilities]

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "strix",
                "informationUri": "https://github.com/usestrix/strix",
                "rules": rules,
            },
        },
        "results": results,
    }

    if report.metadata.run_id:
        run["automationDetails"] = {"id": report.metadata.run_id}

    invocation: dict[str, Any] = {
        "executionSuccessful": report.metadata.status == "completed",
    }
    if report.metadata.start_time:
        invocation["startTimeUtc"] = report.metadata.start_time
    if report.metadata.end_time:
        invocation["endTimeUtc"] = report.metadata.end_time
    run["invocations"] = [invocation]

    return run


def _build_rule(vuln: VulnerabilityReport) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": vuln.id,
        "shortDescription": {"text": vuln.title},
        "fullDescription": {"text": vuln.description or vuln.title},
        "defaultConfiguration": {
            "level": _SEVERITY_TO_SARIF_LEVEL.get(vuln.severity.lower(), "warning"),
        },
        "properties": {
            "severity": vuln.severity,
        },
    }

    if vuln.remediation_steps:
        rule["help"] = {"text": vuln.remediation_steps}

    if vuln.cvss is not None:
        rule["properties"]["cvss"] = vuln.cvss
    if vuln.cvss_breakdown:
        rule["properties"]["cvss-vector"] = vuln.cvss_breakdown.to_vector_string()
    if vuln.cwe:
        rule["properties"]["cwe"] = vuln.cwe

    return rule


def _build_result(vuln: VulnerabilityReport) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": vuln.id,
        "level": _SEVERITY_TO_SARIF_LEVEL.get(vuln.severity.lower(), "warning"),
        "message": {"text": vuln.description or vuln.title},
    }

    locations = _build_locations(vuln)
    if locations:
        result["locations"] = locations

    fixes = _build_fixes(vuln)
    if fixes:
        result["fixes"] = fixes

    props: dict[str, Any] = {}
    if vuln.target:
        props["target"] = vuln.target
    if vuln.endpoint:
        props["endpoint"] = vuln.endpoint
    if vuln.method:
        props["method"] = vuln.method
    if vuln.cve:
        props["cve"] = vuln.cve
    if props:
        result["properties"] = props

    return result


def _build_locations(vuln: VulnerabilityReport) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    for loc in vuln.code_locations:
        physical: dict[str, Any] = {
            "artifactLocation": {"uri": loc.file},
        }
        region: dict[str, Any] = {"startLine": loc.start_line}
        if loc.end_line is not None:
            region["endLine"] = loc.end_line
        physical["region"] = region

        sarif_loc: dict[str, Any] = {"physicalLocation": physical}
        if loc.label:
            sarif_loc["message"] = {"text": loc.label}

        locations.append(sarif_loc)
    return locations


def _build_fixes(vuln: VulnerabilityReport) -> list[dict[str, Any]]:
    fixes: list[dict[str, Any]] = []
    for loc in vuln.code_locations:
        if not loc.fix_before or not loc.fix_after:
            continue
        fix: dict[str, Any] = {
            "description": {"text": f"Fix for {loc.file}"},
            "artifactChanges": [
                {
                    "artifactLocation": {"uri": loc.file},
                    "replacements": [
                        {
                            "deletedRegion": {
                                "startLine": loc.start_line,
                                **({"endLine": loc.end_line} if loc.end_line else {}),
                            },
                            "insertedContent": {"text": loc.fix_after},
                        }
                    ],
                }
            ],
        }
        fixes.append(fix)
    return fixes
