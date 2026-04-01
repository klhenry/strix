from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class CodeLocation(BaseModel):
    file: str
    start_line: int
    end_line: int | None = None
    snippet: str | None = None
    label: str | None = None
    fix_before: str | None = None
    fix_after: str | None = None


class CvssBreakdown(BaseModel):
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    scope: str = ""
    confidentiality: str = ""
    integrity: str = ""
    availability: str = ""

    def to_vector_string(self) -> str:
        return (
            f"AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/"
            f"I:{self.integrity}/A:{self.availability}"
        )


class VulnerabilityReport(BaseModel):
    id: str
    title: str
    severity: str
    timestamp: str
    description: str = ""
    impact: str = ""
    target: str = ""
    technical_analysis: str = ""
    poc_description: str = ""
    poc_script_code: str = ""
    remediation_steps: str = ""
    cvss: float | None = None
    cvss_breakdown: CvssBreakdown | None = None
    endpoint: str | None = None
    method: str | None = None
    cve: str | None = None
    cwe: str | None = None
    code_locations: list[CodeLocation] = Field(default_factory=list)
    evidence_images: list[str] = Field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VulnerabilityReport:
        cvss_bd = data.get("cvss_breakdown")
        if isinstance(cvss_bd, dict):
            cvss_bd = CvssBreakdown(**cvss_bd)

        code_locs = data.get("code_locations") or []
        parsed_locs = [CodeLocation(**loc) if isinstance(loc, dict) else loc for loc in code_locs]

        return cls(
            id=data.get("id", ""),
            title=data.get("title", ""),
            severity=data.get("severity", "unknown"),
            timestamp=data.get("timestamp", ""),
            description=data.get("description", ""),
            impact=data.get("impact", ""),
            target=data.get("target", ""),
            technical_analysis=data.get("technical_analysis", ""),
            poc_description=data.get("poc_description", ""),
            poc_script_code=data.get("poc_script_code", ""),
            remediation_steps=data.get("remediation_steps", ""),
            cvss=data.get("cvss"),
            cvss_breakdown=cvss_bd,
            endpoint=data.get("endpoint"),
            method=data.get("method"),
            cve=data.get("cve"),
            cwe=data.get("cwe"),
            code_locations=parsed_locs,
        )


class ScanMetadata(BaseModel):
    run_id: str = ""
    run_name: str | None = None
    start_time: str = ""
    end_time: str | None = None
    targets: list[str] = Field(default_factory=list)
    status: str = "unknown"
    scan_mode: str = "deep"

    @property
    def report_title(self) -> str:
        if self.scan_mode == "vuln_scan":
            return "Vulnerability Scan Report"
        return "Penetration Test Report"

    @property
    def duration_display(self) -> str:
        if not self.start_time or not self.end_time:
            return "N/A"
        try:
            from datetime import datetime

            start = datetime.fromisoformat(self.start_time.replace("Z", "+00:00"))
            end = datetime.fromisoformat(self.end_time.replace("Z", "+00:00"))
            delta = end - start
            minutes, seconds = divmod(int(delta.total_seconds()), 60)
            hours, minutes = divmod(minutes, 60)
            if hours:
                return f"{hours}h {minutes}m {seconds}s"
            if minutes:
                return f"{minutes}m {seconds}s"
            return f"{seconds}s"
        except (ValueError, TypeError):
            return "N/A"


class ScanReport(BaseModel):
    metadata: ScanMetadata
    vulnerabilities: list[VulnerabilityReport] = Field(default_factory=list)
    executive_summary: str = ""
    methodology: str = ""
    technical_analysis: str = ""
    recommendations: str = ""

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in self.vulnerabilities:
            sev = vuln.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    @property
    def total_vulnerabilities(self) -> int:
        return len(self.vulnerabilities)

    @property
    def average_cvss(self) -> float:
        scores = [v.cvss for v in self.vulnerabilities if v.cvss is not None]
        return round(sum(scores) / len(scores), 1) if scores else 0.0

    @classmethod
    def from_tracer(cls, tracer: Any) -> ScanReport:
        scan_config = tracer.scan_config or {}
        raw_targets = tracer.run_metadata.get("targets", [])
        targets = [
            (t["original"] if isinstance(t, dict) else str(t))
            for t in raw_targets
        ]
        metadata = ScanMetadata(
            run_id=tracer.run_id,
            run_name=tracer.run_name,
            start_time=tracer.start_time,
            end_time=tracer.end_time,
            targets=targets,
            status=tracer.run_metadata.get("status", "unknown"),
            scan_mode=scan_config.get("scan_mode", "deep"),
        )

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulns = [VulnerabilityReport.from_dict(r) for r in tracer.vulnerability_reports]
        vulns.sort(key=lambda v: severity_order.get(v.severity.lower(), 5))

        scan_results = tracer.scan_results or {}

        return cls(
            metadata=metadata,
            vulnerabilities=vulns,
            executive_summary=scan_results.get("executive_summary", ""),
            methodology=scan_results.get("methodology", ""),
            technical_analysis=scan_results.get("technical_analysis", ""),
            recommendations=scan_results.get("recommendations", ""),
        )
