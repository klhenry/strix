"""Reads strix_runs/ directory to enumerate and inspect scan runs.

The filesystem IS the database — no external DB needed.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class RunSummary:
    run_name: str
    status: str  # "running" | "completed" | "error"
    start_time: str = ""
    end_time: str | None = None
    targets: list[str] = field(default_factory=list)
    vulnerability_count: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    available_reports: list[str] = field(default_factory=list)
    duration_display: str = "N/A"


@dataclass
class RunDetail:
    summary: RunSummary
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    executive_summary: str = ""
    methodology: str = ""
    recommendations: str = ""


class RunStore:
    def __init__(self, runs_dir: Path | None = None) -> None:
        self.runs_dir = runs_dir or (Path.cwd() / "strix_runs")

    def list_runs(self) -> list[RunSummary]:
        if not self.runs_dir.exists():
            return []

        summaries: list[RunSummary] = []
        for run_dir in sorted(self.runs_dir.iterdir(), reverse=True):
            if not run_dir.is_dir():
                continue
            try:
                summary = self._read_summary(run_dir)
                summaries.append(summary)
            except Exception:  # noqa: BLE001
                logger.debug("Failed to read run %s", run_dir.name)
        return summaries

    def get_run(self, run_name: str) -> RunDetail | None:
        run_dir = self.runs_dir / run_name
        if not run_dir.is_dir():
            return None

        summary = self._read_summary(run_dir)
        vulns = self._read_findings(run_dir)
        events = self._read_events(run_dir, limit=200)

        exec_summary = ""
        methodology = ""
        recommendations = ""
        report_md = run_dir / "penetration_test_report.md"
        if report_md.exists():
            content = report_md.read_text(encoding="utf-8")
            for section_title, attr in [
                ("Executive Summary", "exec_summary"),
                ("Methodology", "methodology"),
                ("Recommendations", "recommendations"),
            ]:
                marker = f"# {section_title}"
                if marker in content:
                    start = content.index(marker) + len(marker)
                    next_section = content.find("\n# ", start)
                    text = content[start:next_section].strip() if next_section > 0 else content[start:].strip()
                    if attr == "exec_summary":
                        exec_summary = text
                    elif attr == "methodology":
                        methodology = text
                    else:
                        recommendations = text

        return RunDetail(
            summary=summary,
            vulnerabilities=vulns,
            events=events,
            executive_summary=exec_summary,
            methodology=methodology,
            recommendations=recommendations,
        )

    def get_events_path(self, run_name: str) -> Path | None:
        p = self.runs_dir / run_name / "events.jsonl"
        return p if p.exists() else None

    def get_report_path(self, run_name: str, fmt: str) -> Path | None:
        run_dir = self.runs_dir / run_name
        name_map: dict[str, list[str]] = {
            "html": ["vulnerability_scan_report.html", "penetration_test_report.html", "report.html"],
            "pdf": ["vulnerability_scan_report.pdf", "penetration_test_report.pdf", "report.pdf"],
            "json": ["report.json"],
            "sarif": ["results.sarif"],
        }
        for candidate in name_map.get(fmt, []):
            p = run_dir / candidate
            if p.exists():
                return p
        return None

    # ── internal helpers ──────────────────────────────────────────────

    def _read_summary(self, run_dir: Path) -> RunSummary:
        events_file = run_dir / "events.jsonl"
        status = "running"
        start_time = ""
        end_time: str | None = None
        targets: list[str] = []
        severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        vuln_count = 0

        if events_file.exists():
            first_line = ""
            last_line = ""
            with events_file.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if not first_line:
                        first_line = line
                    last_line = line

                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    evt_type = evt.get("event_type", "")
                    if evt_type == "run.started":
                        meta = evt.get("run_metadata") or {}
                        start_time = meta.get("start_time", evt.get("timestamp", ""))
                        raw_targets = meta.get("targets", [])
                        targets = [
                            (t["original"] if isinstance(t, dict) else str(t))
                            for t in raw_targets
                        ]
                    elif evt_type == "run.configured":
                        cfg = (evt.get("payload") or {}).get("scan_config", {})
                        if not targets:
                            raw_targets = cfg.get("targets", [])
                            targets = [
                                (t["original"] if isinstance(t, dict) else str(t))
                                for t in raw_targets
                            ]
                    elif evt_type == "finding.created":
                        vuln_count += 1
                        payload = evt.get("payload") or {}
                        report = payload.get("report") or {}
                        sev = report.get("severity", "info").lower()
                        if sev in severity_counts:
                            severity_counts[sev] += 1
                    elif evt_type == "run.completed":
                        status = "completed"
                        meta = evt.get("run_metadata") or {}
                        end_time = meta.get("end_time", evt.get("timestamp"))

            if status != "completed" and last_line:
                try:
                    last_evt = json.loads(last_line)
                    if last_evt.get("status") == "completed":
                        status = "completed"
                        end_time = last_evt.get("timestamp")
                except json.JSONDecodeError:
                    pass

        available_reports: list[str] = []
        for fmt, names in [
            ("html", ["vulnerability_scan_report.html", "penetration_test_report.html", "report.html"]),
            ("pdf", ["vulnerability_scan_report.pdf", "penetration_test_report.pdf", "report.pdf"]),
            ("json", ["report.json"]),
            ("sarif", ["results.sarif"]),
        ]:
            if any((run_dir / n).exists() for n in names):
                available_reports.append(fmt)

        duration = _duration_display(start_time, end_time)

        return RunSummary(
            run_name=run_dir.name,
            status=status,
            start_time=start_time,
            end_time=end_time,
            targets=targets,
            vulnerability_count=vuln_count,
            severity_counts=severity_counts,
            available_reports=available_reports,
            duration_display=duration,
        )

    def _read_findings(self, run_dir: Path) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        events_file = run_dir / "events.jsonl"
        if not events_file.exists():
            return findings

        with events_file.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if evt.get("event_type") == "finding.created":
                    report = (evt.get("payload") or {}).get("report")
                    if report:
                        findings.append(report)

        findings.sort(key=lambda v: SEVERITY_ORDER.get(v.get("severity", "info").lower(), 5))
        return findings

    def _read_events(self, run_dir: Path, limit: int = 200) -> list[dict[str, Any]]:
        events_file = run_dir / "events.jsonl"
        if not events_file.exists():
            return []

        events: list[dict[str, Any]] = []
        with events_file.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        return events[-limit:]


def _duration_display(start: str, end: str | None) -> str:
    if not start or not end:
        return "N/A"
    try:
        from datetime import datetime

        s = datetime.fromisoformat(start.replace("Z", "+00:00"))
        e = datetime.fromisoformat(end.replace("Z", "+00:00"))
        delta = e - s
        minutes, seconds = divmod(int(delta.total_seconds()), 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            return f"{hours}h {minutes}m {seconds}s"
        if minutes:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"
    except (ValueError, TypeError):
        return "N/A"
