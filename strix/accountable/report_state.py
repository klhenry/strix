"""Project upstream SDK artifacts into Accountable's reports and dashboard events."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from strix.report.state import ReportState


class AccountableReportState(ReportState):
    def __init__(self, run_name: str):
        super().__init__(run_name)
        self.run_metadata = self.run_record
        self.tools_used: set[str] = set()
        self.vulnerability_found_callback = lambda report: self._emit_event(
            "finding.created", payload={"report": report}, status="created"
        )
        self.vulnerability_updated_callback = lambda report: self._emit_event(
            "finding.updated", payload={"report": report}, status="updated"
        )
        self.vulnerability_deleted_callback = lambda report: self._emit_event(
            "finding.deleted", payload={"report": report}, status="deleted"
        )

    def _emit_event(
        self,
        event_type: str,
        *,
        payload: dict[str, Any] | None = None,
        status: str = "running",
        source: str = "strix.accountable",
        **_: Any,
    ) -> None:
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "run_id": self.run_id,
            "payload": payload or {},
            "status": status,
            "source": source,
        }
        if event_type == "run.started":
            event["run_metadata"] = {
                "start_time": self.start_time,
                "targets": (self.scan_config or {}).get("targets", []),
            }
        with (self.get_run_dir() / "events.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")

    def set_scan_config(self, config: dict[str, Any]) -> None:
        super().set_scan_config(config)
        self.run_record["targets"] = config.get("targets", [])
        self._emit_event("run.started")
        # Persist target metadata without duplicating credential-bearing instructions in SSE.
        self.save_run_data()

    def get_tools_used(self) -> list[str]:
        return sorted(self.tools_used)

    def stream_event(self, agent_id: str, event: Any) -> None:
        kind = getattr(event, "type", "")
        if kind != "run_item_stream_event":
            return
        item = getattr(event, "item", None)
        raw = getattr(item, "raw_item", None)
        name = getattr(raw, "name", None)
        item_type = getattr(item, "type", "")
        if name and item_type == "tool_call_item":
            if name in {"exec_command", "write_stdin"}:
                self.tools_used.add("Command-line security testing")
            elif name in {"list_requests", "view_request", "repeat_request", "list_sitemap"}:
                self.tools_used.add("Intercepting HTTP proxy analysis")
            self._emit_event("tool.started", payload={"agent_id": agent_id, "tool_name": name})
        elif item_type == "tool_call_output_item":
            self._emit_event("tool.completed", payload={"agent_id": agent_id})

    def generate_reports(self) -> None:
        from strix.reporting.html_report import generate_html_report
        from strix.reporting.json_report import generate_json_summary
        from strix.reporting.models import ScanReport
        from strix.reporting.pdf_report import generate_pdf_report_sync
        from strix.reporting.sarif_report import generate_sarif_report

        report = ScanReport.from_tracer(self)
        run_dir = self.get_run_dir()
        basename = (
            "vulnerability_scan_report"
            if (self.scan_config or {}).get("scan_mode") == "vuln_scan"
            else "penetration_test_report"
        )
        html = run_dir / f"{basename}.html"
        pdf = run_dir / f"{basename}.pdf"
        generate_html_report(report, html)
        generate_json_summary(report, run_dir / "report.json")
        generate_sarif_report(report, run_dir / "results.sarif")
        for _ in range(2):
            result = generate_pdf_report_sync(html, pdf)
            if result and pdf.exists() and pdf.stat().st_size > 0:
                return
        raise RuntimeError("Branded PDF generation failed")
