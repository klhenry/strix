"""Exercise the runner through real reporting tools and persisted report read-back."""

from __future__ import annotations

import asyncio
import importlib
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from strix.agents.state import AgentState
from strix.telemetry.tracer import get_global_tracer
from strix.tools.finish.finish_actions import finish_scan
from strix.tools.reporting.reporting_actions import create_vulnerability_report
from strix.web.services.run_store import RunStore
from strix.web.services.scan_manager import ScanManager


@pytest.mark.asyncio
@pytest.mark.parametrize("has_finding", [True, False])
@pytest.mark.parametrize("telemetry", ["0", "1"])
async def test_scan_persists_findings_and_final_report(
    monkeypatch, tmp_path, has_finding, telemetry
):
    monkeypatch.setenv("STRIX_TELEMETRY", telemetry)
    monkeypatch.setenv("STRIX_OTEL_TELEMETRY", telemetry)
    monkeypatch.setenv("STRIX_POSTHOG_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr("strix.llm.config.LLMConfig", MagicMock())
    monkeypatch.setattr("strix.runtime.cleanup_runtime", MagicMock())
    monkeypatch.setattr("subprocess.run", MagicMock(return_value=MagicMock(stdout="")))
    monkeypatch.setattr(
        "strix.tools.registry.get_tool_names",
        lambda: ["create_vulnerability_report", "finish_scan"],
    )

    # Browser installation is not required for this regression suite. A separate
    # local smoke test exercises Chromium PDF rendering.
    def render_pdf(_html, output):
        output.write_bytes(b"%PDF-fixture")
        return output

    monkeypatch.setattr("strix.reporting.pdf_report.generate_pdf_report_sync", render_pdf)

    class ReportingAgent:
        def __init__(self, _config):
            self.state = AgentState()

        async def execute_scan(self, _config):
            if has_finding:
                finding = create_vulnerability_report(
                    title="Missing Content-Security-Policy",
                    description="The login response lacks a Content-Security-Policy header.",
                    impact="The browser lacks this defense against script injection.",
                    target="https://example.test/",
                    technical_analysis="A read-only GET returned HTTP 200 without a CSP header.",
                    remediation_steps="Configure a restrictive Content-Security-Policy.",
                    cvss_breakdown=(
                        "<attack_vector>N</attack_vector><attack_complexity>L</attack_complexity>"
                        "<privileges_required>N</privileges_required><user_interaction>R</user_interaction>"
                        "<scope>U</scope><confidentiality>L</confidentiality>"
                        "<integrity>N</integrity><availability>N</availability>"
                    ),
                )
                assert finding["success"] is True
            fields = {
                "executive_summary": "Reviewed the public response headers.",
                "methodology": "Low-volume, read-only HTTP header inspection.",
                "technical_analysis": "Observed response headers; no exploitation performed.",
                "recommendations": "Maintain browser security controls and reassess periodically.",
                "limitations": "Assessed only the public page with a low-volume read-only request.",
                "scope_coverage": (
                    "<coverage><target><asset>https://example.test/</asset>"
                    "<status>"
                    + ("tested_with_findings" if has_finding else "tested_no_findings")
                    + "</status>"
                    "<authentication>unauthenticated</authentication>"
                    "<notes>Inspected public HTTP response headers.</notes></target></coverage>"
                ),
                "agent_state": self.state,
            }
            result = finish_scan(**fields)
            if not has_finding:
                assert result.get("error") == "no_vulnerability_reports"
                result = finish_scan(**fields)
            assert result.get("scan_completed") is True, result
            assert get_global_tracer().scan_results["scan_completed"] is True
            return {"success": True}

    monkeypatch.setattr(
        importlib.import_module("strix.agents.StrixAgent"), "StrixAgent", ReportingAgent
    )
    manager = ScanManager(RunStore(tmp_path))
    monkeypatch.setattr(manager, "_run_scan", manager._run_scan_in_process)
    run_name = await manager.start_scan(["https://example.test/"], scan_mode="vuln_scan")
    await asyncio.wait_for(manager._scans[run_name].task, timeout=10)

    assert manager._scans[run_name].last_error is None
    detail = manager.run_store.get_run(run_name)
    assert detail.summary.status == "completed"
    assert detail.summary.vulnerability_count == int(has_finding)
    assert detail.executive_summary == "Reviewed the public response headers."
    report = json.loads(manager.run_store.get_report_path(run_name, "json").read_text())
    assert report["statistics"]["total_vulnerabilities"] == int(has_finding)
    assert report["executive_summary"] == detail.executive_summary
    from strix.web.services.webhook import build_findings_summary

    summary = build_findings_summary(tmp_path / run_name)
    assert sum(summary.values()) == int(has_finding)
    assert "Scope Coverage" in report["methodology"]
    assert manager.run_store.get_report_path(run_name, "html").stat().st_size > 1000
    assert manager.run_store.get_report_path(run_name, "pdf").stat().st_size > 0
