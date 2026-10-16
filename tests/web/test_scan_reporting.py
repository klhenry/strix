"""Exercise the upstream runner adapter through persisted Accountable report read-back."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import pytest
from agents.tool_context import ToolContext

from strix.accountable.finish import accountable_finish_scan
from strix.report.state import get_global_report_state
from strix.web.services.run_store import RunStore
from strix.web.services.scan_manager import ScanManager


@pytest.mark.parametrize("has_finding", [True, False])
@pytest.mark.parametrize("telemetry", ["0", "1"])
async def test_scan_persists_findings_and_final_report(
    monkeypatch, tmp_path, has_finding, telemetry
):
    monkeypatch.setenv("STRIX_TELEMETRY", telemetry)
    monkeypatch.setenv("OPENAI_AGENTS_DISABLE_TRACING", "1")
    monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path))
    monkeypatch.setenv("STRIX_LLM", "openrouter/z-ai/glm-5.3")

    def render_pdf(_html, output):
        output.write_bytes(b"%PDF-fixture")
        return output

    monkeypatch.setattr("strix.reporting.pdf_report.generate_pdf_report_sync", render_pdf)

    async def run(**kwargs):
        report = get_global_report_state()
        assert kwargs["scan_config"]["accountable"] is True
        if has_finding:
            report.add_vulnerability_report(
                title="Missing Content-Security-Policy",
                severity="low",
                description="A read-only response lacked a CSP header.",
                target="https://example.test/",
                remediation_steps="Configure a CSP.",
            )
        fields = {
            "executive_summary": "Reviewed the public response headers.",
            "methodology": "Low-volume, read-only HTTP header inspection.",
            "technical_analysis": "Observed response headers without exploitation.",
            "recommendations": "Maintain browser security controls.",
            "limitations": "Assessed only the public page with a low-volume read-only request.",
            "scope_coverage": "<coverage><target><asset>https://example.test/</asset><status>"
            + ("tested_with_findings" if has_finding else "tested_no_findings")
            + "</status><authentication>unauthenticated</authentication>"
            "<notes>Inspected public response headers.</notes></target></coverage>",
        }
        ctx = ToolContext(
            tool_name="finish_scan",
            tool_call_id="test",
            tool_arguments="{}",
            context={"agent_id": "root", "parent_id": None},
        )
        result = json.loads(await accountable_finish_scan.on_invoke_tool(ctx, json.dumps(fields)))
        if not has_finding:
            assert result["error"] == "no_vulnerability_reports"
            result = json.loads(
                await accountable_finish_scan.on_invoke_tool(ctx, json.dumps(fields))
            )
        assert result["scan_completed"]
        return object()

    monkeypatch.setattr("strix.core.runner.run_strix_scan", run)
    manager = ScanManager(RunStore(tmp_path))
    monkeypatch.setattr(manager, "_run_scan", manager._run_scan_in_process)
    name = await manager.start_scan(["https://example.test/"], scan_mode="vuln_scan")
    await asyncio.wait_for(manager._scans[name].task, 10)
    detail = manager.run_store.get_run(name)
    assert detail.summary.status == "completed"
    assert len(detail.vulnerabilities) == int(has_finding)
    assert detail.executive_summary
    assert set(detail.summary.available_reports) == {"pdf", "html", "json", "sarif"}


async def test_sdk_finish_waits_for_children_without_persisting(monkeypatch):
    from strix.core.agents import AgentCoordinator

    coordinator = AgentCoordinator()
    await coordinator.register("root", parent_id=None, name="root", task="scan")
    await coordinator.register("child", parent_id="root", name="child", task="scan")
    ctx = ToolContext(
        tool_name="finish_scan",
        tool_call_id="test",
        tool_arguments="{}",
        context={"agent_id": "root", "parent_id": None, "coordinator": coordinator},
    )
    persist = AsyncMock()
    monkeypatch.setattr("strix.accountable.finish.asyncio.to_thread", persist)
    fields = {
        "executive_summary": "s",
        "methodology": "m",
        "technical_analysis": "t",
        "recommendations": "r",
        "scope_coverage": "",
        "limitations": "l",
    }
    result = json.loads(await accountable_finish_scan.on_invoke_tool(ctx, json.dumps(fields)))
    assert result["success"] is False
    persist.assert_not_awaited()
