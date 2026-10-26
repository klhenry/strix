"""Workspace screenshots survive scan cleanup and render under the correct finding."""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from agents.sandbox.sandboxes.unix_local import UnixLocalSandboxClient
from agents.tool_context import ToolContext
from PIL import Image

from strix.accountable.report_state import AccountableReportState
from strix.accountable.report_tool import accountable_create_vulnerability_report as report_tool
from strix.accountable.runtime import RailwaySession
from strix.report.state import set_global_report_state
from strix.reporting.evidence import collect_evidence, normalize_screenshot
from strix.reporting.html_report import generate_html_report
from strix.reporting.models import ScanReport
from strix.tools.reporting.tool import create_vulnerability_report


@pytest.fixture
async def screenshot_context(tmp_path, monkeypatch):
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    report = AccountableReportState("screenshot-test")
    report._run_dir = tmp_path / "run"
    report._run_dir.mkdir()
    set_global_report_state(report)
    client = UnixLocalSandboxClient()
    session = await client.create()
    session._inner = RailwaySession(state=session._inner.state)
    ctx = ToolContext(
        tool_name="create_vulnerability_report",
        tool_call_id="test",
        tool_arguments="{}",
        context={"agent_id": "root", "sandbox_session": session},
    )
    image = io.BytesIO()
    Image.new("RGB", (800, 600), "#eef2ff").save(image, format="JPEG")
    await session.write(Path("/workspace/proof.jpg"), io.BytesIO(image.getvalue()))
    yield ctx, report
    set_global_report_state(None)
    await client.delete(session)


def finding_fields():
    return {
        "title": "Reflected markup in search results",
        "description": "The search value is rendered without encoding.",
        "impact": "An attacker can replace the result markup.",
        "target": "https://example.test/search",
        "technical_analysis": "The response interpolates the query value.",
        "poc_description": "Submit the harmless markup marker and inspect the response.",
        "poc_script_code": "print('fixture')",
        "remediation_steps": "Encode the query value before rendering.",
        "evidence": "The controlled marker appears as rendered markup.",
        "assumptions": "A victim follows a crafted search link.",
        "counterevidence": "No output encoding was observed in the tested response.",
        "confidence": "high",
        "severity_change_conditions": "Output encoding would prevent the demonstrated injection.",
        "fix_effort": "low",
        "cvss_breakdown": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "R",
            "scope": "U",
            "confidentiality": "N",
            "integrity": "L",
            "availability": "N",
        },
        "screenshot_evidence": [{"path": "/workspace/proof.jpg", "caption": "Controlled <marker>"}],
    }


async def test_finding_screenshot_is_persistent_png_with_escaped_caption(screenshot_context):
    ctx, report = screenshot_context
    result = json.loads(await report_tool.on_invoke_tool(ctx, json.dumps(finding_fields())))
    assert result["success"]
    saved = report.get_run_dir() / "evidence" / result["screenshots_saved"][0]
    assert saved.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert list(collect_evidence(report.get_run_dir())) == [result["report_id"]]
    # The output is independent of the ephemeral browser workspace.
    ctx.context["sandbox_session"].normalize_path(Path("/workspace/proof.jpg")).unlink()
    html = generate_html_report(
        ScanReport.from_tracer(report), report.get_run_dir() / "report.html"
    )
    text = html.read_text()
    assert "data:image/png;base64," in text
    assert "Controlled &lt;marker&gt;" in text
    assert "Controlled <marker>" not in text
    assert saved.exists()


@pytest.mark.parametrize("path", ["../outside.png", "/etc/passwd", "/workspace/missing.png"])
async def test_invalid_paths_do_not_file_a_finding(screenshot_context, path):
    ctx, report = screenshot_context
    fields = finding_fields()
    fields["screenshot_evidence"][0]["path"] = path
    result = json.loads(await report_tool.on_invoke_tool(ctx, json.dumps(fields)))
    assert result["success"] is False
    assert report.vulnerability_reports == []


async def test_rejects_symlink_outside_workspace(screenshot_context, tmp_path):
    ctx, report = screenshot_context
    outside = tmp_path / "outside.png"
    Image.new("RGB", (10, 10)).save(outside)
    session = ctx.context["sandbox_session"]
    root = Path(session.state.manifest.root)
    (root / "leak.png").symlink_to(outside)
    fields = finding_fields()
    fields["screenshot_evidence"][0]["path"] = "/workspace/leak.png"
    result = json.loads(await report_tool.on_invoke_tool(ctx, json.dumps(fields)))
    assert result["success"] is False
    assert report.vulnerability_reports == []


async def test_upstream_validation_still_rejects_empty_evidence(screenshot_context):
    ctx, report = screenshot_context
    fields = finding_fields()
    fields["evidence"] = ""
    result = json.loads(await report_tool.on_invoke_tool(ctx, json.dumps(fields)))
    assert result["success"] is False
    assert report.vulnerability_reports == []
    assert collect_evidence(report.get_run_dir()) == {}


async def test_duplicate_result_is_preserved_without_attachments(screenshot_context, monkeypatch):
    ctx, report = screenshot_context
    duplicate = json.dumps({"success": False, "duplicate_of": "vuln-0001"})
    monkeypatch.setattr(
        create_vulnerability_report, "on_invoke_tool", AsyncMock(return_value=duplicate)
    )
    assert await report_tool.on_invoke_tool(ctx, json.dumps(finding_fields())) == duplicate
    assert collect_evidence(report.get_run_dir()) == {}


def test_screenshot_extension_does_not_modify_upstream_schema():
    assert "screenshot_evidence" not in create_vulnerability_report.params_json_schema["properties"]
    assert "screenshot_evidence" in report_tool.params_json_schema["properties"]


@pytest.mark.parametrize("raw", ["", [{}], [{"path": "proof.jpg", "caption": "  "}]])
async def test_invalid_attachment_schema_is_rejected(screenshot_context, raw):
    ctx, report = screenshot_context
    fields = finding_fields()
    fields["screenshot_evidence"] = raw
    result = json.loads(await report_tool.on_invoke_tool(ctx, json.dumps(fields)))
    assert result["success"] is False
    assert not report.vulnerability_reports


async def test_invalid_image_is_rejected(screenshot_context):
    ctx, report = screenshot_context
    await ctx.context["sandbox_session"].write(
        Path("/workspace/proof.jpg"), io.BytesIO(b"not an image")
    )
    result = json.loads(await report_tool.on_invoke_tool(ctx, json.dumps(finding_fields())))
    assert result["success"] is False
    assert not report.vulnerability_reports


async def test_nonvisual_finding_needs_no_screenshot(screenshot_context):
    ctx, _report = screenshot_context
    fields = finding_fields()
    fields["screenshot_evidence"] = None
    result = json.loads(await report_tool.on_invoke_tool(ctx, json.dumps(fields)))
    assert result["success"]


def test_normalization_preserves_transparency_and_discards_metadata():
    image = Image.new("RGBA", (2, 2), (255, 0, 0, 0))
    image.info["exif"] = b"private source metadata"
    source = io.BytesIO()
    image.save(source, format="PNG")
    with Image.open(io.BytesIO(normalize_screenshot(source.getvalue()))) as normalized:
        assert normalized.getpixel((0, 0)) == (255, 255, 255)
        assert not normalized.info
