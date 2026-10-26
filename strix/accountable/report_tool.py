"""Attach reviewed workspace screenshots while retaining upstream finding validation."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from agents.sandbox.errors import SandboxError
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from strix.report.state import get_global_report_state
from strix.reporting.evidence import normalize_screenshot
from strix.tools.reporting.tool import create_vulnerability_report


if TYPE_CHECKING:
    from agents.tool_context import ToolContext


class ScreenshotEvidence(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: str = Field(min_length=1)
    caption: str = Field(min_length=1, max_length=500)


_SCREENSHOTS = TypeAdapter(list[ScreenshotEvidence])
_MAX_SCREENSHOT_BYTES = 10 * 1024 * 1024


async def _read_screenshots(ctx: ToolContext, raw: Any) -> list[tuple[bytes, str]]:
    screenshots = _SCREENSHOTS.validate_python(raw)
    if len(screenshots) > 6:
        raise ValueError("Attach at most six screenshots per finding")
    if not screenshots:
        return []
    session = ctx.context["sandbox_session"]
    images: list[tuple[bytes, str]] = []
    for screenshot in screenshots:
        # The same workspace policy used by the SDK view_image tool rejects
        # paths outside the scan. Never read a model-supplied host path directly.
        path = session.normalize_path(Path(screenshot.path))
        stream = await session.read(path)
        try:
            payload = stream.read(_MAX_SCREENSHOT_BYTES + 1)
        finally:
            stream.close()
        if len(payload) > _MAX_SCREENSHOT_BYTES:
            raise ValueError("Screenshot exceeds 10 MiB; crop or resize it first")
        images.append((normalize_screenshot(payload), screenshot.caption.strip()))
    return images


async def _invoke(ctx: ToolContext, arguments: str) -> Any:
    fields = json.loads(arguments)
    raw = fields.pop("screenshot_evidence", None)
    try:
        images = await _read_screenshots(ctx, [] if raw is None else raw)
    except (OSError, ValueError, KeyError, SandboxError) as exc:
        return json.dumps({"success": False, "error": f"Invalid screenshot evidence: {exc}"})

    result = await create_vulnerability_report.on_invoke_tool(ctx, json.dumps(fields))
    response = json.loads(result) if isinstance(result, str) else result
    if not images or not response.get("success"):
        return result
    report = get_global_report_state()
    report_id = response.get("report_id")
    if report is None or not any(r["id"] == report_id for r in report.vulnerability_reports):
        return result
    evidence_dir = report.get_run_dir() / "evidence"
    saved: list[str] = []
    try:
        evidence_dir.mkdir(exist_ok=True)
        batch = uuid4().hex
        for index, (payload, caption) in enumerate(images):
            image = evidence_dir / f"{report_id}_{batch}_{index:02d}.png"
            image.write_bytes(payload)
            image.with_suffix(".json").write_text(
                json.dumps({"caption": caption}), encoding="utf-8"
            )
            saved.append(image.name)
    except OSError:
        # The finding is already filed. Preserve its success/id so the model
        # cannot accidentally duplicate it while retrying an attachment.
        response["warning"] = "Finding saved, but some screenshots could not be persisted."
    response["screenshots_saved"] = saved
    return json.dumps(response)


_schema = copy.deepcopy(create_vulnerability_report.params_json_schema)
_schema["properties"]["screenshot_evidence"] = {
    "description": "Reviewed, redacted screenshots proving this finding; null when not applicable.",
    "anyOf": [
        {"type": "array", "items": ScreenshotEvidence.model_json_schema()},
        {"type": "null"},
    ],
}
_schema["required"].append("screenshot_evidence")

accountable_create_vulnerability_report = replace(
    create_vulnerability_report,
    params_json_schema=_schema,
    on_invoke_tool=_invoke,
    description=create_vulnerability_report.description
    + "\n\nFor a browser-visible finding, capture focused screenshots with agent-browser, "
    "inspect them with view_image, and include screenshot_evidence [{path, caption}] here. "
    "Use workspace paths. Crop/redact secrets, tokens, personal and unrelated customer data "
    "BEFORE attaching. Captions must explain the observed proof without credentials or "
    "internal paths. Images are copied into the finding's branded HTML/PDF report. "
    "Use null for findings without relevant visual evidence; never fabricate screenshots.",
)
