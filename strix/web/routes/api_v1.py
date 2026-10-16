"""Webhook API v1 — machine-to-machine endpoints for Accountable integration."""

from __future__ import annotations

import asyncio
import shutil
import tempfile
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from strix.web.auth import require_api_key
from strix.web.models.api_v1 import (
    AssessmentRequest,
    InstructionPresetRequest,
    ScanAcceptedResponse,
    ScanRequest,
    ScanStatusResponse,
)


router = APIRouter(prefix="/api/v1", tags=["api_v1"])


@router.post("/instruction-presets", dependencies=[Depends(require_api_key)])
async def register_instruction_preset(
    request: Request, body: InstructionPresetRequest
) -> dict[str, str | int]:
    """Attach private instructions to exactly one matching legacy app request."""
    try:
        identifier = request.app.state.scan_manager.instruction_presets.register(body)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"preset_id": identifier, "expires_in_seconds": body.expires_in_seconds}


@router.delete("/instruction-presets/{identifier}", dependencies=[Depends(require_api_key)])
async def revoke_instruction_preset(request: Request, identifier: str) -> dict[str, bool]:
    request.app.state.scan_manager.instruction_presets.revoke(identifier)
    return {"revoked": True}


@router.post(
    "/scans",
    response_model=ScanAcceptedResponse,
    dependencies=[Depends(require_api_key)],
)
async def create_scan(request: Request, body: ScanRequest) -> ScanAcceptedResponse:
    """Accept a scan request from Accountable. Returns immediately."""
    scan_manager = request.app.state.scan_manager

    try:
        run_name = await scan_manager.start_webhook_scan(body)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return ScanAcceptedResponse(external_scan_id=run_name)


@router.get(
    "/scans/{scan_id}/status",
    response_model=ScanStatusResponse,
    dependencies=[Depends(require_api_key)],
)
async def scan_status(request: Request, scan_id: str) -> ScanStatusResponse:
    """Check scan status by external scan ID (from Accountable)."""
    scan_manager = request.app.state.scan_manager
    result = scan_manager.get_webhook_scan_status(scan_id)

    if result.get("status") == "not_found":
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanStatusResponse(
        status=result["status"],
        progress=result.get("progress", 0),
        error_message=result.get("error_message"),
    )


@router.post(
    "/assessments",
    response_model=ScanAcceptedResponse,
    dependencies=[Depends(require_api_key)],
)
async def create_assessment(request: Request, body: AssessmentRequest) -> ScanAcceptedResponse:
    """Run an authenticated CLI assessment; artifacts remain in the scanner."""
    try:
        run_name = await request.app.state.scan_manager.start_scan(
            targets=list(dict.fromkeys(str(url) for url in body.target_urls)),
            instruction=body.instruction,
            scan_mode=body.scan_mode,
            model=body.model,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return ScanAcceptedResponse(external_scan_id=run_name)


@router.get("/scans/{scan_id}/evidence", dependencies=[Depends(require_api_key)])
async def scan_evidence(request: Request, scan_id: str) -> FileResponse:
    """Authenticated export for verification; includes private SDK conversations."""
    store = request.app.state.run_store
    base = store.runs_dir.resolve()
    run_dir = (base / scan_id).resolve()
    if run_dir.parent != base or not run_dir.is_dir():
        raise HTTPException(status_code=404, detail="Scan not found")
    if request.app.state.scan_manager.is_scan_active(scan_id):
        raise HTTPException(status_code=409, detail="Wait for the assessment to finish")
    temp_dir = Path(tempfile.mkdtemp(prefix="strix-evidence-"))
    archive_path = temp_dir / "evidence.zip"

    def write_archive() -> None:
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name in (
                "run.json",
                "report.json",
                "vulnerabilities.json",
                "coverage.json",
                "events.jsonl",
                ".state/agents.json",
                ".state/agents.db",
            ):
                source = (run_dir / name).resolve()
                if source.is_relative_to(run_dir) and source.is_file():
                    archive.write(source, name)
        archive_path.chmod(0o600)

    try:
        await asyncio.to_thread(write_archive)
    except BaseException:
        shutil.rmtree(temp_dir)
        raise
    return FileResponse(
        archive_path,
        media_type="application/zip",
        filename=f"{scan_id}-evidence.zip",
        background=BackgroundTask(shutil.rmtree, temp_dir),
    )
