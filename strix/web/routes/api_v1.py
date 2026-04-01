"""Webhook API v1 — machine-to-machine endpoints for Accountable integration."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from strix.web.auth import require_api_key
from strix.web.models.api_v1 import (
    ScanAcceptedResponse,
    ScanRequest,
    ScanStatusResponse,
)

router = APIRouter(prefix="/api/v1", tags=["api_v1"])


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
