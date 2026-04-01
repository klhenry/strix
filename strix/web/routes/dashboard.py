"""Dashboard page — scan history and new scan form."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse


router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    run_store = request.app.state.run_store
    scan_manager = request.app.state.scan_manager
    templates = request.app.state.templates

    runs = run_store.list_runs()
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "runs": runs,
            "active_scan": scan_manager.active_run_name,
        },
    )
