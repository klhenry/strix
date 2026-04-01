"""Scan API — start, view, pause, resume, comment, stop scans."""

from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse


router = APIRouter()


@router.post("/api/scans")
async def start_scan(
    request: Request,
    target: str = Form(...),
    scan_mode: str = Form("deep"),
    instruction: str = Form(""),
) -> RedirectResponse:
    scan_manager = request.app.state.scan_manager

    targets = [t.strip() for t in target.split(",") if t.strip()]
    if not targets:
        return RedirectResponse(url="/", status_code=303)

    try:
        run_name = await scan_manager.start_scan(
            targets=targets,
            scan_mode=scan_mode,
            instruction=instruction,
        )
        return RedirectResponse(url=f"/scans/{run_name}", status_code=303)
    except RuntimeError:
        return RedirectResponse(url="/", status_code=303)


@router.get("/scans/{run_name}", response_class=HTMLResponse)
async def scan_detail(request: Request, run_name: str) -> HTMLResponse:
    run_store = request.app.state.run_store
    scan_manager = request.app.state.scan_manager
    templates = request.app.state.templates

    detail = run_store.get_run(run_name)
    is_live = scan_manager.is_scan_active(run_name)
    is_paused = is_live and scan_manager._get_scan_for(run_name) is not None and scan_manager._get_scan_for(run_name).paused

    if detail is None:
        return templates.TemplateResponse(
            request,
            "scan_detail.html",
            {
                "detail": None,
                "run_name": run_name,
                "is_live": is_live,
                "is_paused": is_paused,
            },
        )

    return templates.TemplateResponse(
        request,
        "scan_detail.html",
        {
            "detail": detail,
            "run_name": run_name,
            "is_live": is_live,
            "is_paused": is_paused,
        },
    )


@router.get("/api/scans/{run_name}")
async def scan_status(request: Request, run_name: str) -> JSONResponse:
    run_store = request.app.state.run_store
    scan_manager = request.app.state.scan_manager
    detail = run_store.get_run(run_name)
    if not detail:
        return JSONResponse({"error": "not found"}, status_code=404)

    is_live = scan_manager.is_scan_active(run_name)
    scan_state = scan_manager._get_scan_for(run_name)
    is_paused = is_live and scan_state is not None and scan_state.paused
    return JSONResponse({
        "run_name": detail.summary.run_name,
        "status": "paused" if is_paused else detail.summary.status,
        "vulnerability_count": detail.summary.vulnerability_count,
        "severity_counts": detail.summary.severity_counts,
        "duration": detail.summary.duration_display,
        "available_reports": detail.summary.available_reports,
    })


@router.get("/api/scans/{run_name}/findings")
async def scan_findings(request: Request, run_name: str) -> JSONResponse:
    run_store = request.app.state.run_store
    detail = run_store.get_run(run_name)
    if not detail:
        return JSONResponse({"error": "not found"}, status_code=404)

    return JSONResponse({"findings": detail.vulnerabilities})


@router.post("/api/scans/{run_name}/pause")
async def pause_scan(request: Request, run_name: str) -> JSONResponse:
    scan_manager = request.app.state.scan_manager
    if not scan_manager.is_scan_active(run_name):
        return JSONResponse({"success": False, "error": "Not an active scan"}, status_code=400)

    success = scan_manager.pause_scan(run_name)
    return JSONResponse({"success": success, "status": "paused" if success else "unchanged"})


@router.post("/api/scans/{run_name}/resume")
async def resume_scan(request: Request, run_name: str) -> JSONResponse:
    scan_manager = request.app.state.scan_manager
    if not scan_manager.is_scan_active(run_name):
        return JSONResponse({"success": False, "error": "Not an active scan"}, status_code=400)

    success = scan_manager.resume_scan(run_name)
    return JSONResponse({"success": success, "status": "running" if success else "unchanged"})


@router.post("/api/scans/{run_name}/comment")
async def send_comment(
    request: Request,
    run_name: str,
    comment: str = Form(...),
) -> JSONResponse:
    scan_manager = request.app.state.scan_manager
    if not scan_manager.is_scan_active(run_name):
        return JSONResponse({"success": False, "error": "Not an active scan"}, status_code=400)

    success = scan_manager.send_comment(comment, run_name)
    return JSONResponse({"success": success})


@router.post("/api/scans/{run_name}/stop")
async def stop_scan(request: Request, run_name: str) -> RedirectResponse:
    scan_manager = request.app.state.scan_manager
    if scan_manager.is_scan_active(run_name):
        await scan_manager.stop_scan(run_name)
    return RedirectResponse(url=f"/scans/{run_name}", status_code=303)
