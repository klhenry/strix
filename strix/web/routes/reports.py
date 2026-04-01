"""Report download routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse


router = APIRouter()

_CONTENT_TYPES: dict[str, str] = {
    "html": "text/html",
    "pdf": "application/pdf",
    "json": "application/json",
    "sarif": "application/json",
}


@router.get("/scans/{run_name}/reports/{fmt}", response_model=None)
async def download_report(request: Request, run_name: str, fmt: str) -> FileResponse | HTMLResponse:
    run_store = request.app.state.run_store
    path = run_store.get_report_path(run_name, fmt)

    if path is None:
        return HTMLResponse(f"<h2>No {fmt} report available for {run_name}</h2>", status_code=404)

    content_type = _CONTENT_TYPES.get(fmt, "application/octet-stream")
    filename = f"{run_name}_report.{fmt}"

    return FileResponse(
        path=str(path),
        media_type=content_type,
        filename=filename,
    )
