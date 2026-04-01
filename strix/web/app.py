"""FastAPI application factory for the Strix web dashboard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from strix.web.services.run_store import RunStore
from strix.web.services.scan_manager import ScanManager


_STATIC_DIR = Path(__file__).parent / "static"
_TEMPLATES_DIR = Path(__file__).parent / "templates"


def create_app(strix_runs_dir: Path | None = None) -> FastAPI:
    app = FastAPI(title="Strix Dashboard", docs_url=None, redoc_url=None)

    run_store = RunStore(strix_runs_dir)
    scan_manager = ScanManager(run_store)

    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    # Store on app state for route access
    app.state.run_store = run_store  # type: ignore[attr-defined]
    app.state.scan_manager = scan_manager  # type: ignore[attr-defined]
    app.state.templates = templates  # type: ignore[attr-defined]

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Health check
    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "healthy"}

    # Import and include routers
    from strix.web.routes.api_v1 import router as api_v1_router
    from strix.web.routes.dashboard import router as dashboard_router
    from strix.web.routes.events import router as events_router
    from strix.web.routes.reports import router as reports_router
    from strix.web.routes.scans import router as scans_router

    app.include_router(api_v1_router)
    app.include_router(dashboard_router)
    app.include_router(scans_router)
    app.include_router(events_router)
    app.include_router(reports_router)

    return app


def _load_strix_config() -> None:
    """Load env vars from ~/.strix/cli-config.json, same as the CLI does."""
    import json
    import os

    config_path = Path.home() / ".strix" / "cli-config.json"
    if not config_path.exists():
        return

    try:
        with config_path.open() as f:
            config = json.load(f)
        env_vars = config.get("env", {})
        for key, value in env_vars.items():
            if key not in os.environ:  # Don't override explicit env vars
                os.environ[key] = value
        if env_vars:
            print(f"  Loaded config from {config_path}")  # noqa: T201
    except (json.JSONDecodeError, OSError):
        pass


def run_server(
    host: str = "127.0.0.1",
    port: int = 8420,
    strix_runs_dir: Path | None = None,
) -> None:
    import os

    import uvicorn

    _load_strix_config()
    port = int(os.environ.get("PORT", str(port)))
    app = create_app(strix_runs_dir)
    print(f"\n  Strix Dashboard → http://{host}:{port}\n")  # noqa: T201
    uvicorn.run(app, host=host, port=port, log_level="info")
