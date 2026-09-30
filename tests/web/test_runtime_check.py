"""Readiness failures must stop scans before the agent is started."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from strix.web.services import runtime_check, scan_worker
from strix.web.services.scan_manager import ScanManager


def test_dependency_check_names_missing_python_module_and_binary(monkeypatch):
    def import_module(name):
        if name == "libtmux":
            raise ImportError("No module named 'libtmux'")

    monkeypatch.setattr(runtime_check.importlib, "import_module", import_module)
    monkeypatch.setattr(
        runtime_check.shutil, "which", lambda name: None if name == "tmux" else name
    )
    with pytest.raises(RuntimeError, match="libtmux.*missing executable: tmux"):
        runtime_check.check_dependencies()


@pytest.mark.asyncio
async def test_failed_readiness_does_not_start_agent(monkeypatch, tmp_path):
    def fail():
        raise RuntimeError("Scan runtime is not ready: missing executable: tmux")

    monkeypatch.setattr(runtime_check, "check_dependencies", fail)
    execute = AsyncMock()
    monkeypatch.setattr(ScanManager, "_run_scan_in_process", execute)
    connection = MagicMock()
    connection.poll.return_value = False
    await scan_worker._run_worker(
        connection,
        {
            "run_name": "not-ready",
            "runs_dir": str(tmp_path),
            "workspace": str(tmp_path / "workspace"),
            "targets": ["https://example.test"],
            "scan_mode": "deep",
            "instruction": "",
        },
    )
    execute.assert_not_awaited()
    terminal_result = connection.send.call_args.args[0]
    assert terminal_result["type"] == "result"
    assert terminal_result["error"] == "Scan runtime is not ready: missing executable: tmux"


@pytest.mark.asyncio
async def test_proxy_startup_failure_terminates_process(monkeypatch, tmp_path):
    proxy = MagicMock(returncode=9)
    monkeypatch.setattr(
        runtime_check.asyncio, "create_subprocess_exec", AsyncMock(return_value=proxy)
    )
    cleanup = AsyncMock()
    monkeypatch.setattr(runtime_check, "_stop_process", cleanup)
    with pytest.raises(RuntimeError, match="proxy exited during startup"):
        await runtime_check._start_proxy(tmp_path)
    cleanup.assert_awaited_once_with(proxy)


@pytest.mark.asyncio
async def test_failed_browser_readiness_prevents_proxy_and_scan(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime_check, "check_dependencies", lambda: None)
    monkeypatch.setattr(runtime_check, "_check_terminal", lambda _workspace: None)
    monkeypatch.setattr(
        runtime_check, "_check_browser", AsyncMock(side_effect=RuntimeError("Browser missing"))
    )
    start_proxy = AsyncMock()
    monkeypatch.setattr(runtime_check, "_start_proxy", start_proxy)
    tmux = MagicMock(wait=AsyncMock())
    monkeypatch.setattr(
        runtime_check.asyncio, "create_subprocess_exec", AsyncMock(return_value=tmux)
    )
    monkeypatch.delenv("STRIX_RUNTIME_DIR", raising=False)
    monkeypatch.setenv("STRIX_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("STRIX_TMUX_SOCKET", str(tmp_path / "unused.sock"))
    with pytest.raises(RuntimeError, match="Browser missing"):
        async with runtime_check.scan_runtime(Path(tmp_path)):
            pytest.fail("An unready runtime must never start a scan")
    start_proxy.assert_not_awaited()
    tmux.wait.assert_awaited_once()
