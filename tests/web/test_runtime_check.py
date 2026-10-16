"""SDK runtime readiness must fail before starting an assessment."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from strix.web.services import runtime_check, scan_worker
from strix.web.services.scan_manager import ScanManager


def test_dependency_check_names_missing_module_and_binary(monkeypatch):
    def import_module(name):
        if name == "caido_sdk_client":
            raise ImportError("No module named caido_sdk_client")

    monkeypatch.setattr(runtime_check.importlib, "import_module", import_module)
    monkeypatch.setattr(
        runtime_check.shutil, "which", lambda name: None if name == "agent-browser" else name
    )
    with pytest.raises(RuntimeError, match=r"caido_sdk_client.*missing executable: agent-browser"):
        runtime_check.check_dependencies()


@pytest.mark.asyncio
async def test_failed_readiness_does_not_start_agent(monkeypatch, tmp_path):
    def fail():
        raise RuntimeError("Scan runtime is not ready: missing executable: agent-browser")

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
    assert "missing executable: agent-browser" in connection.send.call_args.args[0]["error"]
