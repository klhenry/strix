"""Regression tests for Accountable webhook scan lifecycle behavior."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest
import pytest_asyncio

from strix.web.models.api_v1 import ScanRequest
from strix.web.services.run_store import RunStore
from strix.web.services.scan_manager import ScanManager


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from pathlib import Path


def _request(**overrides: Any) -> ScanRequest:
    data: dict[str, Any] = {
        "scan_id": "pentest-9",
        "scan_type": "penetration_test",
        "target_url": "https://wellreceived.example.com",
        "target_urls": ["https://setmore.example.com"],
        "instruction": "Use the approved audit accounts.",
        "callback_url": "https://app.example.com/callback",
        "upload_url": "https://s3.amazonaws.com/bucket/report",
    }
    return ScanRequest(**{**data, **overrides})


@pytest_asyncio.fixture
async def manager_with_blocked_scan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> AsyncGenerator[tuple[ScanManager, dict[str, Any]], None]:
    manager = ScanManager(RunStore(tmp_path / "runs"))
    captured: dict[str, Any] = {}
    release = asyncio.Event()

    async def fake_run_scan(
        run_name: str,
        targets: list[str],
        scan_mode: str,
        instruction: str,
        webhook_meta: Any = None,
    ) -> None:
        captured.update(
            run_name=run_name,
            targets=targets,
            scan_mode=scan_mode,
            instruction=instruction,
            webhook_meta=webhook_meta,
        )
        await release.wait()

    monkeypatch.setattr(manager, "_run_scan", fake_run_scan)

    try:
        yield manager, captured
    finally:
        release.set()
        for state in manager._scans.values():
            if not state.task.done():
                state.task.cancel()
            if state.heartbeat_task and not state.heartbeat_task.done():
                state.heartbeat_task.cancel()
        tasks = [state.task for state in manager._scans.values()]
        tasks.extend(
            state.heartbeat_task
            for state in manager._scans.values()
            if state.heartbeat_task is not None
        )
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_webhook_passes_all_targets_and_instructions(
    manager_with_blocked_scan: tuple[ScanManager, dict[str, Any]],
) -> None:
    manager, captured = manager_with_blocked_scan

    run_name = await manager.start_webhook_scan(_request())
    await asyncio.sleep(0)

    assert captured["run_name"] == run_name
    assert captured["targets"] == [
        "https://wellreceived.example.com/",
        "https://setmore.example.com/",
    ]
    assert captured["scan_mode"] == "deep"
    assert captured["instruction"] == "Use the approved audit accounts."


@pytest.mark.asyncio
async def test_duplicate_external_id_reuses_existing_run(
    manager_with_blocked_scan: tuple[ScanManager, dict[str, Any]],
) -> None:
    manager, _captured = manager_with_blocked_scan

    first_run = await manager.start_webhook_scan(_request())
    second_run = await manager.start_webhook_scan(_request())

    assert second_run == first_run
    assert list(manager._scans) == [first_run]


@pytest.mark.asyncio
async def test_status_accepts_external_and_returned_run_ids(
    manager_with_blocked_scan: tuple[ScanManager, dict[str, Any]],
) -> None:
    manager, _captured = manager_with_blocked_scan
    run_name = await manager.start_webhook_scan(_request())

    assert manager.get_webhook_scan_status("pentest-9")["status"] == "in_progress"
    assert manager.get_webhook_scan_status(run_name)["status"] == "in_progress"


@pytest.mark.asyncio
async def test_pre_event_failure_returns_real_error(
    manager_with_blocked_scan: tuple[ScanManager, dict[str, Any]],
) -> None:
    manager, _captured = manager_with_blocked_scan
    run_name = await manager.start_webhook_scan(_request())
    state = manager._scans[run_name]
    state.last_error = "charset-normalizer import failed"
    state.task.cancel()
    await asyncio.gather(state.task, return_exceptions=True)

    status = manager.get_webhook_scan_status(run_name)

    assert status == {
        "status": "failed",
        "progress": 0,
        "error_message": "charset-normalizer import failed",
    }
