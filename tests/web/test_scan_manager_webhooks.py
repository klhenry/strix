"""Regression tests for Accountable webhook scan lifecycle behavior."""

from __future__ import annotations

import asyncio
import importlib
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from strix.web.models.api_v1 import ScanRequest
from strix.web.services.run_store import RunStore
from strix.web.services.scan_manager import ScanManager


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


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


@pytest_asyncio.fixture
async def running_scan_harness(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> AsyncGenerator[dict[str, Any], None]:
    """Exercise the real runner and watchdog without LLM, Docker, or HTTP calls."""
    manager = ScanManager(RunStore(tmp_path / "runs"))
    monkeypatch.setattr(manager, "_run_scan", manager._run_scan_in_process)
    started = asyncio.Event()
    tick = asyncio.Event()
    release = asyncio.Event()
    tracer = MagicMock()
    callbacks = MagicMock()

    async def execute_scan(_config: Any) -> dict[str, bool]:
        started.set()
        await release.wait()
        return {"success": True}

    async def heartbeat_sleep(_seconds: float) -> None:
        await tick.wait()
        tick.clear()

    # Prevent local credentials/configuration and runtime cleanup from being used.
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(
        importlib.import_module("strix.agents.StrixAgent"),
        "StrixAgent",
        MagicMock(
            return_value=MagicMock(execute_scan=AsyncMock(side_effect=execute_scan)),
        ),
    )
    monkeypatch.setattr("strix.llm.config.LLMConfig", MagicMock())
    monkeypatch.setattr("strix.telemetry.tracer.Tracer", MagicMock(return_value=tracer))
    monkeypatch.setattr("strix.telemetry.tracer.set_global_tracer", MagicMock())
    monkeypatch.setattr(
        "strix.tools.registry.get_tool_names",
        lambda: [
            "create_vulnerability_report",
            "finish_scan",
        ],
    )
    monkeypatch.setattr("strix.runtime.cleanup_runtime", MagicMock())
    monkeypatch.setattr("subprocess.run", MagicMock(return_value=MagicMock(stdout="")))
    monkeypatch.setattr("strix.web.services.webhook.post_callback", callbacks)
    monkeypatch.setattr("strix.web.services.scan_manager.asyncio.sleep", heartbeat_sleep)
    monkeypatch.setattr(manager, "_send_completion_callback", AsyncMock())
    monkeypatch.delenv("SCAN_TIMEOUT_HOURS_PENTEST", raising=False)
    monkeypatch.delenv("SCAN_TIMEOUT_HOURS_VULN", raising=False)

    try:
        yield {
            "manager": manager,
            "started": started,
            "tick": tick,
            "release": release,
            "tracer": tracer,
            "callbacks": callbacks,
        }
    finally:
        for state in manager._scans.values():
            await manager.stop_scan(state.run_name)
        await asyncio.gather(
            *(
                state.heartbeat_task
                for state in manager._scans.values()
                if state.heartbeat_task is not None
            ),
            return_exceptions=True,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scan_type", "override", "hours"),
    [
        ("penetration_test", None, 6),
        ("vulnerability_scan", None, 3),
        ("penetration_test", "0.5", 0.5),
    ],
)
async def test_watchdog_reports_one_precise_timeout_and_preserves_partial_run(
    running_scan_harness: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    scan_type: str,
    override: str | None,
    hours: float,
) -> None:
    harness = running_scan_harness
    manager = harness["manager"]
    if override:
        monkeypatch.setenv("SCAN_TIMEOUT_HOURS_PENTEST", override)
    run_name = await manager.start_webhook_scan(_request(scan_type=scan_type))
    await asyncio.wait_for(harness["started"].wait(), timeout=5)
    state = manager._scans[run_name]
    state.start_time -= timedelta(hours=hours, seconds=1)
    harness["tick"].set()
    await asyncio.wait_for(state.task, timeout=5)

    expected_error = f"Scan timed out after {hours:g} hours"
    harness["callbacks"].assert_called_once()
    assert harness["callbacks"].call_args.args[1]["error_message"] == expected_error
    assert harness["callbacks"].call_args.args[1]["status"] == "failed"
    assert manager.get_webhook_scan_status(run_name)["error_message"] == expected_error
    harness["tracer"]._emit_event.assert_called_once_with(
        "run.error",
        payload={"error": expected_error},
        status="error",
        source="strix.web",
    )
    harness["tracer"].save_run_data.assert_called_once_with(mark_complete=False, generate_reports=True)
    manager._send_completion_callback.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("manual", [True, False])
async def test_non_watchdog_cancellation_has_no_timeout_claim(
    running_scan_harness: dict[str, Any],
    manual: bool,
) -> None:
    harness = running_scan_harness
    manager = harness["manager"]
    run_name = await manager.start_webhook_scan(_request())
    await asyncio.wait_for(harness["started"].wait(), timeout=5)
    state = manager._scans[run_name]

    if manual:
        assert await manager.stop_scan(run_name)
    else:
        state.task.cancel()
        await asyncio.wait_for(state.task, timeout=5)

    expected_error = "Scan was cancelled by user" if manual else "Scan was cancelled"
    harness["callbacks"].assert_called_once()
    assert harness["callbacks"].call_args.args[1]["error_message"] == expected_error
    assert manager.get_webhook_scan_status(run_name)["error_message"] == expected_error
    harness["tracer"].save_run_data.assert_called_once_with(mark_complete=False, generate_reports=True)


@pytest.mark.asyncio
async def test_unreachable_heartbeat_records_callback_failure(
    running_scan_harness: dict[str, Any],
) -> None:
    from strix.web.services.webhook import CallbackDeliveryError

    harness = running_scan_harness
    manager = harness["manager"]
    harness["callbacks"].side_effect = CallbackDeliveryError("Connection refused")
    run_name = await manager.start_webhook_scan(_request())
    await asyncio.wait_for(harness["started"].wait(), timeout=5)
    state = manager._scans[run_name]
    harness["tick"].set()
    await asyncio.wait_for(state.task, timeout=5)

    assert manager.get_webhook_scan_status(run_name)["status"] == "callback_failed"
    assert state.last_error == "Scan was cancelled because the callback URL is unreachable"
    assert harness["callbacks"].call_args.args[1]["error_message"] == state.last_error
    harness["tracer"].save_run_data.assert_called_once_with(mark_complete=False, generate_reports=True)


@pytest.mark.asyncio
async def test_success_still_marks_run_complete(
    running_scan_harness: dict[str, Any],
) -> None:
    harness = running_scan_harness
    manager = harness["manager"]
    run_name = await manager.start_webhook_scan(_request())
    await asyncio.wait_for(harness["started"].wait(), timeout=5)
    harness["release"].set()
    await asyncio.wait_for(manager._scans[run_name].task, timeout=5)

    harness["tracer"].save_run_data.assert_called_once_with(mark_complete=True, generate_reports=True)
    manager._send_completion_callback.assert_awaited_once()
    harness["callbacks"].assert_not_called()


@pytest.mark.asyncio
async def test_watchdog_keeps_scan_running_before_deadline(
    running_scan_harness: dict[str, Any],
) -> None:
    harness = running_scan_harness
    manager = harness["manager"]
    heartbeat_sent = asyncio.Event()
    harness["callbacks"].side_effect = lambda *_args: heartbeat_sent.set()
    run_name = await manager.start_webhook_scan(_request())
    await asyncio.wait_for(harness["started"].wait(), timeout=5)
    state = manager._scans[run_name]
    state.start_time -= timedelta(hours=5)
    harness["tick"].set()
    await asyncio.wait_for(heartbeat_sent.wait(), timeout=5)

    assert not state.task.done()
    assert state.last_error is None
    harness["callbacks"].assert_called_once()
    assert harness["callbacks"].call_args.args[1]["status"] == "in_progress"
    harness["release"].set()
    await asyncio.wait_for(state.task, timeout=5)
