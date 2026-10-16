"""Regression tests for Accountable webhook scan lifecycle behavior."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

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


@pytest_asyncio.fixture
async def running_scan_harness(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> AsyncGenerator[dict[str, Any], None]:
    """Exercise the real runner and watchdog without LLM, Docker, or HTTP calls."""
    manager = ScanManager(RunStore(tmp_path / "runs"))
    started = asyncio.Event()
    tick = asyncio.Event()
    release = asyncio.Event()
    tracer = MagicMock()
    tracer.scan_results = {
        "scan_completed": True,
        "executive_summary": "No vulnerabilities identified in the tested surface.",
        "methodology": "Reviewed response headers.",
        "technical_analysis": "Observed the configured security headers.",
        "recommendations": "Continue periodic assessments.",
    }
    callbacks = MagicMock()

    async def execute_scan(**_config: Any) -> dict[str, bool]:
        started.set()
        await release.wait()
        return {"success": True}

    async def heartbeat_sleep(_seconds: float) -> None:
        await tick.wait()
        tick.clear()

    execute = AsyncMock(side_effect=execute_scan)
    monkeypatch.setattr("strix.core.runner.run_strix_scan", execute)
    monkeypatch.setattr(
        "strix.accountable.report_state.AccountableReportState", lambda _name: tracer
    )
    monkeypatch.setattr("strix.accountable.runtime.register_railway_backend", lambda: None)

    async def worker_run(_worker, request):
        await manager._run_scan_in_process(
            request["run_name"], request["targets"], request["scan_mode"], request["instruction"]
        )
        return {"error": manager._scans[request["run_name"]].last_error}

    monkeypatch.setattr("strix.web.services.scan_worker.ScanWorker.run", worker_run)
    monkeypatch.setattr("strix.web.services.webhook.post_callback", callbacks)
    monkeypatch.setattr("strix.web.services.scan_manager.asyncio.sleep", heartbeat_sleep)
    monkeypatch.setattr(manager, "_send_completion_callback", AsyncMock())
    monkeypatch.delenv("SCAN_TIMEOUT_HOURS_PENTEST", raising=False)
    monkeypatch.delenv("SCAN_TIMEOUT_HOURS_VULN", raising=False)

    try:
        yield {
            "manager": manager,
            "execute": execute,
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
    ("configured", "expected"), [(None, None), ("", None), ("  ", None), ("6", 6.0)]
)
async def test_scan_budget_is_unlimited_unless_explicitly_configured(
    running_scan_harness: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    configured: str | None,
    expected: float | None,
) -> None:
    if configured is None:
        monkeypatch.delenv("STRIX_SCAN_BUDGET_USD", raising=False)
    else:
        monkeypatch.setenv("STRIX_SCAN_BUDGET_USD", configured)
    harness = running_scan_harness
    run_name = await harness["manager"].start_webhook_scan(_request())
    await asyncio.wait_for(harness["started"].wait(), timeout=5)
    assert harness["execute"].call_args.kwargs["max_budget_usd"] == expected
    harness["release"].set()
    await asyncio.wait_for(harness["manager"]._scans[run_name].task, timeout=5)


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
    assert (manager.run_store.runs_dir / run_name / "events.jsonl").exists()
    assert expected_error in (manager.run_store.runs_dir / run_name / "events.jsonl").read_text()
    harness["tracer"].save_run_data.assert_any_call(mark_complete=False)
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
    harness["tracer"].save_run_data.assert_any_call(mark_complete=False)


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
    harness["tracer"].save_run_data.assert_any_call(mark_complete=False)


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

    harness["tracer"].save_run_data.assert_any_call(mark_complete=True)
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


@pytest.mark.asyncio
@pytest.mark.parametrize("result", [{}, None, {"success": False, "error": "budget exhausted"}])
async def test_unfinished_agent_cannot_produce_successful_blank_report(
    running_scan_harness: dict[str, Any],
    result: Any,
) -> None:
    harness = running_scan_harness
    harness["execute"].side_effect = None
    harness["execute"].return_value = None if result is None or result == {} else result
    harness["tracer"].scan_results = None
    manager = harness["manager"]
    run_name = await manager.start_webhook_scan(_request(scan_type="vulnerability_scan"))
    await asyncio.wait_for(manager._scans[run_name].task, timeout=5)

    assert manager._scans[run_name].last_error
    assert harness["callbacks"].call_args.args[1]["status"] == "failed"
    harness["tracer"].save_run_data.assert_any_call(mark_complete=False)
    manager._send_completion_callback.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("final_fields", [None, {}, {"scan_completed": True}])
async def test_success_without_finish_scan_report_is_failure(
    running_scan_harness: dict[str, Any],
    final_fields: Any,
) -> None:
    harness = running_scan_harness
    harness["tracer"].scan_results = final_fields
    manager = harness["manager"]
    run_name = await manager.start_webhook_scan(_request(scan_type="vulnerability_scan"))
    await asyncio.wait_for(harness["started"].wait(), timeout=5)
    harness["release"].set()
    await asyncio.wait_for(manager._scans[run_name].task, timeout=5)

    assert "final report" in manager._scans[run_name].last_error
    assert harness["callbacks"].call_args.args[1]["status"] == "failed"
    manager._send_completion_callback.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("pdf", [None, b"", b"%PDF-test"])
@pytest.mark.parametrize("upload_result", [False, True])
async def test_completion_requires_nonempty_pdf_and_successful_upload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pdf: bytes | None,
    upload_result: bool,
) -> None:
    from strix.web.services.scan_manager import WebhookMeta

    manager = ScanManager(RunStore(tmp_path))
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    if pdf is not None:
        (run_dir / "vulnerability_scan_report.pdf").write_bytes(pdf)
    upload = MagicMock(return_value=upload_result)
    callback = MagicMock()
    monkeypatch.setattr("strix.web.services.webhook.upload_pdf", upload)
    monkeypatch.setattr("strix.web.services.webhook.post_callback", callback)
    meta = WebhookMeta(
        "external", "https://callback.example", "https://upload.example", "vulnerability_scan"
    )

    if pdf and upload_result:
        await manager._send_completion_callback("run", meta)
        assert callback.call_args.args[1]["status"] == "completed"
        assert callback.call_args.args[1]["pdf_uploaded"] is True
    else:
        with pytest.raises(RuntimeError, match="PDF report"):
            await manager._send_completion_callback("run", meta)
        callback.assert_not_called()
    assert upload.call_count == bool(pdf)


@pytest.mark.asyncio
async def test_report_delivery_failure_sends_failed_callback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manager = ScanManager(RunStore(tmp_path))
    worker = MagicMock(run=AsyncMock(return_value={"error": None}))
    monkeypatch.setattr("strix.web.services.scan_manager.ScanWorker", lambda: worker)
    callback = MagicMock()
    monkeypatch.setattr("strix.web.services.webhook.post_callback", callback)

    run_name = await manager.start_webhook_scan(_request(scan_type="vulnerability_scan"))
    await asyncio.wait_for(manager._scans[run_name].task, timeout=5)

    callback.assert_called_once()
    payload = callback.call_args.args[1]
    assert payload["status"] == "failed"
    assert payload["pdf_uploaded"] is False
    assert "report delivery failed" in payload["error_message"]
    status = manager.get_webhook_scan_status(run_name)
    assert status["status"] == "callback_failed"
    assert status["error_message"] == payload["error_message"]


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["upload", "callback"])
async def test_cancellation_during_delivery_preserves_one_terminal_status(  # noqa: PLR0915
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, phase: str
) -> None:
    import json
    import threading

    manager = ScanManager(RunStore(tmp_path))
    upload_started = threading.Event()
    upload_release = threading.Event()
    callback_started = threading.Event()
    callback_release = threading.Event()

    async def complete(request):
        run_dir = tmp_path / request["run_name"]
        run_dir.mkdir()
        (run_dir / "vulnerability_scan_report.pdf").write_bytes(b"%PDF-test")
        (run_dir / "events.jsonl").write_text(json.dumps({"event_type": "run.completed"}) + "\n")
        return {"error": None}

    def upload(*_args):
        upload_started.set()
        assert upload_release.wait(5)
        return True

    def callback(*_args):
        callback_started.set()
        assert callback_release.wait(5)

    worker = MagicMock(run=AsyncMock(side_effect=complete))
    callbacks = MagicMock(side_effect=callback)
    monkeypatch.setattr("strix.web.services.scan_manager.ScanWorker", lambda: worker)
    monkeypatch.setattr("strix.web.services.webhook.upload_pdf", upload)
    monkeypatch.setattr("strix.web.services.webhook.post_callback", callbacks)
    run_name = await manager.start_webhook_scan(_request(scan_type="vulnerability_scan"))
    state = manager._scans[run_name]
    stop_task = None
    try:
        assert await asyncio.to_thread(upload_started.wait, 5)
        if phase == "callback":
            upload_release.set()
            assert await asyncio.to_thread(callback_started.wait, 5)
            # Once the final POST starts, stopping cannot retract its outcome.
            assert await manager.stop_scan(run_name) is False
        else:
            stop_task = asyncio.create_task(manager.stop_scan(run_name))
            assert await asyncio.to_thread(callback_started.wait, 5)

        # Repeated cancellation must not abandon or duplicate the terminal POST.
        state.task.cancel()
        await asyncio.sleep(0)
        state.task.cancel()
        await asyncio.sleep(0)
        assert not state.task.done()
        callback_release.set()
        if stop_task:
            assert await asyncio.wait_for(stop_task, 5)
        await asyncio.wait_for(state.task, 5)

        callbacks.assert_called_once()
        expected = "failed" if phase == "upload" else "completed"
        assert callbacks.call_args.args[1]["status"] == expected
        assert manager.get_webhook_scan_status(run_name)["status"] == expected
        assert manager.run_store.get_run(run_name).summary.status == (
            "error" if phase == "upload" else "completed"
        )
        events = [
            json.loads(line)
            for line in (tmp_path / run_name / "events.jsonl").read_text().splitlines()
        ]
        assert sum(event["event_type"] == "run.error" for event in events) == (phase == "upload")
    finally:
        upload_release.set()
        callback_release.set()
        await asyncio.gather(
            state.task, *([stop_task] if stop_task else []), return_exceptions=True
        )


async def test_legacy_app_preset_reaches_worker_and_retry_is_idempotent(manager_with_blocked_scan):
    from strix.web.models.api_v1 import InstructionPresetRequest

    manager, captured = manager_with_blocked_scan
    req = _request(
        target_url="https://app.example.com/?evaluation=nonce", target_urls=[], instruction=""
    )
    manager.instruction_presets.register(
        InstructionPresetRequest(
            target_url=req.target_url,
            callback_origin="https://app.example.com",
            instruction="Authenticate using the private authorized account.",
        )
    )
    name = await manager.start_webhook_scan(req)
    await asyncio.sleep(0)
    assert "Authenticate using the private authorized account" in captured["instruction"]
    assert await manager.start_webhook_scan(req) == name
    assert manager.instruction_presets.consume(req) == ""


@pytest.mark.parametrize(
    "target",
    [
        "https://app.example.com/?evaluation=private-marker&next=/employee/dashboard",
        "https://app.example.com/login#private-fragment",
        "https://user:password@app.example.com:8443/a%2Fb",
        "https://[::1]/?key=value",
    ],
)
async def test_webhook_identifier_is_url_safe_and_status_route_is_reachable(
    manager_with_blocked_scan, target
):
    import re

    from fastapi.testclient import TestClient

    from strix.web.app import create_app

    manager, _captured = manager_with_blocked_scan
    name = await manager.start_webhook_scan(_request(target_url=target, target_urls=[]))
    assert re.fullmatch(r"[a-z0-9_-]+", name)
    assert not any(secret in name for secret in ["private-marker", "private-fragment", "password"])
    app = create_app(manager.run_store.runs_dir)
    app.state.scan_manager = manager
    app.dependency_overrides.clear()
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("API_KEY", "fixture-key")
        response = TestClient(app).get(
            f"/api/v1/scans/{name}/status", headers={"Authorization": "Bearer fixture-key"}
        )
    assert response.status_code == 200
    assert response.json()["status"] == "in_progress"
