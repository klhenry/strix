"""Process isolation and parent lifecycle regressions (no LLM or target requests)."""

from __future__ import annotations

import asyncio
import json
import os
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from strix.web.services import scan_worker
from strix.web.services.run_store import RunStore
from strix.web.services.scan_manager import ScanManager
from strix.web.services.scan_worker import ScanWorker


if TYPE_CHECKING:
    from multiprocessing.connection import Connection


def _probe_worker(connection: Connection, request: dict[str, Any]) -> None:
    """Use the actual mutable agent registry inside a spawned interpreter."""
    from strix.tools.agents_graph import agents_graph_actions as graph

    os.setsid()
    connection.send({"type": "started"})
    before = list(graph._agent_graph["nodes"])
    root = request["run_name"]
    graph._agent_graph["nodes"][root] = {"parent_id": None, "status": "running"}
    connection.send({"type": "progress", "progress": 12})
    message = connection.recv()
    if message["command"] == "crash":
        os._exit(7)
    connection.send(
        {
            "type": "result",
            "error": None,
            "before": before,
            "nodes": list(graph._agent_graph["nodes"]),
            "pid": os.getpid(),
        }
    )
    connection.close()


async def _wait_ready(worker: ScanWorker) -> None:
    async with asyncio.timeout(15):
        while worker.progress != 12:
            await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_concurrent_and_sequential_workers_do_not_share_agent_state(monkeypatch) -> None:
    monkeypatch.setattr(scan_worker, "_worker_entry", _probe_worker)
    first, second = ScanWorker(), ScanWorker()
    tasks = [
        asyncio.create_task(first.run({"run_name": "first"})),
        asyncio.create_task(second.run({"run_name": "second"})),
    ]
    try:
        await asyncio.gather(_wait_ready(first), _wait_ready(second))
        assert first.pause()
        assert second.send("finish")
        result_b = await asyncio.wait_for(tasks[1], timeout=10)
        assert not tasks[0].done()
        assert first.resume()
        assert first.send("finish")
        result_a = await asyncio.wait_for(tasks[0], timeout=10)
        assert result_a["before"] == result_b["before"] == []
        assert result_a["nodes"] == ["first"]
        assert result_b["nodes"] == ["second"]
        assert result_a["pid"] != result_b["pid"]

        third = ScanWorker()
        task = asyncio.create_task(third.run({"run_name": "third"}))
        tasks.append(task)
        await _wait_ready(third)
        third.send("finish")
        result_c = await asyncio.wait_for(task, timeout=10)
        assert result_c["before"] == []
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_canceling_paused_worker_does_not_cancel_another_worker(monkeypatch) -> None:
    monkeypatch.setattr(scan_worker, "_worker_entry", _probe_worker)
    first, second = ScanWorker(), ScanWorker()
    tasks = [
        asyncio.create_task(first.run({"run_name": "first"})),
        asyncio.create_task(second.run({"run_name": "second"})),
    ]
    try:
        await asyncio.gather(_wait_ready(first), _wait_ready(second))
        assert first.pause()
        tasks[0].cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(tasks[0], timeout=10)
        assert not tasks[1].done()
        assert second.send("finish")
        assert (await asyncio.wait_for(tasks[1], timeout=10))["nodes"] == ["second"]
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_worker_crash_is_not_success(monkeypatch) -> None:
    monkeypatch.setattr(scan_worker, "_worker_entry", _probe_worker)
    worker = ScanWorker()
    task = asyncio.create_task(worker.run({"run_name": "crash"}))
    try:
        await _wait_ready(worker)
        worker.send("crash")
        with pytest.raises(RuntimeError, match="exited unexpectedly \\(7\\)"):
            await asyncio.wait_for(task, timeout=10)
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_supervisor_persists_startup_failure_and_sends_one_callback(
    monkeypatch, tmp_path
) -> None:
    from tests.web.test_scan_manager_webhooks import _request

    manager = ScanManager(RunStore(tmp_path))
    monkeypatch.setattr(
        ScanWorker, "run", AsyncMock(return_value={"error": "missing executable: tmux"})
    )
    callback = MagicMock()
    monkeypatch.setattr("strix.web.services.webhook.post_callback", callback)
    completion = AsyncMock()
    monkeypatch.setattr(manager, "_send_completion_callback", completion)
    name = await manager.start_webhook_scan(_request())
    await manager._scans[name].task

    callback.assert_called_once()
    assert callback.call_args.args[1]["status"] == "failed"
    assert callback.call_args.args[1]["error_message"] == "missing executable: tmux"
    completion.assert_not_called()
    events = [
        json.loads(line) for line in (tmp_path / name / "events.jsonl").read_text().splitlines()
    ]
    assert [e["event_type"] for e in events] == ["run.error"]
    assert manager.run_store.get_run(name).summary.status == "error"
    assert manager.get_webhook_scan_status(name)["status"] == "failed"


@pytest.mark.asyncio
async def test_supervisor_stop_preserves_reason(monkeypatch, tmp_path) -> None:
    from tests.web.test_scan_manager_webhooks import _request

    started = asyncio.Event()

    async def block(_request: Any) -> None:
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(ScanWorker, "run", AsyncMock(side_effect=block))
    callback = MagicMock()
    monkeypatch.setattr("strix.web.services.webhook.post_callback", callback)
    manager = ScanManager(RunStore(tmp_path))
    name = await manager.start_webhook_scan(_request())
    await started.wait()
    assert await manager.stop_scan(name)
    callback.assert_called_once()
    assert callback.call_args.args[1]["error_message"] == "Scan was cancelled by user"
    assert manager.get_webhook_scan_status(name)["status"] == "failed"


def _unresponsive_worker(connection: Connection, _request: dict[str, Any]) -> None:
    os.setsid()
    connection.send({"type": "started"})
    connection.send({"type": "progress", "progress": 12})
    # Receive control commands but deliberately never exit or send a result.
    while True:
        connection.recv()


@pytest.mark.asyncio
async def test_unresponsive_worker_is_reaped_after_grace_period(monkeypatch) -> None:
    monkeypatch.setattr(scan_worker, "_worker_entry", _unresponsive_worker)
    monkeypatch.setattr(scan_worker, "STOP_GRACE_SECONDS", 0.1)
    worker = ScanWorker()
    task = asyncio.create_task(worker.run({"run_name": "hung"}))
    try:
        await _wait_ready(worker)
        pid = worker.process.pid
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5)
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
        assert not worker.ready
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_failure_event_stream_ends_without_waiting_forever(tmp_path) -> None:
    from strix.web.routes.events import stream_events

    run_dir = tmp_path / "failed"
    run_dir.mkdir()
    (run_dir / "events.jsonl").write_text(json.dumps({"event_type": "run.error"}) + "\n")
    request = MagicMock()
    request.app.state.run_store = RunStore(tmp_path)
    request.is_disconnected = AsyncMock(return_value=False)
    response = await stream_events(request, "failed")
    async with asyncio.timeout(2):
        messages = [message async for message in response.body_iterator]
    assert len(messages) == 2
    assert "event: run.error" in messages[0]
    assert "event: done" in messages[1]


def test_report_directory_is_stable_after_python_tool_changes_cwd(monkeypatch, tmp_path) -> None:
    from strix.telemetry.tracer import Tracer

    output = tmp_path / "runs"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("STRIX_RUNS_DIR", str(output))
    monkeypatch.chdir(workspace)
    tracer = Tracer.__new__(Tracer)
    tracer._run_dir = None
    tracer.run_name = "stable"
    tracer.run_id = "stable"
    assert tracer.get_run_dir() == output / "stable"


@pytest.mark.asyncio
async def test_real_spawned_worker_reports_readiness_failure_before_testing(monkeypatch, tmp_path):
    # The Python executable is absolute, so spawning still works, but readiness
    # must reject the missing tools even on machines with all Python extras.
    monkeypatch.setenv("PATH", "")
    worker = ScanWorker()
    result = await asyncio.wait_for(
        worker.run(
            {
                "run_name": "preflight",
                "runs_dir": str(tmp_path / "runs"),
                "workspace": str(tmp_path / "work"),
                "targets": ["https://example.invalid"],
                "scan_mode": "deep",
                "instruction": "",
            }
        ),
        timeout=15,
    )
    assert "missing executable: tmux" in result["error"]
    assert "missing executable: caido-cli" in result["error"]
    assert not (tmp_path / "runs" / "preflight" / "events.jsonl").exists()
    assert not worker.ready


@pytest.mark.asyncio
async def test_paused_worker_comments_are_bounded_and_do_not_block_loop(monkeypatch) -> None:
    monkeypatch.setattr(scan_worker, "_worker_entry", _unresponsive_worker)
    monkeypatch.setattr(scan_worker, "STOP_GRACE_SECONDS", 0.2)
    worker = ScanWorker()
    task = asyncio.create_task(worker.run({"run_name": "queued"}))
    try:
        await _wait_ready(worker)
        assert worker.pause()
        # This exceeds the OS pipe buffer. Delivery must yield to the event loop
        # so resume/stop remain usable even while the writer is blocked.
        assert worker.send("comment", message="x" * (256 * 1024))
        await asyncio.sleep(0.1)
        assert worker.send("comment", message="x" * scan_worker.MAX_COMMAND_BYTES) is False
        accepted = [worker.send("comment", message="queued") for _ in range(100)]
        assert sum(accepted) <= scan_worker.MAX_PENDING_COMMANDS
        assert not all(accepted)
        assert worker.resume()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5)
        assert worker._sender.done()
        assert worker.connection.closed
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_repeated_cancel_waits_for_worker_and_tool_cleanup(monkeypatch) -> None:
    from pathlib import Path

    monkeypatch.setattr(scan_worker, "_worker_entry", _unresponsive_worker)
    monkeypatch.setattr(scan_worker, "STOP_GRACE_SECONDS", 0.5)
    worker = ScanWorker()
    task = asyncio.create_task(worker.run({"run_name": "repeated-cancel"}))
    try:
        await _wait_ready(worker)
        pid = worker.process.pid
        runtime_dir = Path(worker.runtime_dir.name)
        assert worker.pause()
        task.cancel()
        async with asyncio.timeout(5):
            while not worker._closing:
                await asyncio.sleep(0.01)
            for _ in range(3):
                task.cancel()
                await asyncio.sleep(0.05)
                assert not task.done()
            with pytest.raises(asyncio.CancelledError):
                await task
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
        assert not runtime_dir.exists()
        assert worker.connection.closed
        assert worker._sender.done()
        assert not worker.ready
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


def _nonreading_worker(connection: Connection, _request: dict[str, Any]) -> None:
    import time

    os.setsid()
    connection.send({"type": "started"})
    connection.send({"type": "progress", "progress": 12})
    while True:
        time.sleep(1)


@pytest.mark.asyncio
async def test_hard_kill_releases_blocked_control_writer(monkeypatch) -> None:
    monkeypatch.setattr(scan_worker, "_worker_entry", _nonreading_worker)
    monkeypatch.setattr(scan_worker, "STOP_GRACE_SECONDS", 0.1)
    worker = ScanWorker()
    task = asyncio.create_task(worker.run({"run_name": "blocked-writer"}))
    try:
        await _wait_ready(worker)
        assert worker.send("comment", message="x" * (256 * 1024))
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5)
        assert worker._sender.done()
        assert worker.connection.closed
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
