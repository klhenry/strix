"""One fresh interpreter per scan; no agent, browser, or tracer state is shared."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import multiprocessing
import os
import shutil
import signal
import tempfile
from multiprocessing.reduction import ForkingPickler
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from multiprocessing.connection import Connection


logger = logging.getLogger(__name__)
POLL_SECONDS = 0.1
STOP_GRACE_SECONDS = 30
MAX_PENDING_COMMANDS = 16
MAX_COMMAND_BYTES = 1024 * 1024


class ScanWorker:
    def __init__(self) -> None:
        self.process: Any = None
        self.connection: Connection | None = None
        self.ready = False
        self.progress = 0
        self.agent_ready = False
        self.paused = False
        self.stop_reason = "Scan worker stopped"
        self.runtime_dir: tempfile.TemporaryDirectory[str] | None = None
        self._commands: asyncio.Queue[bytes | None] = asyncio.Queue(MAX_PENDING_COMMANDS)
        self._sender: asyncio.Task[None] | None = None
        self._closing = False

    def send(self, command: str, **payload: Any) -> bool:
        if (
            self.connection is None or not self.ready or self._closing
            or self._sender is None or self._sender.done()
        ):
            return False
        data = bytes(ForkingPickler.dumps({"command": command, **payload}))
        if len(data) > MAX_COMMAND_BYTES:
            return False
        try:
            self._commands.put_nowait(data)
        except asyncio.QueueFull:
            return False
        return True

    async def _send_commands(self) -> None:
        assert self.connection is not None
        while (data := await self._commands.get()) is not None:
            try:
                # A paused worker cannot drain its pipe. Only this writer may
                # touch the send side, keeping both ordering and the loop safe.
                await asyncio.to_thread(self.connection.send_bytes, data)
            except (BrokenPipeError, EOFError, OSError):
                return

    def _discard_commands(self) -> None:
        while not self._commands.empty():
            self._commands.get_nowait()

    def pause(self) -> bool:
        if self._closing or not self.ready or self.process is None or not self.process.is_alive():
            return False
        try:
            os.killpg(self.process.pid, signal.SIGSTOP)
        except ProcessLookupError:
            return False
        self.paused = True
        return True

    def resume(self) -> bool:
        if not self.paused or self.process is None:
            return False
        try:
            os.killpg(self.process.pid, signal.SIGCONT)
        except ProcessLookupError:
            return False
        self.paused = False
        return True

    async def run(self, request: dict[str, Any]) -> dict[str, Any]:
        self.runtime_dir = tempfile.TemporaryDirectory(prefix="strix-", dir="/tmp")
        request = {**request, "runtime_dir": self.runtime_dir.name}
        ctx = multiprocessing.get_context("spawn")
        self.connection, child = ctx.Pipe()
        self.process = ctx.Process(target=_worker_entry, args=(child, request))
        try:
            self.process.start()
            child.close()
            self._sender = asyncio.create_task(self._send_commands())
            while True:
                result = self._receive()
                if result is not None:
                    return result
                if not self.process.is_alive():
                    # Drain the terminal message sent immediately before exit.
                    result = self._receive()
                    if result is not None:
                        return result
                    raise RuntimeError(f"Scan worker exited unexpectedly ({self.process.exitcode})")
                await asyncio.sleep(POLL_SECONDS)
        finally:
            # Stop/shutdown can cancel this supervisor more than once. Keep a
            # strong reference and wait for cleanup even across those cancels.
            cleanup = asyncio.create_task(self._close())
            cancelled = False
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    cancelled = True
            cleanup.result()
            child.close()
            if cancelled:
                raise asyncio.CancelledError

    def _receive(self) -> dict[str, Any] | None:
        assert self.connection is not None
        try:
            while self.connection.poll():
                message = self.connection.recv()
                if message["type"] == "started":
                    self.ready = True
                elif message["type"] == "progress":
                    self.progress = message["progress"]
                    self.agent_ready = message.get("agent_ready", False)
                elif message["type"] == "result":
                    return message
        except (EOFError, OSError):
            pass
        return None

    async def _close(self) -> None:
        self._closing = True
        self._discard_commands()
        if self.process is not None and self.process.pid is not None:
            if self.paused:
                self.resume()
            # Normal completion has already saved reports. Cancellation gets a
            # bounded grace period to save partial reports before hard cleanup.
            deadline = asyncio.get_running_loop().time() + STOP_GRACE_SECONDS
            sent_cancel = False
            while self.process.is_alive() and asyncio.get_running_loop().time() < deadline:
                self._receive()
                if not sent_cancel and self.ready:
                    self._commands.put_nowait(bytes(ForkingPickler.dumps(
                        {"command": "cancel", "reason": self.stop_reason}
                    )))
                    sent_cancel = True
                await asyncio.sleep(POLL_SECONDS)
            if self.process.is_alive():
                self.process.kill()
            await asyncio.to_thread(self.process.join)
            # Also reap subprocesses left by browser/proxy/tool execution.
            if self.ready:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(self.process.pid, signal.SIGKILL)
            self.process.close()
        # Killing/joining the reader releases any blocked write before we close
        # its connection. Never leave a thread using a closed/reused descriptor.
        self._discard_commands()
        self._commands.put_nowait(None)
        if self._sender is not None:
            await self._sender
        if self.connection is not None:
            self.connection.close()
        if self.runtime_dir is not None:
            tmux_socket = Path(self.runtime_dir.name) / "tmux.sock"
            if tmux_socket.exists() and shutil.which("tmux"):
                tmux = await asyncio.create_subprocess_exec(
                    "tmux",
                    "-S",
                    str(tmux_socket),
                    "kill-server",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await tmux.wait()
            self.runtime_dir.cleanup()
        self.ready = False


async def _run_worker(connection: Connection, request: dict[str, Any]) -> None:
    from strix.web.services.run_store import RunStore
    from strix.web.services.runtime_check import scan_runtime
    from strix.web.services.scan_manager import ScanManager, ScanState

    manager = ScanManager(RunStore(Path(request["runs_dir"])))
    run_name = request["run_name"]

    async def execute() -> None:
        async with scan_runtime(Path(request["workspace"])):
            await manager._run_scan_in_process(
                run_name,
                request["targets"],
                request["scan_mode"],
                request["instruction"],
            )

    task = asyncio.create_task(execute())
    state = ScanState(task=task, run_name=run_name, scan_mode=request["scan_mode"])
    manager._scans[run_name] = state
    last_progress = None
    try:
        while not task.done():
            while connection.poll():
                message = connection.recv()
                command = message["command"]
                if command == "cancel" and not task.cancelling():
                    state.last_error = message["reason"]
                    task.cancel()
                elif command == "comment" and state.agent is not None:
                    manager.send_comment(message["message"], run_name)
                elif command == "event" and state.tracer is not None:
                    state.tracer._emit_event(
                        message["event"],
                        payload={},
                        status=message["status"],
                        source="strix.web",
                    )
            progress = (manager._estimate_progress(state), state.agent is not None)
            if progress != last_progress:
                connection.send(
                    {
                        "type": "progress",
                        "progress": progress[0],
                        "agent_ready": progress[1],
                    }
                )
                last_progress = progress
            await asyncio.sleep(POLL_SECONDS)
        await task
    except asyncio.CancelledError:
        state.last_error = state.last_error or "Scan was cancelled"
    except Exception as exc:
        logger.exception("Scan worker failed for %s", run_name)
        state.last_error = str(exc)
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    connection.send({"type": "result", "error": state.last_error})


def _worker_entry(connection: Connection, request: dict[str, Any]) -> None:
    # A separate process group lets pause/stop include this worker's tools only.
    os.setsid()
    logging.basicConfig(level=logging.INFO)
    os.environ["STRIX_SANDBOX_MODE"] = "true"
    os.environ["STRIX_STANDALONE"] = "true"
    os.environ["STRIX_RUNS_DIR"] = request["runs_dir"]
    os.environ["STRIX_WORKSPACE"] = request["workspace"]
    os.environ["STRIX_RUNTIME_DIR"] = request["runtime_dir"]
    connection.send({"type": "started"})
    try:
        asyncio.run(_run_worker(connection, request))
    except Exception as exc:
        logger.exception("Worker initialization failed")
        with contextlib.suppress(BrokenPipeError, OSError):
            connection.send({"type": "result", "error": str(exc)})
    finally:
        connection.close()
