"""Prepare and verify standalone scan tools before spending any LLM tokens."""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import os
import shutil
import socket
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

import requests


if TYPE_CHECKING:
    from collections.abc import AsyncIterator


REQUIRED_MODULES = ("libtmux", "IPython", "gql", "openhands_aci", "pyte", "playwright.async_api")
REQUIRED_BINARIES = ("tmux", "bash", "caido-cli")


def check_dependencies() -> None:
    problems = []
    for module in REQUIRED_MODULES:
        try:
            importlib.import_module(module)
        except ImportError as exc:
            problems.append(f"{module}: {exc}")
    problems.extend(
        f"missing executable: {name}" for name in REQUIRED_BINARIES if not shutil.which(name)
    )
    if problems:
        raise RuntimeError("Scan runtime is not ready: " + "; ".join(problems))


def _graphql(port: int, query: str, token: str | None = None) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    # Management requests stay local and must not inherit an outbound proxy.
    with requests.Session() as session:
        session.trust_env = False
        response = session.post(
            f"http://127.0.0.1:{port}/graphql",
            json={"query": query},
            headers=headers,
            timeout=2,
        )
        response.raise_for_status()
        result = response.json()
    if result.get("errors") or not result.get("data"):
        raise RuntimeError("Scan proxy initialization failed")
    return result["data"]


async def _start_proxy(data_dir: Path) -> asyncio.subprocess.Process:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    process = await asyncio.create_subprocess_exec(
        "caido-cli",
        "--listen",
        f"127.0.0.1:{port}",
        "--data-path",
        str(data_dir),
        "--allow-guests",
        "--no-open",
        "--no-logging",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        token = None
        for _attempt in range(60):
            if process.returncode is not None:
                raise RuntimeError(f"Scan proxy exited during startup ({process.returncode})")  # noqa: TRY301
            try:
                result = await asyncio.to_thread(
                    _graphql,
                    port,
                    "mutation { loginAsGuest { token { accessToken } } }",
                )
                token = result["loginAsGuest"]["token"]["accessToken"]
                if token:
                    break
            except (requests.RequestException, RuntimeError, KeyError, TypeError):
                pass
            await asyncio.sleep(0.5)
        if not token:
            raise RuntimeError("Scan proxy did not become ready")  # noqa: TRY301
        created = await asyncio.to_thread(
            _graphql,
            port,
            'mutation { createProject(input: {name: "scan", temporary: true}) { project { id } } }',
            token,
        )
        project_id = created["createProject"]["project"]["id"]
        selected = await asyncio.to_thread(
            _graphql,
            port,
            f'mutation {{ selectProject(id: "{project_id}") '
            "{ currentProject { project { id } } } }",
            token,
        )
        if selected["selectProject"]["currentProject"]["project"]["id"] != project_id:
            raise RuntimeError("Scan proxy could not select its isolated project")  # noqa: TRY301
        os.environ["STRIX_CAIDO_PORT"] = str(port)
        os.environ["CAIDO_API_TOKEN"] = token
    except BaseException:
        await _stop_process(process)
        raise
    return process


async def _stop_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            await process.wait()


async def _check_browser() -> None:
    from playwright.async_api import async_playwright

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        try:
            page = await browser.new_page()
            await page.goto("about:blank", timeout=10_000)
            await page.evaluate("1 + 1")
        finally:
            await browser.close()


def _check_terminal(workspace: Path) -> None:
    from strix.tools.terminal.terminal_session import TerminalSession

    terminal = TerminalSession("readiness", work_dir=str(workspace))
    try:
        result = terminal.execute("printf strix-ready", timeout=5)
        if result.get("exit_code") != 0 or "strix-ready" not in result.get("content", ""):
            raise RuntimeError("Scan terminal failed its readiness check")
    finally:
        terminal.close()


def _check_python() -> None:
    from strix.tools.python.python_instance import PythonInstance

    session = PythonInstance("readiness")
    try:
        result = session.execute_code("print(1 + 1)", timeout=5)
        if result.get("stderr") or result.get("stdout", "").strip() != "2":
            raise RuntimeError("Scan Python tool failed its readiness check")
    finally:
        session.close()


async def _check_proxy_request() -> None:
    async def respond(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nstrix-ready"
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    from strix.tools.proxy.proxy_manager import ProxyManager

    server = await asyncio.start_server(respond, "127.0.0.1", 0)
    async with server:
        port = server.sockets[0].getsockname()[1]
        result = await asyncio.to_thread(
            ProxyManager().send_simple_request,
            "GET",
            f"http://127.0.0.1:{port}/",
            timeout=5,
        )
        if result.get("status_code") != 200 or result.get("body") != "strix-ready":
            raise RuntimeError("Scan proxy failed its HTTP readiness check")


@asynccontextmanager
async def scan_runtime(workspace: Path) -> AsyncIterator[None]:
    check_dependencies()
    workspace.mkdir(parents=True, exist_ok=True)
    os.environ["STRIX_WORKSPACE"] = str(workspace)
    # Short socket paths work on both Linux and macOS. Each worker gets its own
    # tmux server and Caido database, including across sequential scans.
    with tempfile.TemporaryDirectory(prefix="strix-", dir="/tmp") as temp:
        temp_dir = Path(os.environ.get("STRIX_RUNTIME_DIR", temp))
        tmux_socket = str(temp_dir / "tmux.sock")
        os.environ["STRIX_TMUX_SOCKET"] = tmux_socket
        proxy = None
        try:
            await asyncio.to_thread(_check_terminal, workspace)
            await asyncio.wait_for(_check_browser(), timeout=30)
            proxy = await _start_proxy(temp_dir / "proxy")
            await asyncio.to_thread(_check_python)
            await _check_proxy_request()
            yield
        finally:
            if proxy:
                await _stop_process(proxy)
            tmux = await asyncio.create_subprocess_exec(
                "tmux",
                "-S",
                tmux_socket,
                "kill-server",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await tmux.wait()


async def _smoke_test() -> None:
    with tempfile.TemporaryDirectory(prefix="strix-smoke-") as workspace:
        async with scan_runtime(Path(workspace)):
            pass


if __name__ == "__main__":
    asyncio.run(_smoke_test())
