"""Railway runtime using the SDK's Unix local session inside the service container.

Each scan has a private workspace, proxy, browser daemon and process group.
The Railway container is the outer execution boundary, matching the existing
standalone deployment. The upstream Docker backend remains the CLI default.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents.sandbox.sandboxes.unix_local import (
    UnixLocalSandboxClient,
    UnixLocalSandboxClientOptions,
    UnixLocalSandboxSession,
    UnixLocalSandboxSessionState,
)
from agents.sandbox.types import ExposedPortEndpoint


if TYPE_CHECKING:
    from agents.sandbox.manifest import Manifest


class RailwaySession(UnixLocalSandboxSession):
    proxy_port: int = 48080

    async def _resolved_exec_context(self) -> tuple[dict[str, str], str]:
        _inherited, cwd = await super()._resolved_exec_context()
        # Model tools do not need the orchestrator's API, webhook or provider keys.
        keep = {
            "PATH",
            "LANG",
            "LC_ALL",
            "VIRTUAL_ENV",
            "PYTHONPATH",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "REQUESTS_CA_BUNDLE",
            "PLAYWRIGHT_BROWSERS_PATH",
            "AGENT_BROWSER_EXECUTABLE_PATH",
            "AGENT_BROWSER_ARGS",
            "AGENT_BROWSER_USER_AGENT",
        }
        env = {k: v for k, v in os.environ.items() if k in keep}
        env.update(await self.state.manifest.environment.resolve())
        proxy = f"http://127.0.0.1:{self.proxy_port}"
        env.update(
            HOME=cwd,
            TMPDIR=str(Path(cwd) / ".tmp"),
            STRIX_CAIDO_URL=proxy,
            http_proxy=proxy,
            https_proxy=proxy,
            ALL_PROXY=proxy,
            NO_PROXY="localhost,127.0.0.1",
            AGENT_BROWSER_SESSION=self.state.session_id.hex,
            AGENT_BROWSER_SOCKET_DIR=str(Path(cwd) / ".browser"),
            AGENT_BROWSER_SCREENSHOT_DIR=str(Path(cwd) / ".screenshots"),
        )
        return env, cwd

    def _map(self, value: Any) -> str:
        return re.sub(
            r"(?<![A-Za-z0-9_./:-])/workspace(?=/|[^A-Za-z0-9_.-]|$)",
            lambda _match: str(self.state.manifest.root),
            str(value),
        ).replace("http://127.0.0.1:48080", f"http://127.0.0.1:{self.proxy_port}")

    async def _exec_internal(self, *command: Any, **kwargs: Any) -> Any:
        return await super()._exec_internal(*(self._map(p) for p in command), **kwargs)

    async def pty_exec_start(self, *command: Any, **kwargs: Any) -> Any:
        return await super().pty_exec_start(*(self._map(p) for p in command), **kwargs)

    def normalize_path(self, path: Any, **kwargs: Any) -> Path:
        return super().normalize_path(self._map(path), **kwargs)

    async def _resolve_exposed_port(self, port: int) -> ExposedPortEndpoint:
        return ExposedPortEndpoint(
            host="127.0.0.1", port=self.proxy_port if port == 48080 else port
        )


class RailwayClient(UnixLocalSandboxClient):
    proxy: asyncio.subprocess.Process | None = None

    async def delete(self, session: Any) -> Any:
        await session.shutdown()
        if self.proxy and self.proxy.returncode is None:
            self.proxy.terminate()
            try:
                await asyncio.wait_for(self.proxy.wait(), 5)
            except TimeoutError:
                self.proxy.kill()
                await self.proxy.wait()
        return await super().delete(session)


async def railway_backend(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
    bind_mounts: list[dict[str, Any]] | None = None,
) -> tuple[Any, Any]:
    if bind_mounts or manifest.entries:
        raise ValueError("The Railway web runtime accepts URL assessments only")
    client = RailwayClient()
    session = await client.create(
        manifest=manifest, options=UnixLocalSandboxClientOptions(exposed_ports=exposed_ports)
    )
    # Swap only the SDK session implementation, retaining its state and wrapper.
    assert isinstance(session._inner.state, UnixLocalSandboxSessionState)
    inner = RailwaySession(state=session._inner.state)
    session._inner = inner
    workspace = Path(session.state.manifest.root)
    for name in (".tmp", ".browser", ".screenshots"):
        (workspace / name).mkdir(parents=True, exist_ok=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        inner.proxy_port = sock.getsockname()[1]
    try:
        cert_args = (
            ["--import-ca-cert", os.environ["STRIX_PROXY_CA_P12"], "--import-ca-cert-pass", ""]
            if os.environ.get("STRIX_PROXY_CA_P12")
            else []
        )
        proxy_log = workspace / ".proxy-startup.log"
        log_handle = proxy_log.open("wb")
        client.proxy = await asyncio.create_subprocess_exec(
            "caido-cli",
            "--listen",
            f"127.0.0.1:{inner.proxy_port}",
            "--data-path",
            str(workspace / ".proxy"),
            "--allow-guests",
            "--no-open",
            "--no-logging",
            *cert_args,
            stdout=log_handle,
            stderr=log_handle,
        )
        log_handle.close()
        await session.start()

        def probe() -> bool:
            body = json.dumps(
                {"query": "mutation { loginAsGuest { token { accessToken } } }"}
            ).encode()
            request = urllib.request.Request(
                f"http://127.0.0.1:{inner.proxy_port}/graphql",
                data=body,
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                    request, timeout=2
                ) as response:
                    return bool(
                        json.load(response)
                        .get("data", {})
                        .get("loginAsGuest", {})
                        .get("token", {})
                        .get("accessToken")
                    )
            except (OSError, ValueError, urllib.error.URLError):
                return False

        for _ in range(40):
            if client.proxy.returncode is not None:
                detail = proxy_log.read_text(errors="replace")[-3000:]
                raise RuntimeError(f"Caido exited ({client.proxy.returncode}): {detail}")  # noqa: TRY301
            if await asyncio.to_thread(probe):
                break
            await asyncio.sleep(0.5)
        else:
            raise RuntimeError(  # noqa: TRY301
                f"Caido startup timed out: {proxy_log.read_text(errors='replace')[-3000:]}"
            )
    except BaseException:
        with contextlib.suppress(Exception):
            await client.delete(session)
        raise
    return client, session


def register_railway_backend() -> None:
    from strix.runtime.backends import register_backend

    register_backend("railway", railway_backend)
