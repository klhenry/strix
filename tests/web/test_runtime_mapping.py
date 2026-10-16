"""Exercise the real SDK session without a model or network target."""

from __future__ import annotations

import io
from pathlib import Path

from agents.sandbox.sandboxes.unix_local import UnixLocalSandboxClient

from strix.accountable.runtime import RailwaySession


async def test_virtual_workspace_and_secret_filtering(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "fixture-private-provider-token")
    monkeypatch.setenv("WEBHOOK_SHARED_SECRET", "fixture-private-webhook-token")
    client = UnixLocalSandboxClient()
    session = await client.create()
    inner = RailwaySession(state=session._inner.state)
    session._inner = inner
    root = Path(session.state.manifest.root)
    (root / ".tmp").mkdir()
    await session.start()
    try:
        env, _cwd = await inner._resolved_exec_context()
        assert "LLM_API_KEY" not in env
        assert "WEBHOOK_SHARED_SECRET" not in env
        await session.write(Path("/workspace/evidence.txt"), io.BytesIO(b"strix-ready"))
        result = await session.exec("cat /workspace/evidence.txt", timeout=10)
        assert result.ok()
        assert result.stdout == b"strix-ready"
        request = "curl https://example.test/workspace/items"
        assert inner._map(request) == request
        assert inner._map("cd /workspace && pwd") == f"cd {root} && pwd"
    finally:
        await session.shutdown()
        await client.delete(session)
