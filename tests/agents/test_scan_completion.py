from unittest.mock import AsyncMock, MagicMock

import pytest

from strix.agents.base_agent import BaseAgent
from strix.agents.state import AgentState


@pytest.mark.asyncio
@pytest.mark.parametrize("stopped", [False, True])
async def test_agent_budget_or_stop_without_finish_is_explicit_failure(monkeypatch, stopped):
    agent = object.__new__(BaseAgent)
    agent.state = AgentState(iteration=75 if not stopped else 2, max_iterations=75)
    agent.state.stop_requested = stopped
    agent.interactive = False
    agent._force_stop = False
    agent._initialize_sandbox_and_state = AsyncMock()
    agent._check_agent_messages = MagicMock()
    monkeypatch.setattr("strix.telemetry.tracer.get_global_tracer", lambda: None)

    result = await agent.agent_loop("Assess the authorized target")

    assert result["success"] is False
    assert "finish tool" in result["error"]
    if not stopped:
        assert "iteration limit (75)" in result["error"]
