"""Tests for operator custom-instruction and scope pass-through.

These lock down the safety-critical path that makes the operator's custom
instructions (``--instruction`` / web ``instruction`` field) and the
system-verified scope authoritative and durable for EVERY agent, including the
sub-agents that perform the actual testing:

1. ``_build_system_scope_context`` carries ``user_instructions`` alongside the
   authorized-target list.
2. The system-prompt template renders both the AUTHORIZED TARGETS block and the
   USER RULES OF ENGAGEMENT block when (and only when) the context is populated.
3. ``create_agent`` propagates the parent's authoritative context into every
   sub-agent's ``LLMConfig`` so the blocks render in the child's system prompt.
"""

from __future__ import annotations

import types
from typing import Any

import pytest

from strix.agents.StrixAgent import StrixAgent
from strix.llm import LLM
from strix.llm.config import LLMConfig


TEST_MODEL = "openai/gpt-5.4"


def _scan_config(user_instructions: str = "") -> dict[str, Any]:
    return {
        "scan_id": "test-scan",
        "scan_mode": "deep",
        "user_instructions": user_instructions,
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": "https://staging.example.com"},
                "original": "https://staging.example.com",
            },
            {
                "type": "repository",
                "details": {
                    "target_repo": "https://github.com/acme/app",
                    "cloned_repo_path": "/tmp/app",
                    "workspace_subdir": "app",
                },
                "original": "https://github.com/acme/app",
            },
            {
                "type": "ip_address",
                "details": {"target_ip": "10.0.0.5"},
                "original": "10.0.0.5",
            },
            {
                "type": "local_code",
                "details": {"target_path": "/src/api", "workspace_subdir": "api"},
                "original": "/src/api",
            },
        ],
    }


def test_build_system_scope_context_includes_user_instructions() -> None:
    instructions = "Only test /v2 endpoints; do NOT touch /admin; no DoS-style payloads."
    ctx = StrixAgent._build_system_scope_context(_scan_config(instructions))

    assert ctx["user_instructions"] == instructions
    # Existing scope guarantees must be preserved.
    assert ctx["scope_source"] == "system_scan_config"
    assert ctx["authorization_source"] == "strix_platform_verified_targets"


def test_build_system_scope_context_defaults_instructions_to_empty_string() -> None:
    # Missing key and explicit None both normalize to "" (falsy -> block hidden).
    assert StrixAgent._build_system_scope_context({"targets": []})["user_instructions"] == ""

    cfg = _scan_config()
    cfg["user_instructions"] = None
    assert StrixAgent._build_system_scope_context(cfg)["user_instructions"] == ""


def test_build_system_scope_context_maps_target_types() -> None:
    ctx = StrixAgent._build_system_scope_context(_scan_config("focus auth"))
    targets = {t["type"]: t for t in ctx["authorized_targets"]}

    assert targets["web_application"]["value"] == "https://staging.example.com"
    assert targets["repository"]["value"] == "https://github.com/acme/app"
    assert targets["ip_address"]["value"] == "10.0.0.5"
    assert targets["local_code"]["value"] == "/src/api"
    # workspace_subdir -> /workspace/<subdir>
    assert targets["repository"]["workspace_path"] == "/workspace/app"
    assert targets["local_code"]["workspace_path"] == "/workspace/api"


def test_system_prompt_renders_scope_and_user_instructions() -> None:
    instructions = "Only test /v2 endpoints; do NOT touch /admin; no DoS-style payloads."
    ctx = StrixAgent._build_system_scope_context(_scan_config(instructions))

    llm = LLM(
        LLMConfig(model_name=TEST_MODEL, system_prompt_context=ctx),
        agent_name="StrixAgent",
    )

    prompt = llm.system_prompt
    assert prompt, "system prompt failed to render"
    # Scope block
    assert "AUTHORIZED TARGETS:" in prompt
    assert "https://staging.example.com" in prompt
    # Operator rules-of-engagement block, verbatim instructions included
    assert "USER RULES OF ENGAGEMENT" in prompt
    assert "OPERATOR INSTRUCTIONS:" in prompt
    assert "do NOT touch /admin" in prompt


def test_system_prompt_omits_blocks_without_context() -> None:
    llm = LLM(LLMConfig(model_name=TEST_MODEL), agent_name="StrixAgent")
    prompt = llm.system_prompt

    assert prompt, "system prompt failed to render"
    assert "AUTHORIZED TARGETS:" not in prompt
    assert "USER RULES OF ENGAGEMENT" not in prompt
    assert "OPERATOR INSTRUCTIONS:" not in prompt


class _DummyThread:
    """Stand-in for threading.Thread so create_agent never runs the agent loop."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.daemon = kwargs.get("daemon", False)

    def start(self) -> None:  # no-op: do not spawn the sub-agent loop / sandbox
        return None


@pytest.fixture
def _clean_agent_graph(monkeypatch):
    from strix.tools.agents_graph import agents_graph_actions as ag

    monkeypatch.setattr(ag, "_agent_graph", {"nodes": {}, "edges": []})
    monkeypatch.setattr(ag, "_agent_messages", {})
    monkeypatch.setattr(ag, "_agent_instances", {})
    monkeypatch.setattr(ag, "_agent_states", {})
    monkeypatch.setattr(ag, "_running_agents", {})
    monkeypatch.setattr(ag, "_root_agent_id", None)
    monkeypatch.setattr(ag.threading, "Thread", _DummyThread)
    return ag


def test_create_agent_propagates_scope_and_instructions_to_subagent(
    monkeypatch, _clean_agent_graph
) -> None:
    monkeypatch.setenv("STRIX_LLM", TEST_MODEL)
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "true")
    ag = _clean_agent_graph

    instructions = "Stay on staging only; never test production; skip destructive payloads."
    parent_ctx = StrixAgent._build_system_scope_context(_scan_config(instructions))

    # Fake parent: only the attributes create_agent reads off the instance.
    parent_id = "agent_parent01"
    fake_parent = types.SimpleNamespace(
        llm=types.SimpleNamespace(_system_prompt_context=parent_ctx),
        llm_config=LLMConfig(model_name=TEST_MODEL, scan_mode="deep"),
    )
    ag._agent_instances[parent_id] = fake_parent
    parent_state = types.SimpleNamespace(agent_id=parent_id)

    result = ag.create_agent(
        parent_state,
        task="Test SQLi on the login form",
        name="SQLi Agent",
        inherit_context=False,  # worst case: inheritance is NOT the carrier
    )

    assert result["success"] is True
    child = ag._agent_instances[result["agent_id"]]

    # Child config carries the authoritative context...
    assert child.llm_config.system_prompt_context.get("user_instructions") == instructions
    assert child.llm_config.system_prompt_context.get("authorized_targets")
    # ...and it actually renders into the child's (root-independent) system prompt.
    prompt = child.llm.system_prompt
    assert "USER RULES OF ENGAGEMENT" in prompt
    assert "never test production" in prompt
    assert "AUTHORIZED TARGETS:" in prompt


def test_create_agent_falls_back_to_tracer_scan_config(monkeypatch, _clean_agent_graph) -> None:
    """If the parent instance carries no live context, rebuild it from scan_config."""
    monkeypatch.setenv("STRIX_LLM", TEST_MODEL)
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "true")
    ag = _clean_agent_graph

    instructions = "Read-only recon; do not submit any forms."

    from strix.telemetry.tracer import Tracer, set_global_tracer

    tracer = Tracer("fallback-scan")
    tracer.set_scan_config(_scan_config(instructions))
    set_global_tracer(tracer)

    parent_id = "agent_parent02"
    # Parent instance exists but exposes an EMPTY context (e.g. standalone path).
    fake_parent = types.SimpleNamespace(
        llm=types.SimpleNamespace(_system_prompt_context={}),
        llm_config=LLMConfig(model_name=TEST_MODEL, scan_mode="deep"),
    )
    ag._agent_instances[parent_id] = fake_parent
    parent_state = types.SimpleNamespace(agent_id=parent_id)

    result = ag.create_agent(parent_state, task="Recon", name="Recon Agent")

    assert result["success"] is True
    child = ag._agent_instances[result["agent_id"]]
    assert child.llm_config.system_prompt_context.get("user_instructions") == instructions
    assert "do not submit any forms" in child.llm.system_prompt
