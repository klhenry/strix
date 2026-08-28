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
from pathlib import Path
from typing import Any

import defusedxml.ElementTree as DefusedET
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


def test_build_system_scope_context_surfaces_instruction_declared_scope() -> None:
    # An app named only in the free-text instructions must be surfaced as an
    # operator-declared asset so it cannot be silently dropped, and provided
    # credentials must flip auth_expected on.
    instructions = (
        "Also test the SetMore staging app at https://go.staging.setmore.com/. "
        "Use the provisioned admin audit account for authenticated testing."
    )
    ctx = StrixAgent._build_system_scope_context(_scan_config(instructions))
    assert "https://go.staging.setmore.com/" in ctx["instruction_declared_assets"]
    assert ctx["auth_expected"] is True
    assert "user_instructions_do_not_expand_scope" not in ctx


def test_repository_host_does_not_cover_instruction_declared_web_scope() -> None:
    cfg = _scan_config("Also test https://api.github.com as an in-scope web application.")
    cfg["targets"] = [target for target in cfg["targets"] if target["type"] == "repository"]

    ctx = StrixAgent._build_system_scope_context(cfg)

    assert ctx["instruction_declared_assets"] == ["https://api.github.com/"]


def test_structured_repository_url_suppresses_exact_instruction_duplicate() -> None:
    repo = "https://github.com/acme/app"
    cfg = _scan_config(f"Also test {repo} as an in-scope target.")
    cfg["targets"] = [target for target in cfg["targets"] if target["type"] == "repository"]

    ctx = StrixAgent._build_system_scope_context(cfg)

    assert ctx["instruction_declared_assets"] == []


def test_structured_repository_url_does_not_hide_distinct_instruction_path() -> None:
    cfg = _scan_config(
        "Also test https://github.com/acme/app/security as an in-scope web application."
    )
    cfg["targets"] = [target for target in cfg["targets"] if target["type"] == "repository"]

    ctx = StrixAgent._build_system_scope_context(cfg)

    assert ctx["instruction_declared_assets"] == ["https://github.com/acme/app/security"]


def test_build_system_scope_context_preserves_distinct_instruction_target_identity() -> None:
    instructions = (
        "In-scope targets: https://www.customer.test:8443/api//v2 and "
        "https://customer.test:9443/api/v2."
    )
    ctx = StrixAgent._build_system_scope_context(_scan_config(instructions))

    assert ctx["instruction_declared_assets"] == [
        "https://www.customer.test:8443/api//v2",
        "https://customer.test:9443/api/v2",
    ]


def test_structured_path_does_not_hide_instruction_declared_sibling_path() -> None:
    cfg = _scan_config("Also test https://staging.example.com/admin/v2 as in scope.")
    web_target = next(target for target in cfg["targets"] if target["type"] == "web_application")
    web_target["details"]["target_url"] = "https://staging.example.com/public/v2"
    web_target["original"] = "https://staging.example.com/public/v2"

    ctx = StrixAgent._build_system_scope_context(cfg)

    assert ctx["instruction_declared_assets"] == [
        "https://staging.example.com/admin/v2",
    ]


def test_build_system_scope_context_declared_scope_empty_by_default() -> None:
    ctx = StrixAgent._build_system_scope_context(_scan_config("focus on the login flow"))
    assert ctx["instruction_declared_assets"] == []
    assert ctx["auth_expected"] is False


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


def test_system_prompt_renders_operational_scope_and_auth_contract() -> None:
    instructions = (
        "Also test https://go.staging.setmore.com/. "
        "Use the provisioned admin audit account for authenticated testing. "
        "Do not test production."
    )
    ctx = StrixAgent._build_system_scope_context(_scan_config(instructions))
    llm = LLM(
        LLMConfig(model_name=TEST_MODEL, system_prompt_context=ctx),
        agent_name="StrixAgent",
    )

    prompt = llm.system_prompt
    operational_prompt, tool_marker, _ = prompt.partition("<tool_usage>")
    assert tool_marker
    for required_rule in (
        "OPERATOR-DECLARED ASSETS",
        "https://go.staging.setmore.com/",
        "Only AUTHORIZED TARGETS and explicitly parsed OPERATOR-DECLARED ASSETS",
        "Arbitrary free-text mentions",
        "Test and account for every distinct listed target exactly as shown",
        "explicit exclusion or narrower operator restriction ALWAYS wins",
        "authenticated or credentialed gray-box testing",
        "only credentials/accounts the operator authorized for use",
        "NEVER use an account or credential the operator forbids",
        "BOTH in the affected asset's scope_coverage notes AND in the report limitations",
        "Merely mentioning OTP/MFA does not document a blocker",
        'NEVER state that "no credentials were provided"',
    ):
        assert required_rule in operational_prompt

    # Exact XML shape and enums belong to the finish tool contract, not every
    # agent's operational system prompt.
    assert "tested_with_findings | tested_no_findings" not in operational_prompt
    assert "www/apex alias" not in operational_prompt
    stale_scope_wording = "They do NOT expand scope beyond the system-verified targets above"
    assert stale_scope_wording not in operational_prompt


def test_finish_schema_owns_exact_coverage_contract() -> None:
    schema_path = (
        Path(__file__).resolve().parents[2]
        / "strix"
        / "tools"
        / "finish"
        / "finish_actions_schema.xml"
    )
    schema = schema_path.read_text(encoding="utf-8")
    normalized_schema = " ".join(schema.split())
    parameters_xml = schema[
        schema.index("<parameters>") : schema.index("</parameters>") + len("</parameters>")
    ]
    parameters_root = DefusedET.fromstring(parameters_xml, forbid_dtd=True)
    parameters = {parameter.attrib["name"]: parameter for parameter in parameters_root}

    assert set(parameters) == {
        "executive_summary",
        "methodology",
        "technical_analysis",
        "recommendations",
        "scope_coverage",
        "limitations",
    }
    assert all(parameter.attrib.get("required") == "true" for parameter in parameters.values())

    scope_contract = " ".join("".join(parameters["scope_coverage"].itertext()).split())
    for required_rule in (
        "<coverage>",
        "tested_with_findings | tested_no_findings | excluded | not_tested",
        "unauthenticated | authenticated | both | not_applicable",
        "Every approved asset MUST have exactly one <target> block",
        "Missing, duplicate, extra, or unrecognized asset rows",
        "preserving the exact scheme, port, and path",
        "www/apex alias, different origin, the same host without the exact path, or a sibling path",
        "Never use credentials the operator forbids",
        "Use excluded if and only if",
        "explicitly excluded recognized target MUST use excluded and MUST NOT be tested",
        "Use not_tested for an asset that was unreachable, unattempted, deferred",
    ):
        assert required_rule in scope_contract

    limitations_contract = " ".join("".join(parameters["limitations"].itertext()).split())
    assert "exact blocker here and also in the affected scope_coverage target's <notes>" in (
        limitations_contract
    )
    assert "Incidental free-text references do not grant scope" in normalized_schema
    assert (
        "Repeating finish_scan never waives this per-target authentication gate"
        in normalized_schema
    )
    assert "Assessment type: External credentialed gray-box penetration test" in normalized_schema
    assert "External penetration test (black-box with limited gray-box context)" not in schema
    assert "using the provided accounts" not in schema
    assert "with the provided standard and admin test accounts" not in schema


def test_system_prompt_renders_instruction_only_scope_without_structured_targets() -> None:
    cfg = {
        "targets": [],
        "user_instructions": "Also test https://only.example.test:8443/app as in scope.",
    }
    ctx = StrixAgent._build_system_scope_context(cfg)
    llm = LLM(
        LLMConfig(model_name=TEST_MODEL, system_prompt_context=ctx),
        agent_name="StrixAgent",
    )

    prompt = llm.system_prompt
    assert "SYSTEM-VERIFIED SCOPE:" in prompt
    assert "OPERATOR-DECLARED ASSETS" in prompt
    assert "https://only.example.test:8443/app" in prompt
    assert "AUTHORIZED TARGETS:" not in prompt
    assert "USER RULES OF ENGAGEMENT" in prompt


def test_system_prompt_omits_blocks_without_context() -> None:
    llm = LLM(LLMConfig(model_name=TEST_MODEL), agent_name="StrixAgent")
    prompt = llm.system_prompt

    assert prompt, "system prompt failed to render"
    assert "AUTHORIZED TARGETS:" not in prompt
    assert "USER RULES OF ENGAGEMENT" not in prompt
    assert "OPERATOR INSTRUCTIONS:" not in prompt


class _DummyThread:
    """Stand-in for threading.Thread so create_agent never runs the agent loop."""

    def __init__(self, *_args: Any, **kwargs: Any) -> None:
        self.daemon = kwargs.get("daemon", False)

    def start(self) -> None:  # no-op: do not spawn the sub-agent loop / sandbox
        return None

    def join(self, _timeout: float | None = None) -> None:
        return None


@pytest.fixture
def clean_agent_graph(monkeypatch):
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
    monkeypatch, clean_agent_graph
) -> None:
    monkeypatch.setenv("STRIX_LLM", TEST_MODEL)
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "true")
    ag = clean_agent_graph

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


def test_create_agent_falls_back_to_tracer_scan_config(monkeypatch, clean_agent_graph) -> None:
    """If the parent instance carries no live context, rebuild it from scan_config."""
    monkeypatch.setenv("STRIX_LLM", TEST_MODEL)
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "true")
    ag = clean_agent_graph

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

    # This test exercises the tracer-based system-prompt fallback, not message
    # history inheritance; the lightweight state intentionally has no history API.
    result = ag.create_agent(
        parent_state,
        task="Recon",
        name="Recon Agent",
        inherit_context=False,
    )

    assert result["success"] is True
    child = ag._agent_instances[result["agent_id"]]
    assert child.llm_config.system_prompt_context.get("user_instructions") == instructions
    assert "do not submit any forms" in child.llm.system_prompt
