"""SDK finish tool retaining Accountable scope and authenticated-coverage gates."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from agents import RunContextWrapper, function_tool

from strix.accountable.coverage import finish_scan as validate_and_finish
from strix.core.agents import coordinator_from_context


@function_tool(name_override="finish_scan", timeout=60)
async def accountable_finish_scan(
    ctx: RunContextWrapper,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
    scope_coverage: str,
    limitations: str,
) -> str:
    """Finalize the Accountable report after reporting findings and checking coverage.

    Root only. First wait for all child agents to finish. All four narrative fields
    and limitations must be complete, factual, client-facing Markdown. Never include
    credentials. scope_coverage is XML: <coverage><target><asset>https://host/</asset>
    <status>tested_with_findings|tested_no_findings|not_tested|excluded</status>
    <authentication>authenticated|unauthenticated|both|not_applicable</authentication>
    <notes>Specific tests and evidence or the causal access blocker</notes></target></coverage>.
    Include every authorized asset. Authenticated testing requires actual login and
    protected-page checks. If blocked, explain the cause in both matching notes and
    limitations. Never call a login-page-only scan authenticated. Findings must first
    be filed using create_vulnerability_report. Review list_reports/list_coverage,
    consider plausible attack chains, and record unresolved work before finishing.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    if inner.get("parent_id") is not None:
        return json.dumps({"success": False, "error": "Only the root agent can finish the scan"})
    if coordinator is not None and me is not None:
        active = await coordinator.active_agents_except(me)
        if active:
            return json.dumps(
                {
                    "success": False,
                    "error": "Wait for or stop active child agents",
                    "active_agents": active,
                }
            )
    result = await asyncio.to_thread(
        validate_and_finish,
        executive_summary=executive_summary,
        methodology=methodology,
        technical_analysis=technical_analysis,
        recommendations=recommendations,
        scope_coverage=scope_coverage,
        limitations=limitations,
        agent_state=SimpleNamespace(parent_id=None, agent_id=me or "root"),
    )
    if result.get("success") and coordinator is not None and isinstance(me, str):
        await coordinator.set_status(me, "completed")
    return json.dumps(result, default=str)
