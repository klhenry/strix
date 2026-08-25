import logging
import re
from typing import Any

from strix.tools.registry import register_tool

logger = logging.getLogger(__name__)

# Track how many times finish_scan has been called with active agents, per scan
_finish_scan_attempts: dict[str, int] = {}
_MAX_ATTEMPTS_BEFORE_FORCE: int = 3

# Track agents that have already been warned about 0 findings so we allow
# them through on the second call.
_zero_findings_warned: set[str] = set()

# Track agents already warned about targets left untested so a scan can still
# complete (with documented limitations) on the second finish_scan call.
_incomplete_coverage_warned: set[str] = set()

_VALID_COVERAGE_STATUSES = {
    "tested_with_findings",
    "tested_no_findings",
    "excluded",
    "not_tested",
}
_VALID_COVERAGE_AUTH = {
    "unauthenticated",
    "authenticated",
    "both",
    "not_applicable",
}


def _authorized_targets(scan_config: dict[str, Any] | None) -> list[tuple[str, str]]:
    """Extract (type, value) for every platform-verified in-scope target.

    Mirrors StrixAgent._build_system_scope_context value extraction without
    importing the agent stack into this tools module.
    """
    targets = (scan_config or {}).get("targets", []) or []
    out: list[tuple[str, str]] = []
    for target in targets:
        ttype = target.get("type", "unknown")
        details = target.get("details", {}) or {}
        if ttype == "repository":
            value = details.get("target_repo", "")
        elif ttype == "local_code":
            value = details.get("target_path", "")
        elif ttype == "web_application":
            value = details.get("target_url", "")
        elif ttype == "ip_address":
            value = details.get("target_ip", "")
        else:
            value = target.get("original", "")
        if value:
            out.append((ttype, value))
    return out


def _parse_scope_coverage(xml_str: str) -> list[dict[str, str]]:
    if not xml_str or not xml_str.strip():
        return []
    entries: list[dict[str, str]] = []
    for match in re.finditer(r"<target>(.*?)</target>", xml_str, re.DOTALL):
        block = match.group(1)
        entry: dict[str, str] = {}
        for field in ("asset", "status", "authentication", "notes"):
            field_match = re.search(rf"<{field}>(.*?)</{field}>", block, re.DOTALL)
            if field_match:
                entry[field] = field_match.group(1).strip()
        if entry.get("asset"):
            entries.append(entry)
    return entries


def _normalize_asset(value: str) -> str:
    normalized = (value or "").strip().lower()
    for scheme in ("https://", "http://"):
        if normalized.startswith(scheme):
            normalized = normalized[len(scheme) :]
            break
    if normalized.startswith("www."):
        normalized = normalized[4:]
    return normalized.rstrip("/")


def _asset_matches(target_value: str, entry_asset: str) -> bool:
    a = _normalize_asset(target_value)
    b = _normalize_asset(entry_asset)
    if not a or not b:
        return False
    return a == b or a in b or b in a


def _validate_coverage_structure(entries: list[dict[str, str]]) -> list[str]:
    errors: list[str] = []
    for entry in entries:
        asset = entry.get("asset", "")
        status = entry.get("status", "")
        auth = entry.get("authentication", "")
        if status not in _VALID_COVERAGE_STATUSES:
            errors.append(
                f"scope_coverage target '{asset}': status must be one of "
                f"{sorted(_VALID_COVERAGE_STATUSES)} (got '{status}')"
            )
        if auth not in _VALID_COVERAGE_AUTH:
            errors.append(
                f"scope_coverage target '{asset}': authentication must be one of "
                f"{sorted(_VALID_COVERAGE_AUTH)} (got '{auth}')"
            )
        if status in ("excluded", "not_tested") and not entry.get("notes", "").strip():
            errors.append(
                f"scope_coverage target '{asset}': status '{status}' requires a reason in <notes>"
            )
    return errors


def _coverage_gaps(
    entries: list[dict[str, str]], authorized: list[tuple[str, str]]
) -> tuple[list[str], list[str]]:
    """Return (unaccounted_target_values, not_tested_target_values)."""
    unaccounted: list[str] = []
    not_tested: list[str] = []
    for _ttype, value in authorized:
        matched = [e for e in entries if _asset_matches(value, e.get("asset", ""))]
        if not matched:
            unaccounted.append(value)
        elif all(e.get("status") == "not_tested" for e in matched):
            not_tested.append(value)
    return unaccounted, not_tested


def _render_coverage_markdown(entries: list[dict[str, str]], limitations: str) -> str:
    status_labels = {
        "tested_with_findings": "Tested — findings reported",
        "tested_no_findings": "Tested — no findings",
        "excluded": "Excluded from scope",
        "not_tested": "Not tested",
    }
    auth_labels = {
        "unauthenticated": "unauthenticated testing",
        "authenticated": "authenticated testing",
        "both": "authenticated and unauthenticated testing",
        "not_applicable": "authentication not applicable",
    }
    lines = ["## Scope Coverage", ""]
    for entry in entries:
        asset = entry.get("asset", "")
        status = status_labels.get(entry.get("status", ""), entry.get("status", ""))
        auth = auth_labels.get(entry.get("authentication", ""), entry.get("authentication", ""))
        note = entry.get("notes", "").strip()
        line = f"- {asset}: {status} ({auth})."
        if note:
            line += f" {note}"
        lines.append(line)
    lines += ["", "## Testing Limitations", "", limitations.strip()]
    return "\n".join(lines)


def _render_tools_used_markdown(tools_used: list[str]) -> str:
    lines = ["## Tools and Techniques Used", ""]
    lines += [f"- {tool}" for tool in tools_used]
    return "\n".join(lines)


def _validate_root_agent(agent_state: Any) -> dict[str, Any] | None:
    if agent_state and hasattr(agent_state, "parent_id") and agent_state.parent_id is not None:
        return {
            "success": False,
            "error": "finish_scan_wrong_agent",
            "message": "This tool can only be used by the root/main agent",
            "suggestion": "If you are a subagent, use agent_finish from agents_graph tool instead",
        }
    return None


def _check_active_agents(agent_state: Any = None) -> dict[str, Any] | None:
    try:
        from strix.tools.agents_graph.agents_graph_actions import (
            _agent_graph,
            force_stop_all_subagents,
        )

        if agent_state and agent_state.agent_id:
            current_agent_id = agent_state.agent_id
        else:
            return None

        active_agents = []
        stopping_agents = []

        for agent_id, node in _agent_graph["nodes"].items():
            if agent_id == current_agent_id:
                continue

            status = node.get("status", "unknown")
            if status == "running":
                active_agents.append(
                    {
                        "id": agent_id,
                        "name": node.get("name", "Unknown"),
                        "task": node.get("task", "Unknown task")[:300],
                        "status": status,
                    }
                )
            elif status == "stopping":
                stopping_agents.append(
                    {
                        "id": agent_id,
                        "name": node.get("name", "Unknown"),
                        "task": node.get("task", "Unknown task")[:300],
                        "status": status,
                    }
                )

        if active_agents or stopping_agents:
            _finish_scan_attempts[current_agent_id] = _finish_scan_attempts.get(current_agent_id, 0) + 1
            attempts = _finish_scan_attempts[current_agent_id]

            # After N failed attempts, force-stop all sub-agents
            if attempts >= _MAX_ATTEMPTS_BEFORE_FORCE:
                total_stuck = len(active_agents) + len(stopping_agents)
                stopped_ids = force_stop_all_subagents(current_agent_id)
                logger.warning(
                    "Force-stopped %d stuck sub-agents after %d finish_scan attempts",
                    len(stopped_ids),
                    attempts,
                )
                _finish_scan_attempts.pop(current_agent_id, None)
                # Allow finish_scan to proceed
                return None

            response: dict[str, Any] = {
                "success": False,
                "error": "agents_still_active",
                "message": f"Cannot finish scan: agents are still active "
                f"(attempt {attempts}/{_MAX_ATTEMPTS_BEFORE_FORCE}, "
                f"will force-stop on attempt {_MAX_ATTEMPTS_BEFORE_FORCE})",
            }

            if active_agents:
                response["active_agents"] = active_agents

            if stopping_agents:
                response["stopping_agents"] = stopping_agents

            response["suggestions"] = [
                "Use wait_for_message to wait for all agents to complete",
                "Use send_message_to_agent if you need agents to complete immediately",
                f"Or call finish_scan again — after {_MAX_ATTEMPTS_BEFORE_FORCE} "
                f"attempts, stuck agents will be force-stopped automatically",
            ]

            response["total_active"] = len(active_agents) + len(stopping_agents)

            return response

    except ImportError:
        pass
    except Exception:
        logging.exception("Error checking active agents")

    return None


@register_tool(sandbox_execution=False)
def finish_scan(
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
    scope_coverage: str = "",
    limitations: str = "",
    agent_state: Any = None,
) -> dict[str, Any]:
    validation_error = _validate_root_agent(agent_state)
    if validation_error:
        return validation_error

    active_agents_error = _check_active_agents(agent_state)
    if active_agents_error:
        return active_agents_error

    validation_errors = []

    if not executive_summary or not executive_summary.strip():
        validation_errors.append("Executive summary cannot be empty")
    if not methodology or not methodology.strip():
        validation_errors.append("Methodology cannot be empty")
    if not technical_analysis or not technical_analysis.strip():
        validation_errors.append("Technical analysis cannot be empty")
    if not recommendations or not recommendations.strip():
        validation_errors.append("Recommendations cannot be empty")
    if not limitations or not limitations.strip():
        validation_errors.append(
            "Limitations cannot be empty — document any constraints and untested areas, "
            "and confirm findings were validated in a controlled, low-volume manner"
        )

    coverage_entries = _parse_scope_coverage(scope_coverage)
    if not coverage_entries:
        validation_errors.append(
            "scope_coverage is required — provide one <target> block per in-scope asset "
            "with <asset>, <status>, <authentication>, and <notes>"
        )
    validation_errors.extend(_validate_coverage_structure(coverage_entries))

    if validation_errors:
        return {"success": False, "message": "Validation failed", "errors": validation_errors}

    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            vulnerability_count = len(tracer.vulnerability_reports)
            agent_id = (
                agent_state.agent_id
                if agent_state and hasattr(agent_state, "agent_id")
                else "unknown"
            )
            logger.info(
                "[FINISH_SCAN] finish_scan called — vulnerability_reports=%d, "
                "tracer_run_id=%s, tracer_id=%s",
                vulnerability_count,
                tracer.run_id,
                id(tracer),
            )
            if vulnerability_count == 0:
                logger.warning(
                    "[FINISH_SCAN] Scan completing with 0 vulnerability reports. "
                    "Either no vulnerabilities were found, or create_vulnerability_report "
                    "was never called / always failed. Check earlier logs for "
                    "[VULN_REPORT] entries.",
                )

            # ── Scope-coverage gate ──────────────────────────────────
            # Every platform-verified in-scope target must be explicitly
            # accounted for in scope_coverage. This catches the "only one
            # of the approved apps was tested" failure mode before the
            # report is generated.
            authorized = _authorized_targets(tracer.scan_config)
            unaccounted, not_tested = _coverage_gaps(coverage_entries, authorized)

            if unaccounted:
                logger.warning(
                    "[FINISH_SCAN] Blocking finish — %d in-scope target(s) unaccounted "
                    "for in scope_coverage: %s",
                    len(unaccounted),
                    ", ".join(unaccounted),
                )
                asset_lines = "\n".join(f"- {value}" for value in unaccounted)
                return {
                    "success": False,
                    "error": "incomplete_scope_coverage",
                    "message": (
                        "Cannot finish scan: the following platform-approved in-scope "
                        "target(s) are missing from scope_coverage. Every approved asset "
                        "must be explicitly accounted for before the report is generated "
                        "(the client approved these assets — they cannot be silently "
                        "dropped):\n\n"
                        f"{asset_lines}\n\n"
                        "ACTION REQUIRED: Test each missing asset now (spawn dedicated "
                        "sub-agents if needed), then add a <target> block for it to "
                        "scope_coverage with <asset>, <status>, <authentication>, and "
                        "<notes>. If an asset is genuinely out of scope or unreachable, "
                        "still add its <target> block with status 'excluded' or "
                        "'not_tested' and a clear reason in <notes>."
                    ),
                }

            # ── Untested-target soft guard ───────────────────────────
            # If any approved target is marked not_tested, bounce ONCE to
            # push for coverage; allow through on retry so a scan can still
            # complete with the limitation clearly documented in the report.
            if not_tested and agent_id not in _incomplete_coverage_warned:
                _incomplete_coverage_warned.add(agent_id)
                asset_lines = "\n".join(f"- {value}" for value in not_tested)
                logger.info(
                    "[FINISH_SCAN] Untested-target soft guard for agent %s: %s",
                    agent_id,
                    ", ".join(not_tested),
                )
                return {
                    "success": False,
                    "error": "targets_not_tested",
                    "message": (
                        "The following approved in-scope target(s) are marked "
                        "'not_tested':\n\n"
                        f"{asset_lines}\n\n"
                        "These were approved by the client and should be tested. "
                        "Test them now (spawn dedicated sub-agents if needed) and update "
                        "their scope_coverage status, or — if they genuinely cannot be "
                        "tested — call finish_scan again to complete with the limitation "
                        "documented in the report."
                    ),
                }

            # ── Zero-findings guard ──────────────────────────────────
            # On the FIRST finish_scan call with 0 findings, bounce the
            # agent back so it has a chance to call
            # create_vulnerability_report.  Allow through on retry so
            # scans that genuinely find nothing can still complete.
            if vulnerability_count == 0 and agent_id not in _zero_findings_warned:
                _zero_findings_warned.add(agent_id)
                logger.info(
                    "[FINISH_SCAN] Returning zero-findings prompt for agent %s",
                    agent_id,
                )
                return {
                    "success": False,
                    "error": "no_vulnerability_reports",
                    "message": (
                        "You are trying to finish the scan but have not created "
                        "any vulnerability reports. The PDF report will be empty "
                        "unless you call create_vulnerability_report for each "
                        "finding BEFORE calling finish_scan.\n\n"
                        "ACTION REQUIRED: Review the issues you discovered during "
                        "this scan and call create_vulnerability_report for each "
                        "one now. After reporting all findings, call finish_scan "
                        "again.\n\n"
                        "If you genuinely found zero vulnerabilities, call "
                        "finish_scan once more to confirm."
                    ),
                }

            report_sections = [
                methodology.strip(),
                _render_coverage_markdown(coverage_entries, limitations),
            ]
            # Append the tools/techniques ACTUALLY used, derived from the
            # execution log, so the report cannot over-claim a generic toolset.
            try:
                tools_used = tracer.get_tools_used()
            except AttributeError:
                tools_used = []
            if tools_used:
                report_sections.append(_render_tools_used_markdown(tools_used))
            methodology_final = "\n\n".join(report_sections)
            tracer.update_scan_final_fields(
                executive_summary=executive_summary.strip(),
                methodology=methodology_final,
                technical_analysis=technical_analysis.strip(),
                recommendations=recommendations.strip(),
            )

            return {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed successfully",
                "vulnerabilities_found": vulnerability_count,
            }

        logger.warning(
            "[FINISH_SCAN] Tracer UNAVAILABLE — scan results not stored. "
            "The PDF report will have no findings.",
        )
        return {
            "success": False,
            "message": "Cannot complete scan — tracer unavailable, results not stored",
        }

    except (ImportError, AttributeError) as e:
        logger.error("[FINISH_SCAN] EXCEPTION: %s", e, exc_info=True)
        return {"success": False, "message": f"Failed to complete scan: {e!s}"}
