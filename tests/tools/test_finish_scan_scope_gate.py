"""Tests for the finish_scan scope-coverage gate.

The gate forces every platform-approved in-scope target to be explicitly
accounted for before the report is generated. It exists to stop the failure
mode where the client approves multiple applications but the report only covers
one of them, and to make authenticated-vs-unauthenticated coverage and testing
limitations explicit in the deliverable.
"""

from __future__ import annotations

import types
from typing import Any

import pytest

from strix.tools.finish import finish_actions as fa


TWO_APP_SCAN_CONFIG: dict[str, Any] = {
    "targets": [
        {
            "type": "web_application",
            "details": {"target_url": "https://staging.wellreceived.com"},
            "original": "https://staging.wellreceived.com",
        },
        {
            "type": "web_application",
            "details": {"target_url": "https://app.setmore.com"},
            "original": "https://app.setmore.com",
        },
    ]
}


class _FakeTracer:
    def __init__(
        self,
        scan_config: dict[str, Any],
        vuln_count: int = 1,
        tools_used: list[str] | None = None,
    ) -> None:
        self.scan_config = scan_config
        self.vulnerability_reports = list(range(vuln_count))
        self.run_id = "test-run"
        self.final_fields: dict[str, str] | None = None
        self._tools_used = tools_used or []

    def update_scan_final_fields(self, **kwargs: str) -> None:
        self.final_fields = kwargs

    def get_tools_used(self) -> list[str]:
        return list(self._tools_used)


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch):
    # Fresh per-test module state and an empty agent graph (no active sub-agents).
    monkeypatch.setattr(fa, "_zero_findings_warned", set())
    monkeypatch.setattr(fa, "_incomplete_coverage_warned", set())
    monkeypatch.setattr(fa, "_finish_scan_attempts", {})
    from strix.tools.agents_graph import agents_graph_actions as ag

    monkeypatch.setattr(ag, "_agent_graph", {"nodes": {}, "edges": []})


def _root_state() -> Any:
    return types.SimpleNamespace(parent_id=None, agent_id="root-agent")


def _install_tracer(monkeypatch, tracer: _FakeTracer) -> None:
    import strix.telemetry.tracer as tracer_mod

    monkeypatch.setattr(tracer_mod, "get_global_tracer", lambda: tracer)


def _coverage(*entries: str) -> str:
    return "<coverage>" + "".join(entries) + "</coverage>"


def _target(asset: str, status: str, auth: str, notes: str = "") -> str:
    return (
        f"<target><asset>{asset}</asset><status>{status}</status>"
        f"<authentication>{auth}</authentication><notes>{notes}</notes></target>"
    )


# ── Pure helpers ────────────────────────────────────────────────────────────


def test_authorized_targets_extracts_each_type() -> None:
    cfg = {
        "targets": [
            {"type": "repository", "details": {"target_repo": "https://github.com/a/b"}},
            {"type": "local_code", "details": {"target_path": "/src"}},
            {"type": "web_application", "details": {"target_url": "https://x"}},
            {"type": "ip_address", "details": {"target_ip": "10.0.0.1"}},
        ]
    }
    vals = [v for _t, v in fa._authorized_targets(cfg)]
    assert vals == ["https://github.com/a/b", "/src", "https://x", "10.0.0.1"]


def test_asset_matches_is_scheme_and_slash_insensitive() -> None:
    assert fa._asset_matches("https://app.setmore.com", "app.setmore.com/")
    assert fa._asset_matches("https://app.setmore.com/", "http://www.app.setmore.com")
    assert not fa._asset_matches("https://a.com", "https://b.com")


def test_coverage_gaps_flags_missing_and_not_tested() -> None:
    authorized = fa._authorized_targets(TWO_APP_SCAN_CONFIG)
    entries = fa._parse_scope_coverage(
        _coverage(_target("https://staging.wellreceived.com", "tested_no_findings", "both", "x"))
    )
    unaccounted, not_tested = fa._coverage_gaps(entries, authorized)
    assert unaccounted == ["https://app.setmore.com"]
    assert not_tested == []


def test_validate_coverage_structure_catches_bad_fields() -> None:
    entries = fa._parse_scope_coverage(
        _coverage(_target("x", "bogus", "nope"))  # bad status + auth, no notes
    )
    errors = fa._validate_coverage_structure(entries)
    assert any("status must be one of" in e for e in errors)
    assert any("authentication must be one of" in e for e in errors)


def test_excluded_requires_reason() -> None:
    entries = fa._parse_scope_coverage(_coverage(_target("x", "excluded", "not_applicable")))
    assert any("requires a reason" in e for e in fa._validate_coverage_structure(entries))


# ── finish_scan end-to-end ──────────────────────────────────────────────────


def test_blocks_when_approved_target_unaccounted(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(TWO_APP_SCAN_CONFIG))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("https://staging.wellreceived.com", "tested_with_findings", "both", "login")
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "incomplete_scope_coverage"
    assert "https://app.setmore.com" in result["message"]


def test_empty_scope_coverage_fails_validation(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(TWO_APP_SCAN_CONFIG))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage="",
        limitations="x",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert any("scope_coverage is required" in e for e in result["errors"])


def test_empty_limitations_fails_validation(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(TWO_APP_SCAN_CONFIG))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("https://staging.wellreceived.com", "tested_no_findings", "both", "x"),
            _target("https://app.setmore.com", "tested_no_findings", "both", "x"),
        ),
        limitations="   ",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert any("Limitations cannot be empty" in e for e in result["errors"])


def test_not_tested_soft_bounces_once_then_completes(monkeypatch) -> None:
    tracer = _FakeTracer(TWO_APP_SCAN_CONFIG, vuln_count=1)
    _install_tracer(monkeypatch, tracer)
    state = _root_state()
    coverage = _coverage(
        _target("https://staging.wellreceived.com", "tested_with_findings", "both", "login"),
        _target("https://app.setmore.com", "not_tested", "not_applicable", "ran out of time"),
    )
    kwargs = {
        "executive_summary": "s",
        "methodology": "Base methodology.",
        "technical_analysis": "t",
        "recommendations": "r",
        "scope_coverage": coverage,
        "limitations": "Controlled, low-volume validation.",
        "agent_state": state,
    }

    first = fa.finish_scan(**kwargs)
    assert first["success"] is False
    assert first["error"] == "targets_not_tested"
    assert "https://app.setmore.com" in first["message"]

    second = fa.finish_scan(**kwargs)
    assert second["success"] is True
    assert second["scan_completed"] is True


def test_success_folds_coverage_and_limitations_into_report(monkeypatch) -> None:
    tracer = _FakeTracer(TWO_APP_SCAN_CONFIG, vuln_count=2)
    _install_tracer(monkeypatch, tracer)
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Base methodology.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(
                "https://staging.wellreceived.com",
                "tested_with_findings",
                "both",
                "login, rbac, sessions",
            ),
            _target(
                "https://app.setmore.com",
                "tested_no_findings",
                "authenticated",
                "login, access controls",
            ),
        ),
        limitations="Validated in a controlled, low-volume manner.",
        agent_state=_root_state(),
    )
    assert result["success"] is True
    methodology = tracer.final_fields["methodology"]
    assert "Base methodology." in methodology
    assert "## Scope Coverage" in methodology
    assert "## Testing Limitations" in methodology
    assert "https://staging.wellreceived.com" in methodology
    assert "https://app.setmore.com" in methodology
    assert "controlled, low-volume" in methodology


def test_success_folds_actual_tools_used_into_report(monkeypatch) -> None:
    tracer = _FakeTracer(
        TWO_APP_SCAN_CONFIG,
        vuln_count=1,
        tools_used=["nmap", "sqlmap", "Intercepting HTTP proxy analysis"],
    )
    _install_tracer(monkeypatch, tracer)
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Base methodology.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("https://staging.wellreceived.com", "tested_with_findings", "both", "login"),
            _target("https://app.setmore.com", "tested_no_findings", "both", "login"),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True
    methodology = tracer.final_fields["methodology"]
    assert "## Tools and Techniques Used" in methodology
    assert "- nmap" in methodology
    assert "- sqlmap" in methodology
    assert "- Intercepting HTTP proxy analysis" in methodology


def test_no_tools_section_when_none_recorded(monkeypatch) -> None:
    tracer = _FakeTracer(TWO_APP_SCAN_CONFIG, vuln_count=1, tools_used=[])
    _install_tracer(monkeypatch, tracer)
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Base methodology.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("https://staging.wellreceived.com", "tested_no_findings", "both", "x"),
            _target("https://app.setmore.com", "tested_no_findings", "both", "x"),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True
    assert "## Tools and Techniques Used" not in tracer.final_fields["methodology"]


def test_subagent_cannot_call_finish_scan(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(TWO_APP_SCAN_CONFIG))
    sub_state = types.SimpleNamespace(parent_id="root-agent", agent_id="sub-1")
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("https://staging.wellreceived.com", "tested_no_findings", "both", "x")
        ),
        limitations="x",
        agent_state=sub_state,
    )
    assert result["success"] is False
    assert result["error"] == "finish_scan_wrong_agent"
