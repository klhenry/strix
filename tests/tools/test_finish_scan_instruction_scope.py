"""Tests for the finish_scan instruction-declared-scope and report-accuracy gates.

These gates close the failure mode where an operator names a second in-scope app
(or provides credentials) only in the free-text rules of engagement: the app was
silently dropped and the report could claim an unauthenticated black-box
engagement even though credentials were supplied.
"""

from __future__ import annotations

import types
from typing import Any

import pytest

from strix.tools.finish import finish_actions as fa


def _cfg(target_url: str, instruction: str) -> dict[str, Any]:
    return {
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": target_url},
                "original": target_url,
            }
        ],
        "user_instructions": instruction,
    }


def _web_cfg(target_urls: list[str], instruction: str) -> dict[str, Any]:
    return {
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": target_url},
                "original": target_url,
            }
            for target_url in target_urls
        ],
        "user_instructions": instruction,
    }


class _FakeTracer:
    def __init__(self, scan_config: dict[str, Any], vuln_count: int = 1) -> None:
        self.scan_config = scan_config
        self.vulnerability_reports = list(range(vuln_count))
        self.run_id = "test-run"
        self.final_fields: dict[str, str] | None = None

    def update_scan_final_fields(self, **kwargs: str) -> None:
        self.final_fields = kwargs

    def get_tools_used(self) -> list[str]:
        return []


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch):
    monkeypatch.setattr(fa, "_zero_findings_warned", set())
    monkeypatch.setattr(fa, "_incomplete_coverage_warned", set())
    monkeypatch.setattr(fa, "_finish_scan_attempts", {})
    from strix.tools.agents_graph import agents_graph_actions as ag

    monkeypatch.setattr(ag, "_agent_graph", {"nodes": {}, "edges": []})


def _install_tracer(monkeypatch, tracer: _FakeTracer) -> None:
    import strix.telemetry.tracer as tracer_mod

    monkeypatch.setattr(tracer_mod, "get_global_tracer", lambda: tracer)


def _root_state() -> Any:
    return types.SimpleNamespace(parent_id=None, agent_id="root-agent")


def _coverage(*entries: str) -> str:
    return "<coverage>" + "".join(entries) + "</coverage>"


def _target(asset: str, status: str, auth: str, notes: str = "") -> str:
    return (
        f"<target><asset>{asset}</asset><status>{status}</status>"
        f"<authentication>{auth}</authentication><notes>{notes}</notes></target>"
    )


def _finish(scope_coverage: str, **overrides: Any) -> dict[str, Any]:
    """Call finish_scan with a complete, valid report unless a test overrides it."""
    arguments: dict[str, Any] = {
        "executive_summary": "s",
        "methodology": "Application assessment.",
        "technical_analysis": "t",
        "recommendations": "r",
        "scope_coverage": scope_coverage,
        "limitations": "Controlled, low-volume validation.",
        "agent_state": _root_state(),
    }
    arguments.update(overrides)
    return fa.finish_scan(**arguments)


WR = "https://my.staging.wellreceived.app/"
# Names SetMore as in-scope only in the free text; no auth signal (isolates the
# instruction-declared gate from the authenticated-testing gate).
SETMORE_ROE = "Also test the SetMore staging app at https://go.staging.setmore.com/ per scope."
# Provides credentials / mandates authenticated testing, but names NO extra host.
AUTH_ROE = (
    "Use the provisioned admin audit account (jake+anywhere-admin@accountablehq.com) "
    "for authenticated testing of the application."
)


# ── Instruction-declared scope gate ─────────────────────────────────────────


def test_blocks_app_named_only_in_instructions(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, SETMORE_ROE)))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(_target(WR, "tested_with_findings", "unauthenticated", "recon")),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "instruction_declared_asset_unaccounted"
    assert "go.staging.setmore.com" in result["message"]


def test_completes_once_instruction_asset_accounted(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, SETMORE_ROE)))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(WR, "tested_with_findings", "unauthenticated", "recon"),
            _target(
                "https://go.staging.setmore.com/", "tested_no_findings", "unauthenticated", "recon"
            ),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True
    assert result["scan_completed"] is True


def test_instruction_only_not_tested_target_uses_untested_guard(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, SETMORE_ROE)))
    state = _root_state()
    kwargs = {
        "executive_summary": "s",
        "methodology": "m",
        "technical_analysis": "t",
        "recommendations": "r",
        "scope_coverage": _coverage(
            _target(WR, "tested_no_findings", "unauthenticated", "recon"),
            _target(
                "https://go.staging.setmore.com/",
                "not_tested",
                "not_applicable",
                "Application was unreachable during the testing window.",
            ),
        ),
        "limitations": "SetMore was unreachable during the testing window.",
        "agent_state": state,
    }

    first = fa.finish_scan(**kwargs)
    assert first["success"] is False
    assert first["error"] == "targets_not_tested"
    assert "go.staging.setmore.com" in first["message"]

    second = fa.finish_scan(**kwargs)
    assert second["success"] is True


def test_instruction_target_preserves_scheme_port_and_path(monkeypatch) -> None:
    declared = "http://api.example.test:8080/v1"
    scan_config = _cfg(WR, f"Also test {declared} as an in-scope target.")
    targets = fa._instruction_declared_targets(
        scan_config,
        fa._authorized_targets(scan_config),
    )
    assert targets == [("web_application", declared)]

    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(WR, "tested_no_findings", "unauthenticated", "recon"),
            _target(declared, "tested_no_findings", "unauthenticated", "API tested"),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True


def test_instruction_only_target_cannot_be_self_excluded(monkeypatch) -> None:
    declared = "https://api.example.test/v1"
    scan_config = _cfg(WR, f"Also test {declared} as an in-scope target.")
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(WR, "tested_no_findings", "unauthenticated", "recon"),
            _target(declared, "excluded", "not_applicable", "Agent chose to skip it."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "structured_target_excluded_without_instruction"


# ── Report-accuracy (authenticated testing) gate ────────────────────────────


def test_blocks_black_box_claim_when_credentials_provided(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, AUTH_ROE)))
    result = fa.finish_scan(
        executive_summary="External, unauthenticated black-box assessment.",
        methodology="No application credentials or source code were provided.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(_target(WR, "tested_with_findings", "unauthenticated", "recon")),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "report_contradicts_operator_auth"


def test_blocks_no_credentials_claim_in_limitations(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, AUTH_ROE)))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Authenticated application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(WR, "tested_no_findings", "both", "Login and authorization tested.")
        ),
        limitations="No application credentials were provided.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "report_contradicts_operator_auth"


def test_blocks_no_credentials_claim_in_coverage_notes(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, AUTH_ROE)))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Authenticated application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(WR, "tested_no_findings", "both", "No credentials were provided.")
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "report_contradicts_operator_auth"


def test_non_auth_row_note_cannot_claim_auth_target_had_no_credentials(
    monkeypatch,
) -> None:
    auth_app = "https://auth.example.test"
    public_app = "https://public.example.test"
    instruction = f"Use credentials for authenticated testing of {auth_app}."
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([auth_app, public_app], instruction)),
    )
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Authenticated application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(auth_app, "tested_no_findings", "both", "Login tested."),
            _target(
                public_app,
                "tested_no_findings",
                "unauthenticated",
                f"No credentials were provided for {auth_app}.",
            ),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["error"] == "report_contradicts_operator_auth"


def test_comma_separated_external_black_box_claim_is_blocked(monkeypatch) -> None:
    app = "https://auth.example.test"
    instruction = f"Use credentials for authenticated testing of {app}."
    _install_tracer(monkeypatch, _FakeTracer(_web_cfg([app], instruction)))
    result = fa.finish_scan(
        executive_summary="External, unauthenticated black-box assessment.",
        methodology="Authenticated application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(app, "tested_no_findings", "both", "Login tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["error"] == "report_contradicts_operator_auth"


def test_auth_blocker_never_waives_false_no_credentials_claim(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, AUTH_ROE)))
    result = fa.finish_scan(
        executive_summary="No application credentials were provided.",
        methodology="Assessment of the WellReceived staging application.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(
                WR,
                "tested_no_findings",
                "unauthenticated",
                "Authenticated login was blocked because the required OTP was unavailable.",
            )
        ),
        limitations="Authenticated login was blocked because the required OTP was unavailable.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "report_contradicts_operator_auth"


def test_allows_documented_otp_blocker(monkeypatch) -> None:
    # Auth was expected but genuinely blocked by OTP — documented, so it ships.
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, AUTH_ROE)))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Assessment of the WellReceived staging application.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(
                WR,
                "tested_with_findings",
                "unauthenticated",
                "Authenticated login blocked: OTP routed to an inbox outside tester control.",
            )
        ),
        limitations="Authenticated testing could not proceed because MFA/OTP was unavailable.",
        agent_state=_root_state(),
    )
    assert result["success"] is True
    assert result["scan_completed"] is True


def test_unchanged_missing_auth_coverage_remains_blocked(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, AUTH_ROE)))
    state = _root_state()
    kwargs = {
        "executive_summary": "s",
        "methodology": "Assessment of the WellReceived staging application.",
        "technical_analysis": "t",
        "recommendations": "r",
        "scope_coverage": _coverage(
            _target(WR, "tested_with_findings", "unauthenticated", "recon")
        ),
        "limitations": "Controlled, low-volume validation.",
        "agent_state": state,
    }

    first = fa.finish_scan(**kwargs)
    assert first["success"] is False
    assert first["error"] == "authenticated_coverage_missing"

    second = fa.finish_scan(**kwargs)
    assert second["success"] is False
    assert second["error"] == "authenticated_coverage_missing"


def test_blocker_must_be_in_target_note_and_limitations(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, AUTH_ROE)))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Assessment of the WellReceived staging application.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(WR, "tested_no_findings", "unauthenticated", "Public routes tested.")
        ),
        limitations="Authenticated login was blocked because the required OTP was unavailable.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"
    assert "scope_coverage <notes>" in result["message"]


def test_target_note_blocker_without_limitation_is_not_enough(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, AUTH_ROE)))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Assessment of the WellReceived staging application.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(
                WR,
                "tested_no_findings",
                "unauthenticated",
                "Authenticated login was blocked because the required OTP was unavailable.",
            )
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"
    assert "missing limitations" in result["message"]


def test_arbitrary_authenticated_row_is_rejected_as_unrecognized(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, AUTH_ROE)))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Assessment of the WellReceived staging application.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(WR, "tested_no_findings", "unauthenticated", "Public routes tested."),
            _target(
                "https://unrelated.example.test",
                "tested_no_findings",
                "authenticated",
                "Login tested.",
            ),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "unrecognized_scope_coverage_asset"
    assert "https://unrelated.example.test" in result["message"]


def test_each_recognized_app_requires_its_own_authenticated_coverage(monkeypatch) -> None:
    second_app = "https://go.staging.setmore.com/"
    scan_config = {
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": WR},
                "original": WR,
            },
            {
                "type": "web_application",
                "details": {"target_url": second_app},
                "original": second_app,
            },
        ],
        "user_instructions": AUTH_ROE,
    }
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(WR, "tested_no_findings", "both", "Login and authorization tested."),
            _target(second_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"
    assert second_app in result["message"]
    assert f"- {WR}:" not in result["message"]


def test_target_specific_auth_instruction_does_not_apply_to_other_app(monkeypatch) -> None:
    second_app = "https://go.staging.setmore.com/"
    scan_config = {
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": WR},
                "original": WR,
            },
            {
                "type": "web_application",
                "details": {"target_url": second_app},
                "original": second_app,
            },
        ],
        "user_instructions": (
            f"Use the provided credentials for authenticated testing of {WR}. "
            "The SetMore application remains an unauthenticated-only assessment."
        ),
    }
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Credentialed testing of WellReceived and public testing of SetMore.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(WR, "tested_no_findings", "both", "Login and authorization tested."),
            _target(second_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True


def test_generic_auth_clause_after_specific_clause_expands_to_every_app(monkeypatch) -> None:
    first_app = "https://one.example.test"
    second_app = "https://two.example.test"
    instruction = (
        f"Use the provided credentials for authenticated testing of {first_app}. "
        "Perform authenticated testing for all applications."
    )
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([first_app, second_app], instruction)),
    )
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(first_app, "tested_no_findings", "both", "Login tested."),
            _target(second_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"
    assert second_app in result["message"]


def test_terminal_period_does_not_hide_target_specific_auth_reference(monkeypatch) -> None:
    first_app = "https://one.example.test"
    second_app = "https://two.example.test"
    instruction = f"Use credentials for authenticated testing of {first_app}."
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([first_app, second_app], instruction)),
    )
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Credentialed testing of the first application.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(first_app, "tested_no_findings", "both", "Login tested."),
            _target(second_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True


@pytest.mark.parametrize(
    ("target_value", "text", "expected"),
    [
        (
            "https://one.example.test/api",
            "Use credentials for authenticated testing (https://one.example.test/api).",
            True,
        ),
        ("https://app.example.test", "app.example.test/", True),
        ("https://app.example.test/admin", "app.example.test/", False),
        ("https://app.example.test/admin", "app.example.test", True),
        (
            "https://app.example.test",
            "app.example.test: authentication was blocked because OTP was unavailable.",
            True,
        ),
    ],
    ids=[
        "bracket-punctuation",
        "scheme-less-explicit-root",
        "root-does-not-cover-child",
        "bare-host-covers-child",
        "target-label-colon",
    ],
)
def test_active_reference_matching_path(
    target_value: str,
    text: str,
    expected: bool,
) -> None:
    target = ("web_application", target_value)
    assert (target in fa._referenced_targets(text, [target])) is expected


def test_inline_negated_target_clause_removes_only_that_auth_requirement(monkeypatch) -> None:
    first_app = "https://one.example.test"
    second_app = "https://two.example.test"
    instruction = (
        f"Use credentials for authenticated testing of {first_app} but do not perform "
        f"authenticated testing on {second_app}."
    )
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([first_app, second_app], instruction)),
    )
    missing_auth = fa.finish_scan(
        executive_summary="s",
        methodology="Application testing.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(first_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
            _target(second_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert missing_auth["error"] == "authenticated_coverage_missing"

    result = fa.finish_scan(
        executive_summary="s",
        methodology="Credentialed testing of the first application.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(first_app, "tested_no_findings", "both", "Login tested."),
            _target(second_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True


def test_generic_auth_survives_inline_per_target_unauthenticated_only_clause(
    monkeypatch,
) -> None:
    first_app = "https://one.example.test"
    second_app = "https://two.example.test"
    instruction = (
        "Use the provided credentials for all applications but "
        f"{second_app} is unauthenticated-only."
    )
    scan_config = _web_cfg([first_app, second_app], instruction)
    required = fa._auth_requirement_targets(
        scan_config,
        fa._authorized_targets(scan_config),
    )
    assert required == [("web_application", first_app)]

    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(first_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
            _target(second_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"
    assert first_app in result["message"]
    assert f"- {second_app}:" not in result["message"]


def test_generic_auth_survives_target_specific_authentication_not_required(
    monkeypatch,
) -> None:
    first_app = "https://one.example.test"
    public_app = "https://public.example.test"
    instruction = (
        "Use the provided credentials for all applications. "
        f"Authentication is not required for {public_app}."
    )
    scan_config = _web_cfg([first_app, public_app], instruction)
    assert fa._auth_requirement_targets(
        scan_config,
        fa._authorized_targets(scan_config),
    ) == [("web_application", first_app)]

    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(first_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
            _target(public_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"
    assert first_app in result["message"]
    assert f"- {public_app}:" not in result["message"]


def test_inline_generic_auth_and_target_opt_out_keeps_other_targets_required(
    monkeypatch,
) -> None:
    private_app = "https://private.example.test"
    public_app = "https://public.example.test"
    instruction = (
        "Use credentials for authenticated testing of all applications and "
        f"authentication is not required for {public_app}."
    )
    scan_config = _web_cfg([private_app, public_app], instruction)
    assert fa._auth_requirement_targets(
        scan_config,
        fa._authorized_targets(scan_config),
    ) == [("web_application", private_app)]

    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(private_app, "tested_no_findings", "unauthenticated", "Public routes."),
            _target(public_app, "tested_no_findings", "unauthenticated", "Public routes."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["error"] == "authenticated_coverage_missing"
    assert private_app in result["message"]
    assert f"- {public_app}:" not in result["message"]


def test_with_clause_generic_auth_and_target_opt_out_keeps_other_targets_required() -> None:
    private_app = "https://private.example.test"
    public_app = "https://public.example.test"
    instruction = (
        "Use credentials for authenticated testing of all applications, with "
        f"{public_app} unauthenticated-only."
    )
    scan_config = _web_cfg([private_app, public_app], instruction)
    assert fa._split_auth_segments(instruction) == [
        "Use credentials for authenticated testing of all applications",
        f"with {public_app} unauthenticated-only.",
    ]
    assert fa._auth_requirement_targets(
        scan_config,
        fa._authorized_targets(scan_config),
    ) == [("web_application", private_app)]


@pytest.mark.parametrize(
    "prohibition",
    [
        "do not use the account for {target}",
        "don't use credentials for {target}",
        "don\u2019t use the credential for {target}",
        "do not use accounts for {target}",
        "never authenticate to {target}",
        "account use is prohibited for {target}",
        "do not use them for {target}",
        "don't use it on {target}",
        "the account for {target} must not be used",
        "For {target}, they must not be used",
        "credential use on {target} is prohibited",
    ],
)
def test_generic_auth_account_prohibitions_remove_only_named_target(
    prohibition: str,
) -> None:
    private_app = "https://private.example.test"
    public_app = "https://public.example.test"
    instruction = (
        "Use the provided credentials for all applications but "
        + prohibition.format(target=public_app)
        + "."
    )
    scan_config = _web_cfg([private_app, public_app], instruction)
    assert fa._auth_requirement_targets(
        scan_config,
        fa._authorized_targets(scan_config),
    ) == [("web_application", private_app)]


def test_nontarget_anaphora_restriction_does_not_cancel_generic_auth_mandate() -> None:
    first_app = "https://one.example.test"
    second_app = "https://two.example.test"
    instruction = (
        "Use the provided credentials for all applications, but do not use them "
        "for destructive testing."
    )
    scan_config = _web_cfg([first_app, second_app], instruction)
    assert fa._auth_requirement_targets(
        scan_config,
        fa._authorized_targets(scan_config),
    ) == [
        ("web_application", first_app),
        ("web_application", second_app),
    ]


@pytest.mark.parametrize(
    ("positive_targets", "selector", "required_target"),
    [
        (
            "https://one.example.test and https://two.example.test",
            "latter",
            "https://one.example.test",
        ),
        (
            "https://one.example.test and https://two.example.test",
            "former",
            "https://two.example.test",
        ),
        (
            "https://two.example.test and https://one.example.test",
            "latter",
            "https://two.example.test",
        ),
    ],
)
def test_former_and_latter_account_prohibitions_follow_textual_target_order(
    positive_targets: str,
    selector: str,
    required_target: str,
) -> None:
    first_app = "https://one.example.test"
    second_app = "https://two.example.test"
    instruction = (
        f"Use credentials for {positive_targets}. the {selector} account must not be used."
    )
    scan_config = _web_cfg([first_app, second_app], instruction)
    assert fa._auth_requirement_targets(
        scan_config,
        fa._authorized_targets(scan_config),
    ) == [("web_application", required_target)]


def test_qualified_latter_account_restriction_preserves_both_auth_targets() -> None:
    first_app = "https://one.example.test"
    second_app = "https://two.example.test"
    instruction = (
        f"Use credentials for {first_app} and {second_app}. "
        "The latter account must not be used for destructive testing."
    )
    scan_config = _web_cfg([first_app, second_app], instruction)
    assert fa._auth_requirement_targets(
        scan_config,
        fa._authorized_targets(scan_config),
    ) == [
        ("web_application", first_app),
        ("web_application", second_app),
    ]


def test_account_prohibition_allows_named_target_to_remain_unauthenticated(
    monkeypatch,
) -> None:
    private_app = "https://private.example.test"
    public_app = "https://public.example.test"
    instruction = (
        "Use the provided credentials for all applications, but do not use the account for "
        f"{public_app}."
    )
    scan_config = _web_cfg([private_app, public_app], instruction)
    _install_tracer(monkeypatch, _FakeTracer(scan_config))

    result = fa.finish_scan(
        executive_summary="s",
        methodology="Authenticated and public application testing.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(private_app, "tested_no_findings", "both", "Login tested."),
            _target(public_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True


@pytest.mark.parametrize("vendor", ["vendor.test", "https://vendor.test"])
def test_auth_clause_naming_only_unrecognized_vendor_is_not_generic(vendor: str) -> None:
    app = "https://app.example.test"
    instruction = f"Use credentials for authenticated testing at {vendor}."
    scan_config = _web_cfg([app], instruction)
    assert (
        fa._auth_requirement_targets(
            scan_config,
            fa._authorized_targets(scan_config),
        )
        == []
    )


def test_auth_clause_naming_only_excluded_vendor_is_not_generic() -> None:
    app = "https://app.example.test"
    vendor = "https://vendor.test"
    instruction = f"Use credentials for authenticated testing at {vendor}. Do not test {vendor}."
    scan_config = _web_cfg([app, vendor], instruction)
    assert (
        fa._auth_requirement_targets(
            scan_config,
            fa._authorized_targets(scan_config),
        )
        == []
    )


@pytest.mark.parametrize(
    "positive_clause",
    [
        "Use credentials for authenticated testing of vendor.test.",
        "Test vendor.test with credentials.",
        "Authenticate vendor.test.",
        "Authenticate via vendor.test.",
        "Use credentials for authenticated testing through vendor.test.",
    ],
)
def test_bare_foreign_targeted_auth_clause_does_not_retarget_recognized_apps(
    positive_clause: str,
) -> None:
    first_app = "https://one.example.test"
    second_app = "https://two.example.test"
    instruction = f"{positive_clause} Do not test vendor.test."
    scan_config = _web_cfg([first_app, second_app], instruction)
    assert (
        fa._auth_requirement_targets(
            scan_config,
            fa._authorized_targets(scan_config),
        )
        == []
    )


def test_dotted_password_does_not_turn_generic_auth_clause_into_targeted_clause() -> None:
    first_app = "https://one.example.test"
    second_app = "https://two.example.test"
    instruction = "Use username admin and password alpha.beta for authenticated testing."
    scan_config = _web_cfg([first_app, second_app], instruction)
    assert fa._auth_requirement_targets(
        scan_config,
        fa._authorized_targets(scan_config),
    ) == [
        ("web_application", first_app),
        ("web_application", second_app),
    ]


def test_conjoined_positive_auth_targets_both_remain_required(monkeypatch) -> None:
    first_app = "https://one.example.test"
    second_app = "https://two.example.test"
    instruction = f"Use credentials for authenticated testing of {first_app} and {second_app}."
    scan_config = _web_cfg([first_app, second_app], instruction)
    assert fa._auth_requirement_targets(
        scan_config,
        fa._authorized_targets(scan_config),
    ) == [
        ("web_application", first_app),
        ("web_application", second_app),
    ]

    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(first_app, "tested_no_findings", "both", "Login tested."),
            _target(second_app, "tested_no_findings", "unauthenticated", "Public routes."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["error"] == "authenticated_coverage_missing"
    assert second_app in result["message"]


def test_credential_email_domain_cannot_narrow_generic_auth_mandate(monkeypatch) -> None:
    first_app = "https://one.example.test"
    second_app = "https://two.example.test"
    instruction = (
        "Use tester@one.example.test and the supplied password for authenticated "
        "testing of all applications."
    )
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([first_app, second_app], instruction)),
    )
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(first_app, "tested_no_findings", "both", "Login tested."),
            _target(second_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"
    assert second_app in result["message"]


def test_generic_web_credentials_do_not_apply_to_standalone_ip_target(monkeypatch) -> None:
    web_app = "https://app.example.test"
    ip_target = "192.0.2.25"
    scan_config = {
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": web_app},
                "original": web_app,
            },
            {
                "type": "ip_address",
                "details": {"target_ip": ip_target},
                "original": ip_target,
            },
        ],
        "user_instructions": "Use the provided credentials for the web application.",
    }
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application and network assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(web_app, "tested_no_findings", "both", "Login tested."),
            _target(ip_target, "tested_no_findings", "not_applicable", "Network services tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True


def test_all_target_auth_mandate_includes_standalone_ip(monkeypatch) -> None:
    web_app = "https://app.example.test"
    ip_target = "192.0.2.25"
    scan_config = {
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": web_app},
                "original": web_app,
            },
            {
                "type": "ip_address",
                "details": {"target_ip": ip_target},
                "original": ip_target,
            },
        ],
        "user_instructions": "Use the provided credentials for all in-scope targets.",
    }
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application and network assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(web_app, "tested_no_findings", "both", "Login tested."),
            _target(ip_target, "tested_no_findings", "not_applicable", "Network services tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"
    assert ip_target in result["message"]
    assert "authorized for use" in result["message"]


def test_all_applications_and_ip_addresses_auth_mandate_includes_ip() -> None:
    web_app = "https://app.example.test"
    ip_target = "192.0.2.25"
    scan_config = {
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": web_app},
                "original": web_app,
            },
            {
                "type": "ip_address",
                "details": {"target_ip": ip_target},
                "original": ip_target,
            },
        ],
        "user_instructions": (
            "Use the provided credentials for all applications and IP addresses."
        ),
    }
    assert fa._auth_requirement_targets(
        scan_config,
        fa._authorized_targets(scan_config),
    ) == [
        ("web_application", web_app),
        ("ip_address", ip_target),
    ]


def test_explicit_ip_auth_requirement_is_enforced(monkeypatch) -> None:
    web_app = "https://app.example.test"
    ip_target = "192.0.2.25"
    scan_config = {
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": web_app},
                "original": web_app,
            },
            {
                "type": "ip_address",
                "details": {"target_ip": ip_target},
                "original": ip_target,
            },
        ],
        "user_instructions": f"Perform authenticated testing of {ip_target}.",
    }
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application and network assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(web_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
            _target(ip_target, "tested_no_findings", "not_applicable", "Network services tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"
    assert ip_target in result["message"]


def test_same_host_paths_require_independent_authenticated_coverage(monkeypatch) -> None:
    base_app = "https://app.example.test"
    api_app = "https://app.example.test/api"
    instruction = "Use the provided credentials for authenticated testing of all applications."
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([base_app, api_app], instruction)),
    )
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(base_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
            _target(api_app, "tested_no_findings", "both", "Authenticated API tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"
    assert base_app in result["message"]
    assert f"- {api_app}:" not in result["message"]


def test_explicit_root_auth_reference_does_not_expand_to_same_host_path(monkeypatch) -> None:
    base_app = "https://app.example.test"
    api_app = "https://app.example.test/api"
    instruction = f"Use credentials for authenticated testing of {base_app}."
    scan_config = _web_cfg([base_app, api_app], instruction)
    assert fa._auth_requirement_targets(
        scan_config,
        fa._authorized_targets(scan_config),
    ) == [("web_application", base_app)]

    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(base_app, "tested_no_findings", "both", "Login tested."),
            _target(api_app, "tested_no_findings", "unauthenticated", "Public API tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True


def test_vague_login_failure_is_not_a_causal_auth_blocker(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, AUTH_ROE)))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(WR, "tested_no_findings", "unauthenticated", "Login failed.")
        ),
        limitations="Login failed.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"


def test_blocker_for_one_app_cannot_exempt_another_app(monkeypatch) -> None:
    first_app = "https://one.example.test"
    second_app = "https://two.example.test"
    instruction = "Use the provided credentials for authenticated testing of all applications."
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([first_app, second_app], instruction)),
    )
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(
                first_app,
                "tested_no_findings",
                "unauthenticated",
                f"Authenticated login to {first_app} was blocked because OTP was unavailable.",
            ),
            _target(
                second_app,
                "tested_no_findings",
                "unauthenticated",
                f"Authenticated login to {first_app} was blocked because OTP was unavailable.",
            ),
        ),
        limitations=(
            f"Authenticated login to {first_app} was blocked because OTP was unavailable; "
            f"only public routes on {second_app} were tested."
        ),
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"
    assert second_app in result["message"]
    assert f"- {first_app}:" not in result["message"]


def test_blocker_explicitly_attributed_to_unrecognized_host_is_rejected(monkeypatch) -> None:
    app = "https://auth.example.test"
    unrelated_blocker = (
        "Authenticated login to https://unrelated.example.test was blocked because "
        "OTP was unavailable."
    )
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([app], "Use provided credentials for authenticated testing.")),
    )
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(app, "tested_no_findings", "unauthenticated", unrelated_blocker)
        ),
        limitations=unrelated_blocker,
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"


def test_foreign_blocker_with_incidental_comparative_target_mention_is_rejected(
    monkeypatch,
) -> None:
    app = "https://auth.example.test"
    misleading_blocker = (
        "OTP was unavailable for https://unrelated.example.test, preventing "
        f"authentication, unlike {app}."
    )
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([app], "Use provided credentials for authenticated testing.")),
    )
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(app, "tested_no_findings", "unauthenticated", misleading_blocker)
        ),
        limitations=misleading_blocker,
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"


def test_target_attributed_blocker_may_name_external_identity_provider(
    monkeypatch,
) -> None:
    app = "https://auth.example.test"
    blocker = (
        f"{app}: authentication was blocked because the identity provider was "
        "unavailable at https://idp.vendor.test."
    )
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([app], "Use provided credentials for authenticated testing.")),
    )
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(_target(app, "tested_no_findings", "unauthenticated", blocker)),
        limitations=blocker,
        agent_state=_root_state(),
    )
    assert result["success"] is True


def test_same_host_blocker_requires_exact_path_attribution(monkeypatch) -> None:
    base_app = "https://app.example.test"
    api_app = "https://app.example.test/api"
    instruction = f"Use the provided credentials for authenticated testing of {api_app}."
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([base_app, api_app], instruction)),
    )
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(base_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
            _target(
                api_app,
                "tested_no_findings",
                "unauthenticated",
                "Authenticated login was blocked because OTP was unavailable.",
            ),
        ),
        limitations=(
            "Authenticated login to app.example.test was blocked because OTP was unavailable."
        ),
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "authenticated_coverage_missing"
    assert "missing limitations" in result["message"]


def test_same_host_blocker_accepts_exact_path_attribution(monkeypatch) -> None:
    base_app = "https://app.example.test"
    api_app = "https://app.example.test/api"
    instruction = f"Use the provided credentials for authenticated testing of {api_app}."
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([base_app, api_app], instruction)),
    )
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(base_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
            _target(
                api_app,
                "tested_no_findings",
                "unauthenticated",
                "Authenticated login was blocked because OTP was unavailable.",
            ),
        ),
        limitations=(f"Authenticated login to {api_app} was blocked because OTP was unavailable."),
        agent_state=_root_state(),
    )
    assert result["success"] is True


@pytest.mark.parametrize(
    ("limitations_template", "expected_success"),
    [
        (
            "Authenticated login to {first} was blocked because OTP was unavailable and "
            "authenticated login to {second} was blocked because OTP was unavailable.",
            True,
        ),
        (
            "OTP was unavailable for {first} and {second}, preventing authentication to both.",
            True,
        ),
        (
            "Both {first} and {second} were assessed, although OTP was unavailable "
            "only for {first}.",
            False,
        ),
        (
            "OTP was unavailable for {first} and {second}, preventing authentication.",
            True,
        ),
        (
            "Only OTP was unavailable for {first} and {second}, preventing authentication.",
            True,
        ),
        (
            "OTP was unavailable for {first} and {second}, but it only prevented "
            "authentication to {first}.",
            False,
        ),
        (
            "Both {first} and {second} were blocked from authentication because "
            "OTP was unavailable.",
            True,
        ),
    ],
    ids=[
        "independent-blockers",
        "shared-explicit-both",
        "cause-limited-to-first",
        "shared-conjoined-list",
        "only-limits-factor",
        "later-effect-limited-to-first",
        "shared-subject",
    ],
)
def test_multi_target_blocker_attribution_variants(
    monkeypatch,
    limitations_template: str,
    expected_success: bool,
) -> None:
    first_app = "https://one.example.test"
    second_app = "https://two.example.test"
    instruction = "Use provided credentials for authenticated testing of all applications."
    note = "Authenticated login was blocked because OTP was unavailable."
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([first_app, second_app], instruction)),
    )
    result = _finish(
        _coverage(
            _target(first_app, "tested_no_findings", "unauthenticated", note),
            _target(second_app, "tested_no_findings", "unauthenticated", note),
        ),
        limitations=limitations_template.format(first=first_app, second=second_app),
    )
    assert result["success"] is expected_success
    if not expected_success:
        assert result["error"] == "authenticated_coverage_missing"
        assert second_app in result["message"]
        assert f"- {first_app}:" not in result["message"]


def test_black_box_wording_for_non_auth_target_is_not_a_contradiction(monkeypatch) -> None:
    auth_app = "https://auth.example.test"
    public_app = "https://public.example.test"
    instruction = f"Use credentials for authenticated testing of {auth_app}."
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([auth_app, public_app], instruction)),
    )
    result = fa.finish_scan(
        executive_summary="s",
        methodology=(
            f"Authenticated testing covered {auth_app}. {public_app} received an "
            "unauthenticated black-box assessment."
        ),
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(auth_app, "tested_no_findings", "both", "Login tested."),
            _target(public_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True


@pytest.mark.parametrize(
    ("report_field", "report_text", "expected_success"),
    [
        (
            "methodology",
            "Unauthenticated black-box testing was followed by authenticated testing.",
            True,
        ),
        (
            "executive_summary",
            "No credentials were provided during an assessment where unauthenticated "
            "testing was followed by authenticated testing.",
            False,
        ),
        (
            "executive_summary",
            "No application credentials were provided in the authenticated phase, "
            "followed by an unauthenticated phase.",
            False,
        ),
        (
            "executive_summary",
            "The authenticated phase had no application credentials, followed by "
            "an unauthenticated phase.",
            False,
        ),
        (
            "methodology",
            "No application credentials were provided during the initial "
            "unauthenticated phase, followed by authenticated testing.",
            True,
        ),
    ],
    ids=[
        "explicit-mixed-phases",
        "generic-no-credentials",
        "no-credentials-in-authenticated-phase",
        "authenticated-phase-had-no-credentials",
        "no-credentials-in-unauthenticated-phase",
    ],
)
def test_mixed_phase_report_wording(
    monkeypatch,
    report_field: str,
    report_text: str,
    expected_success: bool,
) -> None:
    app = "https://auth.example.test"
    instruction = f"Use credentials for authenticated testing of {app}."
    _install_tracer(monkeypatch, _FakeTracer(_web_cfg([app], instruction)))
    result = _finish(
        _coverage(
            _target(app, "tested_no_findings", "both", "Login and both phases tested."),
        ),
        **{report_field: report_text},
    )
    assert result["success"] is expected_success
    if not expected_success:
        assert result["error"] == "report_contradicts_operator_auth"
        assert "authorized for use" in result["message"]


def test_while_joined_public_and_authenticated_target_clauses_are_attributed(
    monkeypatch,
) -> None:
    auth_app = "https://auth.example.test"
    public_app = "https://public.example.test"
    instruction = f"Use credentials for authenticated testing of {auth_app}."
    _install_tracer(
        monkeypatch,
        _FakeTracer(_web_cfg([auth_app, public_app], instruction)),
    )
    result = fa.finish_scan(
        executive_summary="s",
        methodology=(
            f"{public_app} received an unauthenticated black-box assessment while "
            f"{auth_app} received authenticated testing."
        ),
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(auth_app, "tested_no_findings", "both", "Login tested."),
            _target(public_app, "tested_no_findings", "unauthenticated", "Public routes tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True


def test_instruction_declared_ip_is_typed_as_ip_address() -> None:
    scan_config = _cfg(WR, "Also test 192.0.2.25 as an in-scope target.")
    targets = fa._instruction_declared_targets(scan_config, fa._authorized_targets(scan_config))
    assert targets == [("ip_address", "192.0.2.25")]


def test_instruction_declared_ipv6_url_is_typed_as_web_application() -> None:
    target = "https://[2001:db8::25]/app"
    scan_config = _cfg(WR, f"Also test {target} as an in-scope application.")
    targets = fa._instruction_declared_targets(
        scan_config,
        fa._authorized_targets(scan_config),
    )
    assert targets == [("web_application", target)]


def test_zero_tested_auth_scan_cannot_pass_on_retry_without_blockers(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, AUTH_ROE)))
    state = _root_state()
    kwargs = {
        "executive_summary": "s",
        "methodology": "Assessment of the WellReceived staging application.",
        "technical_analysis": "t",
        "recommendations": "r",
        "scope_coverage": _coverage(
            _target(WR, "not_tested", "not_applicable", "Testing window expired.")
        ),
        "limitations": "The testing window expired before validation.",
        "agent_state": state,
    }

    first = fa.finish_scan(**kwargs)
    assert first["success"] is False
    assert first["error"] == "targets_not_tested"

    second = fa.finish_scan(**kwargs)
    assert second["success"] is False
    assert second["error"] == "authenticated_coverage_missing"


def test_authenticated_coverage_passes_gate(monkeypatch) -> None:
    # Credentials provided AND authenticated testing recorded -> no gate fires.
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, AUTH_ROE)))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Authenticated and unauthenticated testing of WellReceived staging.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(WR, "tested_with_findings", "both", "login, RBAC, session, IDOR")
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True
    assert result["scan_completed"] is True


def test_auth_required_target_not_tested_for_non_auth_reason_can_finish(monkeypatch) -> None:
    # An auth-required target the agent could not reach at all (status
    # not_tested, forced authentication=not_applicable) must not be trapped
    # behind the auth-coverage gate demanding auth-specific blocker wording.
    # The one-time not_tested soft guard bounces once; the retry then completes.
    _install_tracer(monkeypatch, _FakeTracer(_cfg(WR, AUTH_ROE)))
    state = _root_state()
    kwargs = {
        "executive_summary": "s",
        "methodology": "Assessment of the WellReceived staging application.",
        "technical_analysis": "t",
        "recommendations": "r",
        "scope_coverage": _coverage(
            _target(
                WR,
                "not_tested",
                "not_applicable",
                "Host was unreachable throughout the engagement; DNS did not resolve.",
            )
        ),
        "limitations": "WellReceived staging was unreachable during the testing window.",
        "agent_state": state,
    }

    first = fa.finish_scan(**kwargs)
    assert first["success"] is False
    assert first["error"] == "targets_not_tested"

    second = fa.finish_scan(**kwargs)
    assert second["success"] is True
    assert second["scan_completed"] is True
