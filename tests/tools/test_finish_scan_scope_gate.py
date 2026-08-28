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


def test_repository_host_does_not_cover_instruction_declared_web_target() -> None:
    cfg = {
        "user_instructions": "Also test https://api.github.com as an in-scope web app.",
        "targets": [
            {"type": "repository", "details": {"target_repo": "https://github.com/a/b"}},
        ],
    }
    authorized = fa._authorized_targets(cfg)
    assert fa._instruction_declared_targets(cfg, authorized) == [
        ("web_application", "https://api.github.com/")
    ]


def test_repeated_repository_url_is_not_added_as_instruction_web_target(monkeypatch) -> None:
    repository = "https://github.com/Customer/Repo"
    cfg = {
        "user_instructions": f"Test the approved repository at {repository}.",
        "targets": [
            {"type": "repository", "details": {"target_repo": repository}},
        ],
    }
    authorized = fa._authorized_targets(cfg)
    assert fa._instruction_declared_targets(cfg, authorized) == []

    _install_tracer(monkeypatch, _FakeTracer(cfg))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Repository assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(repository, "tested_no_findings", "not_applicable", "Code reviewed.")
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True


def test_asset_matches_requires_exact_scheme_and_canonicalizes_slash() -> None:
    assert fa._asset_matches("https://app.setmore.com", "https://app.setmore.com/")
    assert not fa._asset_matches("https://app.setmore.com", "app.setmore.com/")
    assert not fa._asset_matches("https://app.setmore.com", "http://app.setmore.com/")
    assert not fa._asset_matches("https://app.setmore.com/", "www.app.setmore.com")
    assert not fa._asset_matches("https://app.setmore.com/", "http://www.app.setmore.com")
    assert not fa._asset_matches("https://a.com", "https://b.com")


def test_asset_matches_requires_exact_host_not_merely_dns_relation() -> None:
    assert not fa._asset_matches("https://customer.com", "https://app.customer.com")
    assert not fa._asset_matches("https://app.customer.com", "https://notapp.customer.com")
    assert not fa._asset_matches("https://app.customer.com", "https://app.customer.com.evil.test")


def test_asset_matches_rejects_different_explicit_ports() -> None:
    assert not fa._asset_matches("https://app.customer.com:8443", "https://app.customer.com:9443")
    assert not fa._asset_matches("https://app.customer.com:8443", "https://app.customer.com")


def test_asset_matches_canonicalizes_equivalent_default_ports() -> None:
    assert fa._asset_matches("https://app.customer.com", "https://app.customer.com:443")
    assert fa._asset_matches("http://app.customer.com", "http://app.customer.com:80")
    assert not fa._asset_matches("https://app.customer.com:80", "https://app.customer.com")


def test_asset_matches_preserves_scheme_less_explicit_ports() -> None:
    assert not fa._asset_matches("app.customer.com", "app.customer.com:443")
    assert not fa._asset_matches("app.customer.com:443", "app.customer.com")


def test_asset_matches_distinguishes_materially_different_paths() -> None:
    assert fa._asset_matches("https://app.customer.com/api/", "https://app.customer.com/api")
    assert not fa._asset_matches("https://app.customer.com", "https://app.customer.com/api")
    assert not fa._asset_matches("https://app.customer.com/api", "https://app.customer.com/admin")


def test_asset_matches_canonicalizes_ipv6() -> None:
    assert fa._asset_matches("2001:0db8:0:0:0:0:0:1", "[2001:db8::1]", "ip_address")


def test_bare_ip_and_explicit_ip_url_are_distinct_coverage_identities() -> None:
    assert fa._asset_matches("10.0.0.1", "10.0.0.1", "ip_address")
    assert not fa._asset_matches("10.0.0.1", "https://10.0.0.1/", "ip_address")
    assert not fa._asset_matches("https://10.0.0.1/", "10.0.0.1", "web_application")
    assert fa._asset_matches(
        "https://[2001:db8::1]/",
        "https://[2001:0db8:0:0:0:0:0:1]/",
        "web_application",
    )
    assert not fa._asset_matches(
        "https://[2001:db8::1]/",
        "[2001:db8::1]",
        "web_application",
    )


def test_repository_asset_matching_requires_exact_repository() -> None:
    assert fa._asset_matches(
        "https://github.com/customer/api",
        "https://github.com/customer/api/",
        "repository",
    )
    assert not fa._asset_matches(
        "https://github.com/customer/api",
        "github.com/customer/api",
        "repository",
    )
    assert not fa._asset_matches(
        "https://github.com/customer/api",
        "http://github.com/customer/api",
        "repository",
    )
    assert not fa._asset_matches(
        "https://github.com/customer/api",
        "https://github.com/customer/web",
        "repository",
    )
    assert not fa._asset_matches(
        "https://github.com/Customer/API",
        "https://github.com/customer/api",
        "repository",
    )


def test_local_code_asset_matching_is_case_sensitive() -> None:
    assert fa._asset_matches("/Workspace/App/", "/Workspace/App", "local_code")
    assert not fa._asset_matches("/Workspace/App", "/workspace/app", "local_code")


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


def test_uncovered_status_requires_not_applicable_authentication() -> None:
    entries = fa._parse_scope_coverage(
        _coverage(_target("https://app.example.test", "not_tested", "both", "Unreachable."))
    )
    errors = fa._validate_coverage_structure(entries)
    assert any("requires authentication 'not_applicable'" in error for error in errors)


@pytest.mark.parametrize(
    ("xml", "message"),
    [
        ("<coverage><target></coverage>", "well-formed XML"),
        (
            '<!DOCTYPE coverage [<!ENTITY leaked "secret">]><coverage>&leaked;</coverage>',
            "safe, well-formed XML",
        ),
        ("<scope_coverage />", "root element must be <coverage>"),
        (
            "<coverage><target><asset>x</asset><status>tested_no_findings</status>"
            "<authentication>not_applicable</authentication></target></coverage>",
            "missing required field",
        ),
        (
            "<coverage><target><asset>x</asset><asset>y</asset>"
            "<status>tested_no_findings</status><authentication>not_applicable</authentication>"
            "<notes>n</notes></target></coverage>",
            "duplicate <asset>",
        ),
        (
            "<coverage><target><asset>x</asset><status>tested_no_findings</status>"
            "<authentication>not_applicable</authentication><notes>n</notes>"
            "<extra>no</extra></target></coverage>",
            "unexpected <extra>",
        ),
    ],
)
def test_parse_scope_coverage_rejects_malformed_or_non_contract_xml(
    xml: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        fa._parse_scope_coverage(xml)


def test_parse_scope_coverage_decodes_escaped_text() -> None:
    entries = fa._parse_scope_coverage(
        "<coverage><target><asset>https://app.example.test/?a=1&amp;b=2</asset>"
        "<status>tested_no_findings</status><authentication>unauthenticated</authentication>"
        "<notes>Routes &amp; parameters tested.</notes></target></coverage>"
    )
    assert entries == [
        {
            "asset": "https://app.example.test/?a=1&b=2",
            "status": "tested_no_findings",
            "authentication": "unauthenticated",
            "notes": "Routes & parameters tested.",
        }
    ]


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


def test_one_row_cannot_cover_two_same_host_path_targets(monkeypatch) -> None:
    scan_config = {
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": "https://app.example.test"},
                "original": "https://app.example.test",
            },
            {
                "type": "web_application",
                "details": {"target_url": "https://app.example.test/api/v1"},
                "original": "https://app.example.test/api/v1",
            },
        ]
    }
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("https://app.example.test", "tested_no_findings", "unauthenticated", "x")
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "incomplete_scope_coverage"
    assert "https://app.example.test/api/v1" in result["message"]


def test_explicit_url_target_rejects_scheme_less_coverage_row(monkeypatch) -> None:
    target = "https://app.example.test/api"
    scan_config = {
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": target},
                "original": target,
            },
        ]
    }
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("app.example.test/api", "tested_no_findings", "unauthenticated", "x")
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["error"] == "incomplete_scope_coverage"
    assert target in result["message"]


def test_rejects_unrecognized_coverage_row_before_rendering(monkeypatch) -> None:
    tracer = _FakeTracer(TWO_APP_SCAN_CONFIG)
    _install_tracer(monkeypatch, tracer)
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("https://staging.wellreceived.com", "tested_no_findings", "both", "x"),
            _target("https://app.setmore.com", "tested_no_findings", "both", "x"),
            _target("https://payments.vendor.test", "tested_no_findings", "both", "x"),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "unrecognized_scope_coverage_asset"
    assert tracer.final_fields is None


def test_rejects_coverage_row_ambiguous_between_distinct_targets(monkeypatch) -> None:
    shared_url = "https://github.example.test/Customer/Repo"
    scan_config = {
        "targets": [
            {
                "type": "repository",
                "details": {"target_repo": shared_url},
                "original": shared_url,
            },
            {
                "type": "web_application",
                "details": {"target_url": shared_url},
                "original": shared_url,
            },
        ]
    }
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(_target(shared_url, "tested_no_findings", "unauthenticated", "x")),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "ambiguous_scope_coverage_asset"


def test_rejects_duplicate_rows_for_one_recognized_target(monkeypatch) -> None:
    tracer = _FakeTracer(TWO_APP_SCAN_CONFIG)
    _install_tracer(monkeypatch, tracer)
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("https://staging.wellreceived.com", "tested_no_findings", "both", "x"),
            _target(
                "https://staging.wellreceived.com/",
                "tested_no_findings",
                "both",
                "duplicate",
            ),
            _target("https://app.setmore.com", "tested_no_findings", "both", "x"),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "duplicate_scope_coverage_target"
    assert tracer.final_fields is None


def test_equivalent_default_port_targets_share_one_coverage_identity(monkeypatch) -> None:
    scan_config = {
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": "https://app.example.test"},
                "original": "https://app.example.test",
            },
            {
                "type": "web_application",
                "details": {"target_url": "https://app.example.test:443/"},
                "original": "https://app.example.test:443/",
            },
        ]
    }
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("https://app.example.test", "tested_no_findings", "unauthenticated", "x")
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True


@pytest.mark.parametrize(
    ("bare_ip", "web_url"),
    [
        ("10.0.0.1", "https://10.0.0.1/"),
        ("2001:db8::1", "https://[2001:db8::1]/"),
    ],
)
def test_bare_ip_and_instruction_ip_url_can_be_reported_separately(
    monkeypatch,
    bare_ip: str,
    web_url: str,
) -> None:
    scan_config = {
        "targets": [
            {
                "type": "ip_address",
                "details": {"target_ip": bare_ip},
                "original": bare_ip,
            },
        ],
        "user_instructions": f"Also test {web_url} as a web application.",
    }
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="Network and application assessment.",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target(bare_ip, "tested_no_findings", "not_applicable", "Services tested."),
            _target(web_url, "tested_no_findings", "unauthenticated", "Web routes tested."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is True


def test_www_and_repeated_slash_targets_remain_distinct() -> None:
    targets = [
        ("web_application", "https://app.example.test/api/v1"),
        ("web_application", "https://www.app.example.test/api/v1"),
        ("web_application", "https://app.example.test/api//v1"),
    ]
    assert fa._dedupe_targets(targets) == targets


def test_structured_target_cannot_be_self_excluded(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(TWO_APP_SCAN_CONFIG))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("https://staging.wellreceived.com", "tested_no_findings", "both", "x"),
            _target("https://app.setmore.com", "excluded", "not_applicable", "Skipped."),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "structured_target_excluded_without_instruction"


def test_structured_target_can_reflect_explicit_operator_exclusion(monkeypatch) -> None:
    scan_config = {
        **TWO_APP_SCAN_CONFIG,
        "user_instructions": "Do not test https://app.setmore.com; it is explicitly excluded.",
    }
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("https://staging.wellreceived.com", "tested_no_findings", "both", "x"),
            _target(
                "https://app.setmore.com",
                "excluded",
                "not_applicable",
                "Explicitly excluded by the operator.",
            ),
        ),
        limitations="SetMore was explicitly excluded by the operator.",
        agent_state=_root_state(),
    )
    assert result["success"] is True


def test_explicit_exclusion_requires_note_to_state_operator_basis(monkeypatch) -> None:
    scan_config = {
        **TWO_APP_SCAN_CONFIG,
        "user_instructions": "Do not test https://app.setmore.com; it is explicitly excluded.",
    }
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("https://staging.wellreceived.com", "tested_no_findings", "both", "x"),
            _target("https://app.setmore.com", "excluded", "not_applicable", "Skipped."),
        ),
        limitations="SetMore was explicitly excluded by the operator.",
        agent_state=_root_state(),
    )
    assert result["error"] == "excluded_target_note_missing_operator_basis"


def test_explicitly_excluded_structured_target_must_use_excluded_status(
    monkeypatch,
) -> None:
    scan_config = {
        **TWO_APP_SCAN_CONFIG,
        "user_instructions": "Do not test https://app.setmore.com; it is explicitly excluded.",
    }
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("https://staging.wellreceived.com", "tested_no_findings", "both", "x"),
            _target(
                "https://app.setmore.com",
                "not_tested",
                "not_applicable",
                "Operator excluded this target from scope.",
            ),
        ),
        limitations="SetMore was explicitly excluded by the operator.",
        agent_state=_root_state(),
    )
    assert result["error"] == "excluded_target_not_marked_excluded"


def test_explicitly_excluded_structured_target_cannot_be_reported_as_tested(
    monkeypatch,
) -> None:
    scan_config = {
        **TWO_APP_SCAN_CONFIG,
        "user_instructions": "Do not test https://app.setmore.com; it is explicitly excluded.",
    }
    _install_tracer(monkeypatch, _FakeTracer(scan_config))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage=_coverage(
            _target("https://staging.wellreceived.com", "tested_no_findings", "both", "x"),
            _target("https://app.setmore.com", "tested_no_findings", "unauthenticated", "x"),
        ),
        limitations="Controlled, low-volume validation.",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert result["error"] == "excluded_target_reported_as_tested"


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


def test_malformed_scope_coverage_fails_validation(monkeypatch) -> None:
    _install_tracer(monkeypatch, _FakeTracer(TWO_APP_SCAN_CONFIG))
    result = fa.finish_scan(
        executive_summary="s",
        methodology="m",
        technical_analysis="t",
        recommendations="r",
        scope_coverage="<coverage><target></coverage>",
        limitations="x",
        agent_state=_root_state(),
    )
    assert result["success"] is False
    assert any("well-formed XML" in error for error in result["errors"])


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


def test_not_tested_warning_state_is_isolated_per_scan_run(monkeypatch) -> None:
    state = _root_state()
    coverage = _coverage(
        _target("https://staging.wellreceived.com", "tested_with_findings", "both", "login"),
        _target("https://app.setmore.com", "not_tested", "not_applicable", "unreachable"),
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

    first_tracer = _FakeTracer(TWO_APP_SCAN_CONFIG)
    first_tracer.run_id = "scan-one"
    _install_tracer(monkeypatch, first_tracer)
    assert fa.finish_scan(**kwargs)["error"] == "targets_not_tested"

    second_tracer = _FakeTracer(TWO_APP_SCAN_CONFIG)
    second_tracer.run_id = "scan-two"
    _install_tracer(monkeypatch, second_tracer)
    assert fa.finish_scan(**kwargs)["error"] == "targets_not_tested"


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


def test_inactive_agent_wave_resets_force_stop_attempt_counter(monkeypatch) -> None:
    from strix.tools.agents_graph import agents_graph_actions as ag

    state = _root_state()
    monkeypatch.setattr(
        ag,
        "_agent_graph",
        {"nodes": {"child": {"status": "running", "name": "child", "task": "work"}}},
    )
    first = fa._check_active_agents(state)
    assert first is not None
    assert first["error"] == "agents_still_active"
    assert fa._finish_scan_attempts[state.agent_id] == 1

    ag._agent_graph["nodes"].clear()
    assert fa._check_active_agents(state) is None
    assert state.agent_id not in fa._finish_scan_attempts

    ag._agent_graph["nodes"]["next-child"] = {
        "status": "running",
        "name": "next-child",
        "task": "more work",
    }
    next_wave = fa._check_active_agents(state)
    assert next_wave is not None
    assert "attempt 1/" in next_wave["message"]
