"""Tests for operator-instruction/structured-scope reconciliation."""

from __future__ import annotations

import pytest

from strix.scope import reconcile as rc


ROE = """
In-Scope Applications: WellReceived staging and SetMore staging.
WellReceived: https://my.staging.wellreceived.app/
SetMore: https://go.staging.setmore.com/
Login URL: https://auth.staging.setmore.com/o/login/service?service=setmore
Admin audit user: jake+anywhere-admin@accountablehq.com
Staff audit user: jake+anywhere-staff@accountablehq.com
Previously provided @full.io test accounts should not be used.
Do not test Google, Microsoft, or Apple identity providers.
Use these provisioned accounts for authenticated testing.
"""


# -- normalize_host ---------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://www.Go.Staging.Setmore.com:443/x/y", "www.go.staging.setmore.com"),
        ("go.staging.setmore.com/", "go.staging.setmore.com"),
        ("https://user:secret@app.customer.test:8443/path", "app.customer.test"),
        ("https://app.customer.test/path?notify=ops@alerts.vendor.test", "app.customer.test"),
        ("https://app.customer.test,", "app.customer.test"),
        ("10.20.30.40:8443", "10.20.30.40"),
        ("2001:0db8:0:0:0:0:0:1", "2001:db8::1"),
        ("https://[2001:db8::1]:8443/login", "2001:db8::1"),
        ("[2001:db8::1]:8443", "2001:db8::1"),
        ("", ""),
    ],
)
def test_normalize_host(raw: str, expected: str) -> None:
    assert rc.normalize_host(raw) == expected


def test_normalize_host_rejects_invalid_bracketed_url() -> None:
    assert rc.normalize_host("https://[2001:db8::1") == ""


# -- extract_instruction_targets -------------------------------------------


def test_extract_finds_targets_only_in_positive_scope_context() -> None:
    targets = rc.extract_instruction_targets(ROE)
    assert targets == [
        "https://my.staging.wellreceived.app/",
        "https://go.staging.setmore.com/",
        "https://auth.staging.setmore.com/o/login/service",
    ]
    # Account email and @handle domains are data, not assessment targets.
    assert all("accountablehq.com" not in target for target in targets)
    assert all("full.io" not in target for target in targets)


def test_extract_requires_positive_declaration_or_in_scope_section() -> None:
    text = """
Documentation lives at https://docs.customer.test/.
Contact security@customer.test and see vendor.example.net for background.
Please test https://app.customer.test/.
"""
    assert rc.extract_instruction_targets(text) == ["https://app.customer.test/"]


def test_extract_does_not_promote_reference_url_in_positive_clause() -> None:
    text = (
        "Test https://app.customer.test using documentation at "
        "https://docs.vendor.test. Also assess api.customer.test; "
        "see https://reference.vendor.test for background."
    )
    assert rc.extract_instruction_targets(text) == [
        "https://app.customer.test/",
        "api.customer.test",
    ]


@pytest.mark.parametrize(
    "instruction",
    [
        "Do not test https://payments.vendor.test; it is out of scope.",
        "Out of scope: https://payments.vendor.test",
        "Reference only: https://payments.vendor.test",
        "https://payments.vendor.test is informational only.",
        "The excluded target is https://payments.vendor.test.",
        "Never scan payments.vendor.test.",
    ],
)
def test_extract_never_promotes_negative_or_reference_only_clause(instruction: str) -> None:
    assert rc.extract_instruction_targets(instruction) == []


def test_extract_negative_clause_wins_inside_positive_line_and_section() -> None:
    text = """
In scope:
- app.customer.test
- Do not test https://payments.vendor.test.
- api.customer.test is in scope, but not in scope: admin.customer.test.
Test status.customer.test; do not test metrics.vendor.test.
"""
    assert rc.extract_instruction_targets(text) == [
        "app.customer.test",
        "api.customer.test",
        "status.customer.test",
    ]


def test_extract_splits_unpunctuated_and_do_not_clause() -> None:
    assert rc.extract_instruction_targets(
        "Test app.customer.test and do not test admin.customer.test"
    ) == ["app.customer.test"]


@pytest.mark.parametrize(
    "instruction",
    [
        "Test app.customer.test except admin.customer.test",
        "Test app.customer.test but not admin.customer.test",
        "In scope: app.customer.test, except admin.customer.test",
        "Test app.customer.test excluding admin.customer.test",
        "Test app.customer.test and skip admin.customer.test",
    ],
)
def test_extract_inline_exclusion_introducers_never_expand_scope(instruction: str) -> None:
    assert rc.extract_instruction_targets(instruction) == ["app.customer.test"]


def test_extract_supports_apex_domains_ipv4_and_ipv6() -> None:
    text = """
In-scope targets:
- customer.test,
- 192.0.2.25:8443;
- [2001:db8::25]:9443
- 2001:db8::26
Out-of-scope targets:
- vendor.test
- 198.51.100.8
- 2001:db8::99
"""
    assert rc.extract_instruction_targets(text) == [
        "customer.test",
        "192.0.2.25:8443",
        "[2001:db8::25]:9443",
        "2001:db8::26",
    ]


def test_extract_url_userinfo_and_email_query_do_not_hide_or_add_hosts() -> None:
    text = (
        "Test https://audit:secret@app.customer.test:8443/login?notify=ops@vendor.test, "
        "and scan https://api.customer.test/search?owner=alice@example.net."
    )
    assert rc.extract_instruction_targets(text) == [
        "https://app.customer.test:8443/login",
        "https://api.customer.test/search",
    ]


def test_extract_strips_trailing_punctuation_and_deduplicates() -> None:
    text = "Test app.customer.test, api.customer.test; also test https://app.customer.test/path)."
    assert rc.extract_instruction_targets(text) == [
        "app.customer.test",
        "api.customer.test",
        "https://app.customer.test/path",
    ]


def test_extract_accepts_explicit_apex_but_ignores_source_files() -> None:
    text = (
        "Scope covers wellreceived.app and wellreceived.com. "
        "Test implementation described in GenericExceptionMapper.java line 38."
    )
    assert rc.extract_instruction_targets(text) == ["wellreceived.app", "wellreceived.com"]


def test_extract_empty() -> None:
    assert rc.extract_instruction_targets("") == []
    assert rc.extract_instruction_targets("   ") == []


# -- reconcile_instruction_targets -----------------------------------------


def test_reconcile_surfaces_app_named_only_in_instructions() -> None:
    missing = rc.reconcile_instruction_targets(["https://my.staging.wellreceived.app/"], ROE)
    assert missing == [
        "https://go.staging.setmore.com/",
        "https://auth.staging.setmore.com/o/login/service",
    ]


def test_reconcile_empty_when_all_covered() -> None:
    structured = [
        "https://my.staging.wellreceived.app/",
        "https://go.staging.setmore.com/",
        "https://auth.staging.setmore.com/o/login/service",
    ]
    assert rc.reconcile_instruction_targets(structured, ROE) == []


def test_reconcile_ip_coverage_is_exact() -> None:
    instruction = "Test 192.0.2.5 and [2001:db8::5]."
    assert rc.reconcile_instruction_targets(["192.0.2.50", "2001:db8::5"], instruction) == [
        "192.0.2.5"
    ]


def test_reconcile_no_instruction() -> None:
    assert rc.reconcile_instruction_targets(["https://x.com"], "") == []


def test_reconcile_instruction_targets_preserves_full_identity() -> None:
    instruction = "Test https://www.app.customer.test:8443/a//b/ and https://[2001:db8::25]/app."
    assert rc.reconcile_instruction_targets([], instruction) == [
        "https://www.app.customer.test:8443/a//b",
        "https://[2001:db8::25]/app",
    ]


def test_reconcile_instruction_targets_requires_exact_identity() -> None:
    instruction = "Test https://www.customer.test/admin and https://api.customer.test/api/v2."
    structured = ["https://customer.test/", "https://api.customer.test/api"]
    assert rc.reconcile_instruction_targets(structured, instruction) == [
        "https://www.customer.test/admin",
        "https://api.customer.test/api/v2",
    ]


def test_reconcile_instruction_targets_canonicalizes_default_port_and_trailing_slash() -> None:
    instruction = "Test https://app.customer.test:443/api/."
    assert rc.reconcile_instruction_targets(["https://app.customer.test/api"], instruction) == []


# -- detect_auth_expectation ------------------------------------------------


@pytest.mark.parametrize(
    "instruction",
    [
        ROE,
        "Perform authenticated testing with the audit account.",
        "Credentials: admin@example.test / password provided for login.",
        "Credentials: username admin; password secret",
        "Username = admin\nPassword = correct-horse-battery-staple",
        "Use the supplied credentials for role-based testing.",
        "Test both authenticated and unauthenticated workflows.",
    ],
)
def test_detect_auth_expectation_positive(instruction: str) -> None:
    assert rc.detect_auth_expectation(instruction)


@pytest.mark.parametrize(
    "instruction",
    [
        "External black-box test of the public site. No login required.",
        "No authenticated testing is required.",
        "Authenticated testing is not requested.",
        "Do not perform authenticated testing.",
        "Credentials: none",
        "Credentials were not provided.",
        "No credentials were provided.",
        "No valid credentials are currently available.",
        "No login credentials have been supplied.",
        "Contact security@example.test for authorization approval.",
        "Login URL: https://auth.customer.test/login",
        "Contact ops@example.test about the password policy and login URL.",
        "The Authorization header and password reset flow are in scope.",
        "Test the password requirements and username validation behavior.",
        "No credentials were exposed in logs.",
        "",
    ],
)
def test_detect_auth_expectation_negative(instruction: str) -> None:
    assert not rc.detect_auth_expectation(instruction)


# -- report_claims_no_credentials ------------------------------------------


@pytest.mark.parametrize(
    "report_text",
    [
        (
            "External, unauthenticated black-box assessment -- no application credentials "
            "or source code were provided."
        ),
        "The testers had no valid credentials for the app.",
        "Testing proceeded without any application credentials.",
        "No credentials were available for authenticated testing.",
        "The assessment was conducted as an unauthenticated black-box.",
        "We were not provided any credentials.",
        "The client did not supply credentials.",
        "The client withheld the credentials.",
        "The assessment lacked authenticated access.",
        "This was a black-box assessment.",
        "Assessment type: external black-box.",
        "The assessment was performed without valid credentials.",
        "Credentials were not provided.",
        "Credentials were unavailable.",
        "The testing team did not receive credentials.",
        "No login access was provided.",
        "Testing was entirely black-box.",
        "The engagement was an external black-box assessment.",
        "External black-box assessment.",
        "We never received credentials.",
        "The client failed to provide credentials.",
        "No accounts were provided.",
        "The assessment was unauthenticated.",
        "Authenticated access was unavailable to testers.",
        "This assessment was credential-free.",
        "Testers lacked a valid account.",
        "No login credentials were supplied.",
        "We weren't provided credentials.",
        "We weren\u2019t provided credentials.",
        "The client didn't provide credentials.",
        "The client didn\u2019t provide credentials.",
        "Only unauthenticated testing was performed.",
        "The assessment proceeded without login credentials.",
        "The client declined to provide credentials.",
        "The engagement had no test account.",
        "External, unauthenticated black-box assessment.",
        "The penetration test was conducted as a black-box assessment.",
    ],
)
def test_report_claims_no_credentials_matches_engagement_claims(report_text: str) -> None:
    assert rc.report_claims_no_credentials(report_text)


@pytest.mark.parametrize(
    "report_text",
    [
        "Authenticated testing used the provided admin and staff accounts.",
        "No credentials were exposed in logs.",
        "No credentials were stored in plaintext.",
        "No hard-coded credentials were found in source code.",
        "No credentials were available in application logs.",
        "No credentials were provided to unauthenticated users by the API.",
        "The response contained no credentials or session tokens.",
        "Testing confirmed the admin endpoint was accessible without credentials.",
        "The assessment identified an endpoint that operated without credentials.",
        "Testing verified that unauthenticated users could access records without credentials.",
        "Black-box testing of the public route found no vulnerability.",
        "Credentials were not provided to unauthenticated clients.",
        "No login access was provided to unauthenticated users.",
        "No credentials were provided in HTTP responses.",
        "No credentials were supplied through error messages.",
        "The client did not provide credentials to unauthorized users.",
        "We were not provided credentials by the API.",
        "The assessment found that no credentials were provided in a response.",
        "No credentials were provided during registration.",
        "The black-box assessment component was not performed.",
        "Black-box assessment techniques identified an access-control issue.",
        "",
    ],
)
def test_report_claims_no_credentials_ignores_security_findings(report_text: str) -> None:
    assert not rc.report_claims_no_credentials(report_text)


# -- report_documents_auth_blocker -----------------------------------------


@pytest.mark.parametrize(
    "report_text",
    [
        "Authenticated testing was blocked because OTP codes routed to an external inbox.",
        "Could not log in: MFA verification code unavailable.",
        "The OTP was not received, preventing completion of the login flow.",
        "The supplied account was rejected by the login service.",
        "MFA prevented login.",
        "Login failed because the MFA verification code was unavailable.",
        "Authentication was not possible due to an unavailable identity provider.",
        "Could not log in: the identity provider was unavailable.",
        "The authenticator app was inaccessible.",
        "The verification code expired before it could be entered.",
        "Authentication was blocked by an unavailable identity provider.",
        "The SSO identity provider was unavailable, preventing authentication.",
        "Login failed because the supplied credentials were invalid.",
        "Login failed due to a TLS error contacting the identity provider.",
        "Couldn't log in because the identity provider was unavailable.",
        "Couldn\u2019t log in because the identity provider was unavailable.",
        "The MFA code wasn't received.",
        "The MFA code wasn\u2019t received.",
    ],
)
def test_report_documents_auth_blocker_requires_concrete_failure(report_text: str) -> None:
    assert rc.report_documents_auth_blocker(report_text)


@pytest.mark.parametrize(
    "report_text",
    [
        "MFA was enabled for the administrator account.",
        "The login flow requested an OTP.",
        "A verification code was sent successfully.",
        "The application supports 2FA and authenticator codes.",
        "MFA was tested successfully.",
        "All endpoints returned 200.",
        "Login failed.",
        "Authentication failed.",
        "Failed to log in.",
        "The tester was unable to authenticate.",
        "MFA was enabled; the unrelated reporting endpoint was unavailable.",
        "MFA was enabled and the unrelated reporting endpoint was unavailable.",
        "The OTP feature was present while an API dependency was unavailable.",
        "Authentication was not possible.",
        "Login failed because MFA worked as designed.",
        "Login failed because the SQL injection payload was rejected.",
        "Authentication failed because authorization worked as designed.",
        "We could not log in because testing intentionally used an invalid password.",
        "The supplied account was rejected because we entered the password incorrectly.",
        "The verification code expired because the tester intentionally waited until it expired.",
        "MFA prevented login because the tester intentionally disabled it.",
        "Authentication was unavailable during the assessment.",
        "",
    ],
)
def test_report_documents_auth_blocker_rejects_bare_factor_mentions(report_text: str) -> None:
    assert not rc.report_documents_auth_blocker(report_text)


# -- adversarial exclusion and classifier regressions ----------------------


def test_plain_and_inline_exclusions_are_not_promoted_inside_scope_section() -> None:
    text = """
In scope:
- app.customer.test, but not admin.customer.test
- api.customer.test except metrics.customer.test
- not payments.customer.test
"""
    assert rc.extract_instruction_targets(text) == ["app.customer.test", "api.customer.test"]


def test_plain_references_section_terminates_in_scope_state() -> None:
    text = """
In scope:
- app.customer.test
References:
- https://docs.vendor.test
- background.vendor.test
"""
    assert rc.extract_instruction_targets(text) == ["app.customer.test"]


def test_later_exclusion_globally_overrides_positive_declaration() -> None:
    text = "Test app.customer.test. Later: do not test app.customer.test."
    assert rc.extract_instruction_targets(text) == []


def test_path_specific_exclusion_does_not_remove_positive_sibling_path() -> None:
    text = "Test https://app.customer.test/public. Do not test https://app.customer.test/admin."
    assert rc.extract_instruction_targets(text) == ["https://app.customer.test/public"]


def test_path_parent_exclusion_removes_positive_descendant_path() -> None:
    text = "Test https://app.customer.test/api/v2. Do not test https://app.customer.test/api."
    assert rc.extract_instruction_targets(text) == []


def test_instruction_excludes_asset_matches_explicit_negative_context_only() -> None:
    instruction = """
Out-of-scope targets:
- vendor.customer.test
- 192.0.2.8
References:
- https://docs.customer.test
"""
    assert rc.instruction_excludes_asset(instruction, "https://vendor.customer.test/")
    assert rc.instruction_excludes_asset(instruction, "https://api.vendor.customer.test/")
    assert rc.instruction_excludes_asset(instruction, "192.0.2.8")
    assert not rc.instruction_excludes_asset(instruction, "192.0.2.80")
    assert not rc.instruction_excludes_asset(instruction, "notvendor.customer.test")
    assert not rc.instruction_excludes_asset(instruction, "https://docs.customer.test")


def test_instruction_excludes_asset_preserves_non_root_url_paths() -> None:
    instruction = "Do not test https://app.customer.test/api."
    assert rc.instruction_excludes_asset(instruction, "https://app.customer.test/api")
    assert rc.instruction_excludes_asset(instruction, "https://app.customer.test/api/v2")
    assert not rc.instruction_excludes_asset(instruction, "https://app.customer.test/")
    assert not rc.instruction_excludes_asset(instruction, "https://app.customer.test/apix")
    assert not rc.instruction_excludes_asset(instruction, "https://app.customer.test/admin")
    assert not rc.instruction_excludes_asset(instruction, "https://api.app.customer.test/api")


def test_instruction_excludes_asset_host_root_covers_paths_but_not_other_origins() -> None:
    assert rc.instruction_excludes_asset(
        "Do not test customer.test.", "https://api.customer.test/private"
    )
    assert rc.instruction_excludes_asset(
        "Do not test https://app.customer.test/.", "https://app.customer.test/api"
    )
    assert not rc.instruction_excludes_asset(
        "Do not test http://app.customer.test/.", "https://app.customer.test/api"
    )


def test_scheme_less_path_exclusion_never_widens_to_host_or_sibling() -> None:
    instruction = "Do not test app.customer.test/admin."
    assert rc.instruction_excludes_asset(instruction, "app.customer.test/admin")
    assert rc.instruction_excludes_asset(instruction, "app.customer.test/admin/users")
    assert not rc.instruction_excludes_asset(instruction, "app.customer.test/")
    assert not rc.instruction_excludes_asset(instruction, "app.customer.test/public")


def test_repeated_slashes_remain_distinct_in_exclusions() -> None:
    assert not rc.instruction_excludes_asset(
        "Do not test https://app.customer.test/a/b.",
        "https://app.customer.test/a//b",
    )
    assert not rc.instruction_excludes_asset(
        "Do not test https://app.customer.test/a//b.",
        "https://app.customer.test/a/b",
    )


@pytest.mark.parametrize(
    "hostname",
    [
        "account.example.test",
        "accounts.example.test",
        "credentials.example.test",
        "authentication.example.test",
        "login.example.test",
    ],
)
def test_auth_looking_hostname_does_not_hide_scope_exclusion(hostname: str) -> None:
    instruction = f"Test {hostname}. Later: do not test {hostname}."
    assert rc.extract_instruction_targets(instruction) == []
    assert rc.instruction_excludes_asset(instruction, hostname)


@pytest.mark.parametrize(
    "instruction",
    [
        "Do not ever test vendor.example.test.",
        "Never, under any circumstances, test vendor.example.test.",
        "You are forbidden to test vendor.example.test.",
        "In scope:\n- Testing vendor.example.test is prohibited.",
        "In scope:\n- No testing of vendor.example.test.",
        "In scope:\n- vendor.example.test is off limits.",
    ],
)
def test_adversarial_negative_scope_phrasing_never_authorizes(instruction: str) -> None:
    assert rc.extract_instruction_targets(instruction) == []
    assert rc.instruction_excludes_asset(instruction, "vendor.example.test")


def test_scope_boundary_is_not_inverted_into_an_exclusion() -> None:
    instruction = "Do not test anything outside app.example.test."
    assert not rc.instruction_excludes_asset(instruction, "app.example.test")


def test_incidental_related_host_is_not_promoted_or_globally_excluded() -> None:
    positive = "Test app.example.test using identity provider idp.vendor.test."
    assert rc.extract_instruction_targets(positive) == ["app.example.test"]

    mixed = (
        "Test docs.vendor.test. Do not test app.example.test using documentation at "
        "docs.vendor.test."
    )
    assert rc.extract_instruction_targets(mixed) == ["docs.vendor.test"]
    assert not rc.instruction_excludes_asset(mixed, "docs.vendor.test")


@pytest.mark.parametrize(
    "instruction",
    [
        "Credentials: username admin; password secret; do not use these credentials.",
        "Credentials: admin / secret are for reference only; do not authenticate.",
        "No authenticated testing is required. Credentials: admin / secret.",
        "Use the provisioned account only as a reference; authenticated testing is prohibited.",
        "Credentials: see the vault entry for reference only.",
        "Username: admin; password: secret; do not use them.",
    ],
)
def test_authentication_opt_out_overrides_credential_signals(instruction: str) -> None:
    assert not rc.detect_auth_expectation(instruction)


def test_target_specific_auth_opt_out_does_not_erase_other_target_requirement() -> None:
    instruction = (
        "Authenticate https://one.example.test but do not authenticate https://two.example.test."
    )
    assert rc.detect_auth_expectation(instruction)


def test_auth_only_exception_does_not_remove_target_from_engagement_scope() -> None:
    instruction = "Perform authenticated testing on all targets except https://public.example.test."
    assert not rc.instruction_excludes_asset(instruction, "https://public.example.test")


def test_target_qualified_auth_prohibition_is_not_a_scope_exclusion() -> None:
    instruction = (
        "Authenticate https://one.example.test. Authenticated testing on "
        "https://two.example.test is prohibited."
    )
    assert rc.detect_auth_expectation(instruction)
    assert not rc.instruction_excludes_asset(instruction, "https://two.example.test")


def test_credential_unavailability_is_not_a_global_opt_out_of_explicit_auth_mandate() -> None:
    instruction = (
        "Credentials were not provided. Perform authenticated testing through self-registration."
    )
    assert rc.detect_auth_expectation(instruction)


@pytest.mark.parametrize(
    "instruction",
    [
        "Credentials: old-secret. These credentials are not authorized for use.",
        "Credentials: old-secret. These credentials are revoked.",
        "Credentials: old-secret. These credentials are superseded.",
        "Credentials: compromised. Do not use the compromised test account.",
    ],
)
def test_revoked_or_forbidden_credentials_cancel_auth_signal(instruction: str) -> None:
    assert not rc.detect_auth_expectation(instruction)


@pytest.mark.parametrize(
    "instruction",
    [
        "Use supplied credentials for app.test; do not use credentials outside "
        "the authorized scope.",
        "Use supplied credentials for app.test; do not use credentials for destructive actions.",
        "Use supplied credentials for app.test; do not use them after the assessment.",
    ],
)
def test_usage_qualifiers_do_not_cancel_authorized_auth_testing(instruction: str) -> None:
    assert rc.detect_auth_expectation(instruction)


def test_later_replacement_credentials_survive_revoked_old_set() -> None:
    instruction = "Old credentials were revoked. Use the new credentials: admin / new-secret."
    assert rc.detect_auth_expectation(instruction)


def test_credential_observation_objective_is_not_provisioned_access() -> None:
    assert not rc.detect_auth_expectation(
        "Test whether credentials are provided/exposed in HTTP responses or logs."
    )
    assert rc.detect_auth_expectation("Credentials were provided for testing.")


@pytest.mark.parametrize(
    "instruction",
    [
        "Do not authenticate to https://app.test/public. Authenticate to https://app.test/admin.",
        "Do not authenticate to http://app.test/. Authenticate to https://app.test/.",
        "Do not authenticate to app.test:8080. Authenticate to app.test:8443.",
    ],
)
def test_distinct_origin_or_path_auth_opt_out_does_not_erase_requirement(
    instruction: str,
) -> None:
    assert rc.detect_auth_expectation(instruction)


# -- final audit regression matrix -----------------------------------------


def test_scheme_less_instruction_target_is_covered_by_exact_structured_origin() -> None:
    assert (
        rc.reconcile_instruction_targets(
            ["https://app.test/"],
            "Test app.test.",
        )
        == []
    )
    assert (
        rc.reconcile_instruction_targets(
            ["https://app.test:8443/api"],
            "Test app.test/api.",
        )
        == []
    )


def test_scheme_less_reconciliation_does_not_merge_explicit_distinct_origins() -> None:
    assert rc.reconcile_instruction_targets(
        ["http://app.test/"],
        "Test https://app.test/.",
    ) == ["https://app.test/"]
    assert rc.reconcile_instruction_targets(
        ["app.test:8443/api"],
        "Test app.test:9443/api.",
    ) == ["app.test:9443/api"]


@pytest.mark.parametrize(
    ("structured", "instruction", "expected"),
    [
        (
            ["10.0.0.1"],
            "Also test https://10.0.0.1/ as a web application.",
            ["https://10.0.0.1/"],
        ),
        (
            ["2001:db8::25"],
            "Also test https://[2001:db8::25]/ as a web application.",
            ["https://[2001:db8::25]/"],
        ),
    ],
)
def test_bare_ip_scope_does_not_hide_explicit_ip_url(
    structured: list[str],
    instruction: str,
    expected: list[str],
) -> None:
    assert rc.reconcile_instruction_targets(structured, instruction) == expected


@pytest.mark.parametrize(
    "instruction",
    [
        "We did not test vendor.test.",
        "Do not attempt to test vendor.test.",
        "It is unnecessary to test vendor.test.",
        "The team failed to test vendor.test.",
        "In scope:\n- Testing vendor.test is forbidden.",
        "Don\u2019t test vendor.test.",
        "In scope:\n- vendor.test — do not test.",
        "In scope:\n- vendor.test is out\u2011of\u2011scope.",
    ],
)
def test_negated_testing_variants_never_grant_scope(instruction: str) -> None:
    assert rc.extract_instruction_targets(instruction) == []
    assert rc.instruction_excludes_asset(instruction, "vendor.test")


@pytest.mark.parametrize(
    "instruction",
    [
        "Do not test anything other than app.test.",
        "Test nothing except app.test.",
        "Everything except app.test is out of scope.",
        "Out of scope: everything except app.test.",
    ],
)
def test_negative_scope_boundaries_do_not_exclude_the_exception(instruction: str) -> None:
    assert not rc.instruction_excludes_asset(instruction, "app.test")


@pytest.mark.parametrize(
    ("instruction", "expected"),
    [
        (
            "Test app.test and use auth.vendor.test only as its identity provider.",
            ["app.test"],
        ),
        ("In scope:\n- app.test uses CDN cdn.vendor.test.", ["app.test"]),
        (
            "In scope: app.test. Notes: status.vendor.test is an external dependency.",
            ["app.test"],
        ),
        ("Test app.test and compare behavior with baseline.vendor.test", ["app.test"]),
    ],
)
def test_incidental_dependency_hosts_are_not_promoted(
    instruction: str,
    expected: list[str],
) -> None:
    assert rc.extract_instruction_targets(instruction) == expected


def test_mixed_positive_and_no_testing_clause_keeps_only_positive_target() -> None:
    instruction = "Test app.test with no testing of admin.test."
    assert rc.extract_instruction_targets(instruction) == ["app.test"]
    assert rc.instruction_excludes_asset(instruction, "admin.test")


def test_credential_use_restriction_is_not_a_whole_asset_exclusion() -> None:
    instruction = "Do not use credentials for https://admin.test."
    assert not rc.instruction_excludes_asset(instruction, "https://admin.test/")


@pytest.mark.parametrize(
    "instruction",
    [
        "Perform authenticated testing of https://app.customer.test.",
        "Testing is authorized for https://app.customer.test.",
        "Conduct an assessment of https://app.customer.test.",
    ],
)
def test_explicit_positive_testing_forms_surface_target(instruction: str) -> None:
    assert rc.extract_instruction_targets(instruction) == ["https://app.customer.test/"]


@pytest.mark.parametrize(
    "instruction",
    [
        "Credentials: admin/secret. Don't use them.",
        "Credentials: admin/secret. Don\u2019t use them.",
        "Credentials: admin/secret. They are for reference only.",
        "Credentials: admin/secret. They are revoked.",
        "Password is hashed before storage.",
        "Verify credentials are provided only over TLS.",
        "Old credentials were revoked. Test whether the password is stored securely.",
        "Credentials are provided but not authorized for use.",
    ],
)
def test_auth_classifier_rejects_opt_outs_and_credential_observations(
    instruction: str,
) -> None:
    assert not rc.detect_auth_expectation(instruction)


@pytest.mark.parametrize("conjunction", ["and", "but", "while", "whereas"])
def test_target_specific_auth_negation_does_not_erase_generic_mandate(
    conjunction: str,
) -> None:
    instruction = (
        "Use credentials for authenticated testing of all applications "
        f"{conjunction} authentication is not required for https://b.test."
    )
    assert rc.detect_auth_expectation(instruction)


# -- exact non-web exclusions ----------------------------------------------


@pytest.mark.parametrize(
    ("instruction", "asset"),
    [
        ("Do not test /Workspace/App.", "/Workspace/App"),
        ("Out of scope:\n- `/Workspace/App/`", "/Workspace/App"),
        (
            "Do not test git@github.com:Org/Repo.git.",
            "git@github.com:Org/Repo.git",
        ),
        (
            "Out of scope:\n- `git@github.com:Org/Repo.git/`",
            "git@github.com:Org/Repo.git",
        ),
    ],
)
def test_instruction_excludes_exact_non_web_identity(
    instruction: str,
    asset: str,
) -> None:
    assert rc.instruction_excludes_asset(instruction, asset)


@pytest.mark.parametrize(
    ("instruction", "asset"),
    [
        ("Do not test /Workspace/Application.", "/Workspace/App"),
        ("Do not test /Workspace/App/subdir.", "/Workspace/App"),
        ("Do not test /Workspace/App.", "/Workspace/App/subdir"),
        ("Do not test /workspace/app.", "/Workspace/App"),
        (
            "Do not test git@github.com:Org/Repo.git-fork.",
            "git@github.com:Org/Repo.git",
        ),
        (
            "Do not test git@github.com:Org/Repo.git.",
            "git@github.com:Org/Other.git",
        ),
        (
            "Do not test git@github.com:org/Repo.git.",
            "git@github.com:Org/Repo.git",
        ),
        (
            "References:\n- git@github.com:Org/Repo.git",
            "git@github.com:Org/Repo.git",
        ),
        ("Test /Workspace/App.", "/Workspace/App"),
        ("Do not test anything outside /Workspace/App.", "/Workspace/App"),
    ],
)
def test_non_web_exclusions_require_exact_negative_identity(
    instruction: str,
    asset: str,
) -> None:
    assert not rc.instruction_excludes_asset(instruction, asset)


@pytest.mark.parametrize(
    "instruction",
    [
        "Test git@github.com:Org/Repo.git.",
        "Test (`git@github.com:Org/Repo.git`).",
        "In scope:\n- git@github.com:Org/Repo.git",
        "Test ssh://git@github.com/Org/Repo.git.",
        "Test /Workspace/Repo.git.",
        "Test src/Repo.git.",
    ],
)
def test_non_web_identity_is_not_promoted_as_web_scope(instruction: str) -> None:
    assert rc.extract_instruction_targets(instruction) == []


# -- final auth/identity reconciliation regressions ------------------------


@pytest.mark.parametrize(
    "instruction",
    [
        "Never authenticate.",
        "Credentials: admin/secret; never authenticate.",
        "Do not use the account for https://b.test/.",
        "Don't use an account for https://b.test/.",
        "Don\u2019t use credentials for https://b.test/.",
        "Do not use the provided accounts for https://b.test/.",
    ],
)
def test_auth_prohibitions_never_become_positive_expectations(instruction: str) -> None:
    assert not rc.detect_auth_expectation(instruction)


@pytest.mark.parametrize(
    "instruction",
    [
        (
            "Use the supplied account for authenticated testing; do not use the "
            "account for destructive actions."
        ),
        (
            "Use the supplied account for https://b.test; don't use the account "
            "for destructive actions on https://b.test."
        ),
    ],
)
def test_qualified_non_auth_account_restrictions_preserve_auth_mandate(
    instruction: str,
) -> None:
    assert rc.detect_auth_expectation(instruction)


@pytest.mark.parametrize(
    "instruction",
    [
        "Use authorized credentials for A and B.",
        "Test A and B with credentials.",
    ],
)
def test_multi_target_credential_phrasing_sets_auth_expectation(instruction: str) -> None:
    assert rc.detect_auth_expectation(instruction)


@pytest.mark.parametrize(
    ("structured", "instruction", "expected"),
    [
        (["app.test"], "Test app.test:443.", ["app.test:443"]),
        (["https://app.test"], "Test app.test:443.", ["app.test:443"]),
        (["app.test:443"], "Test app.test.", ["app.test"]),
        (["app.test:443"], "Test https://app.test.", ["https://app.test/"]),
        (["app.test:443"], "Test app.test:443.", []),
        (["https://app.test"], "Test https://app.test:443.", []),
        (["https://app.test:443"], "Test https://app.test.", []),
    ],
)
def test_scheme_less_explicit_ports_keep_exact_reconciliation_identity(
    structured: list[str],
    instruction: str,
    expected: list[str],
) -> None:
    assert rc.reconcile_instruction_targets(structured, instruction) == expected


@pytest.mark.parametrize(
    "instruction",
    [
        "In scope: app.test, out of scope: admin.test.",
        "app.test is in scope, admin.test is out of scope.",
        "Test app.test, no testing of admin.test.",
        "Authorized targets: app.test, excluded targets: admin.test.",
    ],
)
def test_mixed_comma_scope_keeps_positive_and_excludes_negative(instruction: str) -> None:
    assert rc.extract_instruction_targets(instruction) == ["app.test"]
    assert rc.instruction_excludes_asset(instruction, "admin.test")


def test_mixed_comma_scope_does_not_promote_incidental_reference() -> None:
    instruction = "Test app.test, see docs.vendor.test for reference, no testing of admin.test."
    assert rc.extract_instruction_targets(instruction) == ["app.test"]
    assert rc.instruction_excludes_asset(instruction, "admin.test")


@pytest.mark.parametrize(
    "restriction",
    [
        "Do not test denial-of-service on app.test.",
        "Do not test the admin function on app.test.",
        "Do not test authentication workflows on app.test.",
        "Do not test login workflows on app.test.",
        "Do not test payment processing on app.test.",
        "Do not test /admin on app.test.",
        "Do not scan UDP ports on app.test.",
        "Do not scan port 22 on app.test.",
        "Do not attack production data on app.test.",
        "Must not test account deletion against app.test.",
        "Avoid destructive testing on app.test.",
        "Do not use brute force against app.test.",
        "Exclude the payment feature on app.test from testing.",
        "Do not test app.test for denial-of-service.",
        "Do not scan app.test on port 22.",
        "Do not scan app.test on UDP ports.",
        "Do not use app.test as a callback endpoint.",
    ],
)
def test_activity_restriction_does_not_exclude_its_host(restriction: str) -> None:
    instruction = f"Test app.test. {restriction}"
    assert rc.extract_instruction_targets(instruction) == ["app.test"]
    assert not rc.instruction_excludes_asset(instruction, "app.test")

    # A negative technique/feature clause remains non-authorizing on its own.
    assert rc.extract_instruction_targets(restriction) == []


@pytest.mark.parametrize(
    "restriction",
    [
        "Do not test app.test.",
        "Do not perform testing on app.test.",
        "Do not test anything on app.test.",
        "Do not test app.test for any reason.",
        "Do not use app.test as a target.",
    ],
)
def test_whole_asset_negative_wording_still_excludes_host(restriction: str) -> None:
    instruction = f"Test app.test. {restriction}"
    assert rc.extract_instruction_targets(instruction) == []
    assert rc.instruction_excludes_asset(instruction, "app.test")


def test_direct_path_exclusion_remains_path_specific() -> None:
    instruction = "Test app.test. Do not test app.test/admin."
    assert rc.extract_instruction_targets(instruction) == ["app.test"]
    assert not rc.instruction_excludes_asset(instruction, "app.test")
    assert rc.instruction_excludes_asset(instruction, "app.test/admin")


# -- regression: scope leaks and over-acceptance ---------------------------


def test_unknown_subsection_heading_terminates_authorized_section() -> None:
    # Hosts listed under a reference/background subsection whose label does not
    # match a known section keyword must NOT inherit the in-scope state.
    instruction = """
In-scope applications:
- https://app.corp.test/

Additional resources:
- https://internal-monitoring.corp.test/
- grafana.corp.test

Background information:
- internal-jira.corp.test
"""
    assert rc.extract_instruction_targets(instruction) == ["https://app.corp.test/"]


def test_labelled_item_line_with_host_still_authorizes() -> None:
    # A "Label: <host>" line inside an in-scope section is an in-scope entry,
    # not a new section heading, so it must keep extracting.
    instruction = """
In-Scope Applications:
WellReceived: https://my.app.test/
SetMore: https://go.app.test/
"""
    assert rc.extract_instruction_targets(instruction) == [
        "https://my.app.test/",
        "https://go.app.test/",
    ]


@pytest.mark.parametrize(
    ("instruction", "asset"),
    [
        ("Out of scope: the identity provider auth.customer.test.", "auth.customer.test"),
        ("Excluded: see docs at internal.vendor.test.", "internal.vendor.test"),
        ("Out of scope: refer to reports.vendor.test for details.", "reports.vendor.test"),
    ],
)
def test_exclusion_recognized_despite_reference_marker(instruction: str, asset: str) -> None:
    # Reference-marker suppression is a positive-scope safeguard only; it must
    # never drop a host from an explicit exclusion clause.
    assert rc.instruction_excludes_asset(instruction, asset)


@pytest.mark.parametrize(
    "literal",
    ["::", "::1", "127.0.0.1", "0.0.0.0"],
)
def test_unspecified_and_loopback_literals_not_authorized(literal: str) -> None:
    assert rc.extract_instruction_targets(f"In scope: test {literal} thoroughly.") == []


def test_routable_ip_literal_still_authorized() -> None:
    assert rc.extract_instruction_targets("In scope: test 10.20.30.40 thoroughly.") == [
        "10.20.30.40",
    ]
