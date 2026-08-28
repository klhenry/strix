import ipaddress
import logging
import re
from typing import Any
from urllib.parse import urlparse

import defusedxml.ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

from strix.scope import (
    detect_auth_expectation,
    instruction_excludes_asset,
    reconcile_instruction_targets,
    report_claims_no_credentials,
    report_documents_auth_blocker,
)
from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)

# Track how many times finish_scan has been called with active agents, per scan
_finish_scan_attempts: dict[str, int] = {}
_MAX_ATTEMPTS_BEFORE_FORCE: int = 3

# Track agents that have already been warned about 0 findings so we allow
# them through on the second call.
_zero_findings_warned: set[tuple[str, str]] = set()

# Track agents already warned about targets left untested so a scan can still
# complete (with documented limitations) on the second finish_scan call.
_incomplete_coverage_warned: set[tuple[str, str]] = set()

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

_EMAIL_TOKEN_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+", re.IGNORECASE)
_AUTH_SEGMENT_SPLIT_RE = re.compile(
    r"\s*;\s*|\r?\n+|\s+(?:(?:and|but)\s+)?"
    r"(?=(?:do\s+not|don['\u2019]t|never)\b)|"
    r"\s+(?=(?:but\s+not|except(?:\s+for)?|excluding)\b)|"
    r"\s+(?=(?:although|but|while|whereas)\b)|"
    r"(?:,\s*|\s+)(?=with\b[^\n]{0,160}\bunauthenticated[-\s]+only\b)|"
    r"\s+(?=and\s+(?:authenticated|credentialed|unauthenticated|"
    r"login|log[-\s]?in|sign[-\s]?in|authentication)\b)|"
    r",\s+(?=(?:but|however|except|not|never|do\s+not|and\s+do\s+not)\b)|"
    r"(?<=[.!?])\s+(?=[A-Z#])",
    re.IGNORECASE,
)
_NEGATIVE_AUTH_SEGMENT_RE = re.compile(
    r"\b(?:"
    r"(?:do\s+not|don['\u2019]t|never)\s+(?:perform\s+)?"
    r"(?:authenticated\s+(?:testing|assessment)|authenticate|log\s*in|sign\s*in|"
    r"use\s+(?:(?:the|this|that|these|those|any|a|an|our|provided|supplied|"
    r"test(?:er)?)\s+)?"
    r"(?:credentials?|accounts?)|use\s+(?:it|them))"
    r"|(?:credentials?|accounts?)(?:\s+use)?\b[^\n]{0,120}?\b"
    r"(?:(?:is|are|was|were)\s+(?:prohibited|not\s+(?:allowed|permitted|authorized))|"
    r"(?:must|should)\s+not\s+be\s+used)"
    r"|(?:it|they|them)\s+(?:must|should)\s+not\s+be\s+used"
    r"|no\s+authenticated\s+(?:testing|assessment|coverage|access)"
    r"|authenticated\s+(?:testing|assessment|coverage|access)\b"
    r"[^\n]{0,200}?\b(?:is\s+|was\s+)?"
    r"(?:not\s+required|not\s+requested|excluded|prohibited|out[-\s]?of[-\s]?scope)"
    r"|(?:authentication|login)\s+(?:is\s+|was\s+)?"
    r"(?:not\s+required|not\s+requested|excluded|prohibited)"
    r"|unauthenticated[-\s]+only|(?:but\s+not|except(?:\s+for)?|excluding)\b"
    r")",
    re.IGNORECASE,
)
_GENERIC_AUTH_SEGMENT_RE = re.compile(
    r"\b(?:all|every|each|both)\s+"
    r"(?:in[-\s]?scope\s+)?(?:applications?|apps?)\b",
    re.IGNORECASE,
)
_GENERIC_ALL_TARGET_AUTH_RE = re.compile(
    r"\b(?:all|every|each|both)\s+"
    r"(?:in[-\s]?scope\s+)?(?:targets?|assets?|systems?)\b"
    r"|\b(?:all|every|each|both)\s+(?:in[-\s]?scope\s+)?"
    r"(?:web\s+)?(?:applications?|apps?)\s+(?:and|plus)\s+"
    r"(?:all\s+)?(?:ips?|ip\s+addresses?|network\s+(?:targets?|addresses?))\b"
    r"|\bengagement[-\s]+wide\b",
    re.IGNORECASE,
)
_UNAUTHENTICATED_PHASE_RE = re.compile(
    r"\b(?:initial|first|separate|distinct|public)?\s*"
    r"(?:unauthenticated(?:\s+black[-\s]?box)?|black[-\s]?box)\s+"
    r"(?:testing|assessment|phase)\b",
    re.IGNORECASE,
)
_AUTHENTICATED_PHASE_RE = re.compile(
    r"\b(?:authenticated|credentialed)(?:\s+(?:authenticated|credentialed))?\s+"
    r"(?:testing|assessment|phase)\b",
    re.IGNORECASE,
)
_PHASE_RELATION_RE = re.compile(
    r"\b(?:preceded|followed|before|after|alongside|then)\b",
    re.IGNORECASE,
)
_NO_CREDENTIALS_AUTH_PHASE_RE = re.compile(
    r"\b(?:"
    r"(?:no\b[^.!?\n]{0,60}\bcredentials?\b"
    r"|credentials?\b[^.!?\n]{0,40}\b(?:not|never)\b"
    r"|without\b[^.!?\n]{0,40}\bcredentials?\b)"
    r"[^.!?\n]{0,40}\b(?:in|during|for)\s+(?:the\s+)?"
    r"(?:authenticated|credentialed)\s+"
    r"(?:testing|assessment|phase)\b"
    r"|(?:authenticated|credentialed)\s+(?:testing|assessment|phase)\b"
    r"[^.!?\n]{0,60}\b(?:no\b[^.!?\n]{0,60}\bcredentials?\b"
    r"|credentials?\b[^.!?\n]{0,40}\b(?:not|never)\b"
    r"|without\b[^.!?\n]{0,40}\bcredentials?\b)"
    r")",
    re.IGNORECASE,
)
_NO_CREDENTIALS_UNAUTH_PHASE_RE = re.compile(
    r"\b(?:"
    r"(?:no\b[^.!?\n]{0,60}\bcredentials?\b"
    r"|credentials?\b[^.!?\n]{0,40}\b(?:not|never)\b"
    r"|without\b[^.!?\n]{0,40}\bcredentials?\b)"
    r"[^.!?\n]{0,40}\b(?:in|during|for)\s+(?:the\s+)?"
    r"(?:initial\s+|first\s+)?(?:unauthenticated|black[-\s]?box)\s+"
    r"(?:testing|assessment|phase)\b"
    r"|(?:initial\s+|first\s+)?(?:unauthenticated|black[-\s]?box)\s+"
    r"(?:testing|assessment|phase)\b[^.!?\n]{0,60}"
    r"(?:no\b[^.!?\n]{0,60}\bcredentials?\b"
    r"|without\b[^.!?\n]{0,40}\bcredentials?\b)"
    r")",
    re.IGNORECASE,
)
_EXCLUSION_NOTE_SOURCE_RE = re.compile(
    r"\b(?:operator|client|customer|rules?[-\s]+of[-\s]+engagement|ROE|instructions?)\b",
    re.IGNORECASE,
)
_EXCLUSION_NOTE_ACTION_RE = re.compile(
    r"\b(?:exclud(?:e|ed|es|ing)|out[-\s]+of[-\s]+scope|do[-\s]+not[-\s]+test)\b",
    re.IGNORECASE,
)
_DISTINCT_BLOCKER_MARKER_RE = re.compile(
    r"\b(?:respectively|separate(?:ly)?|different)\b",
    re.IGNORECASE,
)
_LIMITED_BLOCKER_MARKER_RE = re.compile(
    r"\b(?:only|solely|exclusively)\b",
    re.IGNORECASE,
)
_SHARED_BLOCKER_EFFECT_RE = re.compile(
    r"(?:prevent(?:ed|ing)|block(?:ed|ing)|den(?:ied|ying)|unavailable)"
    r"[^.;!?\n]{0,100}\b(?:both|all|each)\b|"
    r"\b(?:both|all|each)\b[^.;!?\n]{0,100}"
    r"(?:authentication|authenticate|login|log[-\s]?in|sign[-\s]?in)"
    r"[^.;!?\n]{0,80}(?:prevent(?:ed|ing)|block(?:ed|ing)|den(?:ied|ying)|unavailable)",
    re.IGNORECASE,
)
_SHARED_TARGET_GROUP_EFFECT_RE = re.compile(
    r"^\s*(?:were|was|are|is)?\s*(?:both\s+)?"
    r"(?:prevent(?:ed|ing)|block(?:ed|ing)|den(?:ied|ying))\s+"
    r"(?:from\s+)?(?:authentication|authenticating|login|logging[-\s]+in|signing[-\s]+in)\b",
    re.IGNORECASE,
)
_LIMITED_AUTH_EFFECT_RE = re.compile(
    r"\b(?:only|solely|exclusively)\s+"
    r"(?:prevent(?:ed|ing)|block(?:ed|ing)|den(?:ied|ying)|affect(?:ed|ing))\b"
    r"[^.;!?\n]{0,80}\b"
    r"(?:authentication|authenticate|login|log[-\s]?in|sign[-\s]?in)\b",
    re.IGNORECASE,
)
_LIMITED_TARGET_INTRO_RE = re.compile(
    r"\b(?:only|solely|exclusively)\s+(?:for|on|at|to)\b",
    re.IGNORECASE,
)
_TARGET_LIST_JOIN_RE = re.compile(
    r"^\s*(?:,\s*(?:(?:and|plus)\s+)?|(?:and|plus|&)\s+)$",
    re.IGNORECASE,
)
_AFFECTED_TARGET_PREFIX_RE = re.compile(
    r"(?:authentication|authenticate(?:d)?|login|log[-\s]?in|sign[-\s]?in)"
    r"\s+(?:to|for|on|at)\s*$",
    re.IGNORECASE,
)
_AFFECTED_TARGET_SUFFIX_RE = re.compile(
    r"^\s*[:,-]?\s*(?:"
    r"(?:authentication|login|log[-\s]?in|sign[-\s]?in)\b[^.;!?\n]{0,80}"
    r"(?:prevent(?:ed|ing)|block(?:ed|ing)|den(?:ied|ying)|unavailable|failed)|"
    r"(?:prevent(?:ed|ing)|block(?:ed|ing)|den(?:ied|ying))\b[^.;!?\n]{0,50}"
    r"(?:authentication|authenticate|login|log[-\s]?in|sign[-\s]?in)"
    r")",
    re.IGNORECASE,
)
_INCIDENTAL_TARGET_PREFIX_RE = re.compile(
    r"\b(?:unlike|versus|whereas|although|however|"
    r"compared\s+(?:with|to)|as\s+opposed\s+to)\s*$",
    re.IGNORECASE,
)
_ACCOUNT_SELECTOR_PROHIBITION_RE = re.compile(
    r"\b(?:the\s+)?(?P<selector>latter|former)\s+(?:credentials?|accounts?)\s+"
    r"(?:(?:must|should)\s+not\s+be\s+used|"
    r"(?:is|are|was|were)\s+(?:prohibited|not\s+(?:allowed|permitted|authorized)))"
    r"\s*[.!?]?\s*$",
    re.IGNORECASE,
)

_COVERAGE_FIELDS = ("asset", "status", "authentication", "notes")
_CoverageResolution = dict[tuple[Any, ...], list[dict[str, str]]]
_ReferenceAnalysis = list[tuple[str, list[tuple[str, str]]]]


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


def _parse_scope_coverage(xml_str: str) -> list[dict[str, str]]:  # noqa: PLR0912
    if not xml_str or not xml_str.strip():
        return []
    try:
        root = DefusedET.fromstring(xml_str, forbid_dtd=True)
    except (DefusedET.ParseError, DefusedXmlException) as exc:
        raise ValueError(f"scope_coverage must be safe, well-formed XML: {exc}") from exc
    if root.tag != "coverage":
        raise ValueError("scope_coverage root element must be <coverage>")
    if root.attrib:
        raise ValueError("scope_coverage <coverage> must not have attributes")
    if (root.text or "").strip():
        raise ValueError("scope_coverage <coverage> may contain only <target> elements")

    entries: list[dict[str, str]] = []
    for target_index, target in enumerate(root, start=1):
        if target.tag != "target":
            raise ValueError(
                "scope_coverage <coverage> may contain only <target> elements "
                f"(found <{target.tag}>)"
            )
        if target.attrib:
            raise ValueError(f"scope_coverage target {target_index} must not have attributes")
        if (target.tail or "").strip():
            raise ValueError("scope_coverage <coverage> may contain only <target> elements")
        if (target.text or "").strip():
            raise ValueError(
                f"scope_coverage target {target_index} may contain only required child fields"
            )

        entry: dict[str, str] = {}
        for child in target:
            field = child.tag
            if field not in _COVERAGE_FIELDS:
                raise ValueError(
                    f"scope_coverage target {target_index} has unexpected <{field}> field"
                )
            if field in entry:
                raise ValueError(
                    f"scope_coverage target {target_index} has duplicate <{field}> fields"
                )
            if child.attrib or list(child):
                raise ValueError(
                    f"scope_coverage target {target_index} <{field}> must contain plain text only"
                )
            entry[field] = (child.text or "").strip()
            if (child.tail or "").strip():
                raise ValueError(
                    f"scope_coverage target {target_index} may contain only required child fields"
                )

        missing_fields = [field for field in _COVERAGE_FIELDS if field not in entry]
        if missing_fields:
            missing = ", ".join(f"<{field}>" for field in missing_fields)
            raise ValueError(
                f"scope_coverage target {target_index} is missing required field(s): {missing}"
            )
        if not entry["asset"]:
            raise ValueError(f"scope_coverage target {target_index} <asset> cannot be empty")
        entries.append(entry)
    return entries


def _normalize_exact_asset(value: str) -> str:
    """Normalize separators without case-folding case-sensitive asset paths."""
    raw = (value or "").strip()
    if raw != "/":
        raw = raw.rstrip("/")
    return raw


def _web_asset_parts(value: str) -> tuple[str, str, int | None, bool, str]:
    """Return (scheme, host, effective_port, explicit_port, normalized_path)."""
    raw = (value or "").strip()
    if not raw:
        return "", "", None, False, ""
    try:
        direct_ip = ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        # Unbracketed IP literals have no unambiguous port component.  Handle
        # them before urlparse mistakes IPv6 colons for a host/port separator.
        return "", str(direct_ip), None, False, "/"
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    scheme = parsed.scheme.lower()
    try:
        raw_host = (parsed.hostname or "").rstrip(".").lower()
    except ValueError:
        return "", "", None, False, ""
    try:
        host = str(ipaddress.ip_address(raw_host))
    except ValueError:
        try:
            host = raw_host.encode("idna").decode("ascii")
        except UnicodeError:
            return "", "", None, False, ""
    try:
        explicit_port = parsed.port
    except ValueError:
        return "", "", None, False, ""
    port = explicit_port
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    return scheme, host, port, explicit_port is not None, path


def _bare_ip_identity(value: str) -> str:
    """Return a canonical IP only when *value* is an unqualified IP literal."""
    raw = (value or "").strip()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def _ports_compatible(
    left: tuple[str, int | None, bool],
    right: tuple[str, int | None, bool],
) -> bool:
    """Treat scheme-less/default prose references as aliases, never non-default ports."""
    left_scheme, left_port, left_explicit = left
    right_scheme, right_port, right_explicit = right
    if left_port is not None and right_port is not None:
        return left_port == right_port

    known_scheme, known_port, known_explicit = (
        (left_scheme, left_port, left_explicit)
        if left_port is not None
        else (right_scheme, right_port, right_explicit)
    )
    if known_port is None:
        return True
    if not known_explicit:
        return True
    expected_default = {"http": 80, "https": 443}.get(known_scheme)
    if expected_default is not None:
        return known_port == expected_default
    return known_port in {80, 443}


def _asset_matches(  # noqa: PLR0911
    target_value: str,
    entry_asset: str,
    target_type: str = "web_application",
) -> bool:
    """Match coverage assets without unsafe substring comparisons.

    Repository and local-code targets preserve path case. Web assets require an
    exact scheme, host, and path. Equivalent default ports and trailing slashes
    canonicalize, but a scheme-less row cannot stand in for an explicit URL.
    """
    if target_type in {"repository", "local_code"}:
        target_exact = _normalize_exact_asset(target_value)
        entry_exact = _normalize_exact_asset(entry_asset)
        return bool(target_exact) and target_exact == entry_exact

    if target_type == "ip_address":
        target_ip = _bare_ip_identity(target_value)
        entry_ip = _bare_ip_identity(entry_asset)
        return bool(target_ip) and target_ip == entry_ip

    # A bare IP denotes a standalone network target, not an explicit web
    # application living at an IP URL.  Keep those two recognized identities
    # independently representable in scope_coverage.
    if _bare_ip_identity(entry_asset) and not _bare_ip_identity(target_value):
        return False

    target_scheme, target_host, target_port, _target_explicit_port, target_path = _web_asset_parts(
        target_value
    )
    entry_scheme, entry_host, entry_port, _entry_explicit_port, entry_path = _web_asset_parts(
        entry_asset
    )
    if not target_host or not entry_host or target_host != entry_host:
        return False
    if target_scheme != entry_scheme:
        return False
    # Schemes already match exactly, so their parsed effective ports must also
    # match exactly. In particular, a scheme-less host has no implicit default:
    # ``app.test`` and ``app.test:443`` are distinct coverage identities.
    if target_port != entry_port:
        return False
    return target_path == entry_path


def _target_identity(target: tuple[str, str]) -> tuple[Any, ...]:
    """Return a semantic identity used only to collapse equivalent targets."""
    target_type, value = target
    if target_type in {"web_application", "ip_address"}:
        scheme, host, port, _explicit_port, path = _web_asset_parts(value)
        return target_type, scheme, host, port, path
    if target_type in {"repository", "local_code"}:
        return target_type, _normalize_exact_asset(value)
    return target_type, value


def _dedupe_targets(targets: list[tuple[str, str]]) -> list[tuple[str, str]]:
    deduped: list[tuple[str, str]] = []
    seen: set[tuple[Any, ...]] = set()
    for target in targets:
        identity = _target_identity(target)
        if identity in seen:
            continue
        seen.add(identity)
        deduped.append(target)
    return deduped


def _resolve_coverage_entries(
    entries: list[dict[str, str]],
    recognized_targets: list[tuple[str, str]],
) -> _CoverageResolution:
    """Resolve coverage rows once for each semantic target identity."""
    return {
        _target_identity(target): [
            entry
            for entry in entries
            if _asset_matches(target[1], entry.get("asset", ""), target[0])
        ]
        for target in _dedupe_targets(recognized_targets)
    }


def _resolved_target_entries(
    resolution: _CoverageResolution,
    target: tuple[str, str],
) -> list[dict[str, str]]:
    return resolution.get(_target_identity(target), [])


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
        if status in {"excluded", "not_tested"} and auth != "not_applicable":
            errors.append(
                f"scope_coverage target '{asset}': status '{status}' requires "
                "authentication 'not_applicable'"
            )
    return errors


def _coverage_gaps(
    entries: list[dict[str, str]],
    authorized: list[tuple[str, str]],
    *,
    resolution: _CoverageResolution | None = None,
) -> tuple[list[str], list[str]]:
    """Return (unaccounted_target_values, not_tested_target_values)."""
    if resolution is None:
        resolution = _resolve_coverage_entries(entries, authorized)
    unaccounted: list[str] = []
    not_tested: list[str] = []
    for target in authorized:
        _target_type, value = target
        matched = _resolved_target_entries(resolution, target)
        if not matched:
            unaccounted.append(value)
        elif all(e.get("status") == "not_tested" for e in matched):
            not_tested.append(value)
    return unaccounted, not_tested


def _coverage_entry_gate(
    entries: list[dict[str, str]],
    recognized_targets: list[tuple[str, str]],
    *,
    resolution: _CoverageResolution,
) -> dict[str, Any] | None:
    """Require exactly one coverage row for exactly one recognized target."""
    unrecognized: list[str] = []
    ambiguous: list[tuple[str, list[str]]] = []
    targets = _dedupe_targets(recognized_targets)
    for entry in entries:
        asset = entry.get("asset", "")
        matched = [
            target for target in targets if entry in _resolved_target_entries(resolution, target)
        ]
        if not matched:
            unrecognized.append(asset)
        elif len(matched) > 1:
            ambiguous.append((asset, [value for _target_type, value in matched]))

    if unrecognized:
        return {
            "success": False,
            "error": "unrecognized_scope_coverage_asset",
            "message": (
                "Cannot finish scan: scope_coverage contains asset(s) that are not "
                "recognized structured or operator-declared targets:\n\n"
                + "\n".join(f"- {asset}" for asset in unrecognized)
                + "\n\nRemove these rows. Out-of-scope or incidental assets must not be "
                "reported as engagement coverage."
            ),
        }
    if ambiguous:
        details = "\n".join(
            f"- {asset}: matches {', '.join(targets)}" for asset, targets in ambiguous
        )
        return {
            "success": False,
            "error": "ambiguous_scope_coverage_asset",
            "message": (
                "Cannot finish scan: a scope_coverage row ambiguously matches more "
                "than one distinct target:\n\n"
                f"{details}\n\nUse each target's exact scheme, port, and path."
            ),
        }
    duplicates = [
        (target, [entry.get("asset", "") for entry in matched])
        for target in _dedupe_targets(recognized_targets)
        if len(matched := _resolved_target_entries(resolution, target)) > 1
    ]
    if duplicates:
        details = "\n".join(f"- {target[1]}: {', '.join(assets)}" for target, assets in duplicates)
        return {
            "success": False,
            "error": "duplicate_scope_coverage_target",
            "message": (
                "Cannot finish scan: more than one scope_coverage row maps to the "
                "same recognized target:\n\n"
                f"{details}\n\nConsolidate each target into exactly one coverage row."
            ),
        }
    return None


def _structured_exclusion_gate(
    scan_config: dict[str, Any] | None,
    authorized: list[tuple[str, str]],
    recognized_targets: list[tuple[str, str]],
    *,
    resolution: _CoverageResolution,
) -> dict[str, Any] | None:
    """Make reported exclusions agree with the operator's instructions."""
    instruction = (scan_config or {}).get("user_instructions", "") or ""
    explicitly_excluded = {
        target: instruction_excludes_asset(instruction, target[1])
        for target in dict.fromkeys([*recognized_targets, *authorized])
    }
    self_excluded: list[str] = []
    undocumented_exclusions: list[str] = []
    for target in recognized_targets:
        _target_type, value = target
        excluded_entries = [
            entry
            for entry in _resolved_target_entries(resolution, target)
            if entry.get("status") == "excluded"
        ]
        if excluded_entries and not explicitly_excluded[target]:
            self_excluded.append(value)
        if any(
            not (
                _EXCLUSION_NOTE_SOURCE_RE.search(entry.get("notes", ""))
                and _EXCLUSION_NOTE_ACTION_RE.search(entry.get("notes", ""))
            )
            for entry in excluded_entries
        ):
            undocumented_exclusions.append(value)
    if self_excluded:
        return {
            "success": False,
            "error": "structured_target_excluded_without_instruction",
            "message": (
                "Cannot finish scan: recognized target(s) were marked excluded "
                "without an explicit operator exclusion:\n\n"
                + "\n".join(f"- {value}" for value in self_excluded)
                + "\n\nTest each target or mark it not_tested with the factual reason. "
                "Only an explicit operator exclusion permits status 'excluded'."
            ),
        }
    if undocumented_exclusions:
        return {
            "success": False,
            "error": "excluded_target_note_missing_operator_basis",
            "message": (
                "Cannot finish scan: excluded target note(s) must summarize the "
                "operator/client rules-of-engagement exclusion:\n\n"
                + "\n".join(f"- {value}" for value in undocumented_exclusions)
                + "\n\nState that the operator/client instructions excluded or "
                "placed the target out of scope; a generic note such as 'Skipped' "
                "does not document the exclusion."
            ),
        }

    tested_exclusions: list[str] = []
    incorrectly_unexcluded: list[str] = []
    for target in authorized:
        _target_type, value = target
        if not explicitly_excluded[target]:
            continue
        rows = _resolved_target_entries(resolution, target)
        if any(
            entry.get("status") in {"tested_with_findings", "tested_no_findings"} for entry in rows
        ):
            tested_exclusions.append(value)
        if any(entry.get("status") != "excluded" for entry in rows):
            incorrectly_unexcluded.append(value)
    if tested_exclusions:
        return {
            "success": False,
            "error": "excluded_target_reported_as_tested",
            "message": (
                "Cannot finish scan: structured target(s) explicitly excluded by "
                "the operator were reported as tested:\n\n"
                + "\n".join(f"- {value}" for value in tested_exclusions)
                + "\n\nDo not test excluded assets. Report each with status 'excluded' "
                "and summarize the operator's exclusion in its notes."
            ),
        }
    if incorrectly_unexcluded:
        return {
            "success": False,
            "error": "excluded_target_not_marked_excluded",
            "message": (
                "Cannot finish scan: structured target(s) explicitly excluded by "
                "the operator must use status 'excluded':\n\n"
                + "\n".join(f"- {value}" for value in incorrectly_unexcluded)
                + "\n\nUse 'not_tested' only for authorized in-scope targets that "
                "could not be tested; an operator-excluded target must be reported "
                "as 'excluded'."
            ),
        }
    return None


def _instruction_declared_targets(
    scan_config: dict[str, Any] | None,
    authorized: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Return instruction-only application targets in the reconciler's order."""
    instruction = (scan_config or {}).get("user_instructions", "") or ""
    structured_values = []
    for target_type, value in authorized:
        if target_type in {"web_application", "ip_address"}:
            structured_values.append(value)
        elif target_type == "repository" and urlparse(value).scheme.lower() in {
            "http",
            "https",
        }:
            # Suppress only an instruction URL that is canonically identical to
            # the already-structured repository URL.  The reconciler's exact
            # origin/path identity still surfaces any distinct web target.
            structured_values.append(value)
    declared: list[tuple[str, str]] = []
    for value in reconcile_instruction_targets(structured_values, instruction):
        target_type = "ip_address" if _bare_ip_identity(value) else "web_application"
        declared.append((target_type, value))
    return declared


def _instruction_scope_gate(
    declared_missing: list[str],
) -> dict[str, Any] | None:
    """Block finish if an operator-declared in-scope asset is unaccounted for."""
    if not declared_missing:
        return None
    logger.warning(
        "[FINISH_SCAN] Blocking finish — %d operator-declared in-scope "
        "asset(s) unaccounted for in scope_coverage: %s",
        len(declared_missing),
        ", ".join(declared_missing),
    )
    asset_lines = "\n".join(f"- {value}" for value in declared_missing)
    return {
        "success": False,
        "error": "instruction_declared_asset_unaccounted",
        "message": (
            "Cannot finish scan: the following asset(s) were named as "
            "in-scope in the operator's own rules of engagement but are "
            "missing from scope_coverage. These are authorized for this "
            "engagement and cannot be silently dropped just because they "
            "were not entered as structured targets:\n\n"
            f"{asset_lines}\n\n"
            "ACTION REQUIRED: Test each asset now (spawn dedicated "
            "sub-agents if needed), then add a <target> block for it to "
            "scope_coverage with <asset>, <status>, <authentication>, and "
            "<notes>. If an asset is unreachable, still add its <target> "
            "block with status 'not_tested' and a clear reason in <notes>. "
            "Use status 'excluded' only when the operator explicitly "
            "excluded that asset in the rules of engagement."
        ),
    }


def _report_auth_contradiction_gate(
    scan_config: dict[str, Any] | None,
    entries: list[dict[str, str]],
    recognized_targets: list[tuple[str, str]],
    *,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
    limitations: str,
    resolution: _CoverageResolution,
) -> dict[str, Any] | None:
    """Hard-block factual no-credential claims anywhere in the shipped report."""
    instruction = (scan_config or {}).get("user_instructions", "") or ""
    if not any(
        not _NEGATIVE_AUTH_SEGMENT_RE.search(segment) and detect_auth_expectation(segment)
        for segment in _split_auth_segments(instruction)
    ):
        return None

    auth_targets = _auth_requirement_targets(scan_config, recognized_targets)
    applicable_targets = [
        target for target in recognized_targets if target[0] in {"web_application", "ip_address"}
    ]
    contradiction = False
    for text in (
        executive_summary,
        methodology,
        technical_analysis,
        recommendations,
        limitations,
    ):
        for segment in _split_auth_segments(text):
            if not (
                report_claims_no_credentials(segment)
                or _NO_CREDENTIALS_AUTH_PHASE_RE.search(segment)
            ):
                continue
            if _describes_distinct_mixed_auth_phases(segment):
                continue
            referenced = _referenced_targets(segment, applicable_targets)
            if not referenced or any(target in auth_targets for target in referenced):
                contradiction = True
                break
        if contradiction:
            break

    if not contradiction:
        for entry in entries:
            note = entry.get("notes", "")
            if not (
                report_claims_no_credentials(note) or _NO_CREDENTIALS_AUTH_PHASE_RE.search(note)
            ):
                continue
            row_targets = [
                target
                for target in applicable_targets
                if entry in _resolved_target_entries(resolution, target)
            ]
            referenced_targets = _referenced_targets(note, applicable_targets)
            attributed_targets = referenced_targets or row_targets
            if any(target in auth_targets for target in attributed_targets):
                contradiction = True
                break

    if contradiction:
        logger.warning(
            "[FINISH_SCAN] Blocking finish — report asserts no-credentials/"
            "black-box but operator authorized credentials / required auth."
        )
        return {
            "success": False,
            "error": "report_contradicts_operator_auth",
            "message": (
                "Cannot finish scan: the operator's rules of engagement "
                "provided credentials authorized for use and/or required "
                "authenticated testing, "
                "but the report describes the engagement as unauthenticated / "
                "black-box or states that no credentials were provided. That "
                "is inaccurate and cannot ship.\n\n"
                "ACTION REQUIRED: Perform the authenticated testing using the "
                "credentials authorized for use and update the report to reflect it. If "
                "authentication was genuinely blocked (e.g. OTP/MFA you could "
                "not access), remove the 'black-box'/'no credentials' framing "
                "and instead document the specific blocker in the limitations "
                "and in the affected scope_coverage <notes>, then call "
                "finish_scan again."
            ),
        }

    return None


def _describes_distinct_mixed_auth_phases(text: str) -> bool:
    """Allow black-box wording only for an explicit unauthenticated phase."""
    no_credentials_claim = report_claims_no_credentials(text)
    return bool(
        not _NO_CREDENTIALS_AUTH_PHASE_RE.search(text)
        and (not no_credentials_claim or _NO_CREDENTIALS_UNAUTH_PHASE_RE.search(text))
        and _UNAUTHENTICATED_PHASE_RE.search(text)
        and _AUTHENTICATED_PHASE_RE.search(text)
        and _PHASE_RELATION_RE.search(text)
    )


def _reference_tokens(text: str) -> list[str]:
    """Extract URL/host-shaped whitespace tokens while ignoring email domains."""
    tokens: list[str] = []
    sanitized = _EMAIL_TOKEN_RE.sub(" ", text)
    for raw_token in sanitized.split():
        token = raw_token.strip("\t\r\n ,;!?<>\"'").lstrip("({")
        token = token.rstrip(".,;!?")
        for opener, closer in (("(", ")"), ("{", "}"), ("[", "]")):
            while token.endswith(closer) and token.count(closer) > token.count(opener):
                token = token[:-1].rstrip(".,;!?")
        if token.endswith(":"):
            try:
                ipaddress.ip_address(token)
            except ValueError:
                token = token[:-1]
        lowered_token = token.lower()
        scheme_index = min(
            (
                index
                for marker in ("http://", "https://")
                if (index := lowered_token.find(marker)) >= 0
            ),
            default=-1,
        )
        if scheme_index > 0:
            token = token[scheme_index:]
        if token:
            tokens.append(token)
    return tokens


def _reference_token_has_explicit_path(token: str) -> bool:
    authority_and_path = token.split("://", 1)[-1]
    return "/" in authority_and_path


def _reference_token_matches_target(target_value: str, token: str) -> bool:
    target_scheme, target_host, target_port, target_explicit_port, target_path = _web_asset_parts(
        target_value
    )
    if not target_host:
        return False
    (
        candidate_scheme,
        candidate_host,
        candidate_port,
        candidate_explicit_port,
        candidate_path,
    ) = _web_asset_parts(token)
    if candidate_host != target_host:
        return False
    if target_scheme and candidate_scheme and target_scheme != candidate_scheme:
        return False
    if not _ports_compatible(
        (target_scheme, target_port, target_explicit_port),
        (candidate_scheme, candidate_port, candidate_explicit_port),
    ):
        return False
    # A scheme-less bare host is an intentionally ambiguous host-level
    # reference. An explicit URL, including an explicit root URL, is exact.
    if (
        candidate_path == "/"
        and not candidate_scheme
        and not _reference_token_has_explicit_path(token)
    ):
        return True
    return candidate_path == target_path


def _located_reference_tokens(text: str) -> list[tuple[str, int, int]]:
    """Return normalized reference tokens with best-effort spans in source text."""
    located: list[tuple[str, int, int]] = []
    lowered = text.lower()
    cursor = 0
    for token in _reference_tokens(text):
        start = lowered.find(token.lower(), cursor)
        if start < 0:
            start = lowered.find(token.lower())
        if start < 0:
            continue
        end = start + len(token)
        located.append((token, start, end))
        cursor = end
    return located


def _looks_like_explicit_target_reference(token: str) -> bool:
    scheme, host, _port, _explicit_port, _path = _web_asset_parts(token)
    if not host:
        return False
    if scheme:
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        return len(labels) > 1 and len(labels[-1]) > 1
    return True


def _segment_has_explicit_target_reference(
    segment: str,
    recognized_targets: list[tuple[str, str]],
) -> bool:
    """Distinguish a targeted auth clause from credentials containing dotted values."""
    if _referenced_targets(segment, recognized_targets):
        return True
    for token, start, _end in _located_reference_tokens(segment):
        if not _looks_like_explicit_target_reference(token):
            continue
        scheme, host, _port, _explicit_port, _path = _web_asset_parts(token)
        if scheme or _bare_ip_identity(token):
            return True
        prefix = segment[max(0, start - 32) : start]
        if host and re.search(
            r"\b(?:against|at|for|of|on|through|to|via)\s*$",
            prefix,
            re.IGNORECASE,
        ):
            return True
        if host and re.search(
            r"\b(?:test|scan|assess|authenticate|login|log[-\s]?in|sign[-\s]?in)\s*$",
            prefix,
            re.IGNORECASE,
        ):
            return True
    return False


def _has_foreign_target_reference(
    text: str,
    targets: list[tuple[str, str]],
) -> bool:
    return any(
        _looks_like_explicit_target_reference(token)
        and not any(_reference_token_matches_target(target[1], token) for target in targets)
        for token in _reference_tokens(text)
    )


def _split_auth_segments(text: str) -> list[str]:
    return [segment.strip() for segment in _AUTH_SEGMENT_SPLIT_RE.split(text) if segment.strip()]


def _referenced_targets(
    text: str,
    targets: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    tokens = _reference_tokens(text)
    return [
        target
        for target in targets
        if any(_reference_token_matches_target(target[1], token) for token in tokens)
    ]


def _unambiguous_referenced_targets_in_text(
    text: str,
    targets: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Return explicitly referenced targets in textual order, or empty if ambiguous."""
    ordered: list[tuple[str, str]] = []
    for token in _reference_tokens(text):
        matched = [
            target for target in targets if _reference_token_matches_target(target[1], token)
        ]
        if len(matched) > 1:
            return []
        if len(matched) == 1 and matched[0] not in ordered:
            ordered.append(matched[0])
    return ordered


def _foreign_segment_explicitly_affects_target(
    segment: str,
    target: tuple[str, str],
) -> bool:
    """Reject an incidental in-scope mention beside a foreign target's blocker."""
    for token, start, end in _located_reference_tokens(segment):
        if not _reference_token_matches_target(target[1], token):
            continue
        prefix = segment[max(0, start - 120) : start]
        suffix = segment[end : end + 120]
        if _INCIDENTAL_TARGET_PREFIX_RE.search(prefix):
            continue
        if _AFFECTED_TARGET_PREFIX_RE.search(prefix) or _AFFECTED_TARGET_SUFFIX_RE.search(suffix):
            return True
    return False


def _targets_form_shared_blocker_list(
    segment: str,
    referenced: list[tuple[str, str]],
) -> bool:
    """Recognize one causal blocker explicitly shared by a conjoined target list."""
    if len(referenced) < 2:
        return False
    if _DISTINCT_BLOCKER_MARKER_RE.search(segment):
        return False

    occurrences: list[tuple[tuple[str, str], int, int]] = []
    for token, start, end in _located_reference_tokens(segment):
        for candidate in referenced:
            if _reference_token_matches_target(candidate[1], token):
                occurrences.append((candidate, start, end))
                break

    wanted = set(referenced)
    for first_index, (_first_target, first_start, _first_end) in enumerate(occurrences):
        grouped: set[tuple[str, str]] = set()
        previous_end: int | None = None
        for candidate, _start, end in occurrences[first_index:]:
            if candidate in grouped:
                break
            if previous_end is not None:
                joiner = segment[previous_end:_start]
                if not _TARGET_LIST_JOIN_RE.fullmatch(joiner):
                    break
            grouped.add(candidate)
            previous_end = end
            if grouped != wanted:
                continue
            prefix = segment[max(0, first_start - 80) : first_start]
            suffix = segment[previous_end : previous_end + 120]
            if re.search(
                r"\b(?:for|to|on|across|affect(?:ed|ing))\s*$",
                prefix,
                re.IGNORECASE,
            ) or _SHARED_TARGET_GROUP_EFFECT_RE.search(suffix):
                return True

    target_limited = any(
        re.fullmatch(
            r"\s*(?:(?:for|on|at|to)\s+)?",
            segment[limiter.end() : target_start],
            re.IGNORECASE,
        )
        for limiter in _LIMITED_BLOCKER_MARKER_RE.finditer(segment)
        for _candidate, target_start, _target_end in occurrences
        if limiter.end() <= target_start
    )
    return bool(not target_limited and _SHARED_BLOCKER_EFFECT_RE.search(segment))


def _segment_attributed_to_target(
    segment: str,
    target: tuple[str, str],
    targets: list[tuple[str, str]],
    *,
    explicit_reference_required: bool,
) -> bool:
    referenced = _referenced_targets(segment, targets)
    if _has_foreign_target_reference(segment, targets):
        # A causal sentence may name the affected in-scope target and an
        # external identity-provider URL.  A foreign-only blocker still cannot
        # be attributed to an in-scope target by implication.
        return referenced == [target] and _foreign_segment_explicitly_affects_target(
            segment, target
        )
    if not referenced:
        return not explicit_reference_required
    return referenced == [target]


def _limitations_document_target_blocker(
    analysis: _ReferenceAnalysis,
    target: tuple[str, str],
    auth_targets: list[tuple[str, str]],
    *,
    target_reference_required: bool,
) -> bool:
    """Require a causal blocker in limitations, tied to the target when ambiguous."""
    narrowed_shared_segments: set[int] = set()
    for index in range(1, len(analysis)):
        qualifier, qualifier_targets = analysis[index]
        if not (
            _LIMITED_AUTH_EFFECT_RE.search(qualifier) or _LIMITED_TARGET_INTRO_RE.search(qualifier)
        ):
            continue
        previous_targets = analysis[index - 1][1]
        if (
            qualifier_targets
            and target not in qualifier_targets
            and target in previous_targets
            and len(previous_targets) > 1
        ):
            narrowed_shared_segments.add(index - 1)

    for index, (segment, referenced) in enumerate(analysis):
        if index in narrowed_shared_segments:
            continue
        if not report_documents_auth_blocker(segment):
            continue
        if _segment_attributed_to_target(
            segment,
            target,
            auth_targets,
            explicit_reference_required=target_reference_required,
        ):
            return True
        if (
            target in referenced
            and len(referenced) > 1
            and not _has_foreign_target_reference(segment, auth_targets)
            and _targets_form_shared_blocker_list(segment, referenced)
        ):
            return True
    return False


def _note_documents_target_blocker(
    note: str,
    target: tuple[str, str],
    auth_targets: list[tuple[str, str]],
) -> bool:
    return report_documents_auth_blocker(note) and _segment_attributed_to_target(
        note,
        target,
        auth_targets,
        explicit_reference_required=False,
    )


def _anaphoric_auth_prohibition_targets(
    segment: str,
    previous_targets: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Resolve terminal former/latter account prohibitions conservatively."""
    if len(previous_targets) < 2:
        return []
    match = _ACCOUNT_SELECTOR_PROHIBITION_RE.search(segment)
    if match is None:
        return []
    index = -1 if match.group("selector").lower() == "latter" else 0
    return [previous_targets[index]]


def _auth_requirement_targets(
    scan_config: dict[str, Any] | None,
    recognized_targets: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Return targets affected by the operator's authentication requirement.

    When an auth-positive clause names one or more recognized targets, only
    those targets inherit that requirement.  A generic engagement-level auth
    mandate applies to all applicable web targets unless it explicitly says all
    targets/assets/systems, in which case standalone IP targets also participate.
    """
    instruction = (scan_config or {}).get("user_instructions", "") or ""
    candidates = [
        target
        for target in recognized_targets
        if target[0] in {"web_application", "ip_address"}
        and not instruction_excludes_asset(instruction, target[1])
    ]
    web_candidates = [target for target in candidates if target[0] == "web_application"]
    specifically_named: list[tuple[str, str]] = []
    explicitly_negated: list[tuple[str, str]] = []
    generic_web_mandate = False
    generic_all_target_mandate = False
    last_explicit_positive_targets: list[tuple[str, str]] = []

    for segment in _split_auth_segments(instruction):
        referenced = _referenced_targets(segment, candidates)
        has_explicit_target_reference = _segment_has_explicit_target_reference(
            segment,
            recognized_targets,
        )
        if _NEGATIVE_AUTH_SEGMENT_RE.search(segment):
            negated_targets = referenced or _anaphoric_auth_prohibition_targets(
                segment,
                last_explicit_positive_targets,
            )
            for target in negated_targets:
                if target not in explicitly_negated:
                    explicitly_negated.append(target)
            continue
        if not detect_auth_expectation(segment):
            continue
        last_explicit_positive_targets = _unambiguous_referenced_targets_in_text(
            segment,
            candidates,
        )
        if _GENERIC_ALL_TARGET_AUTH_RE.search(segment):
            generic_all_target_mandate = True
        elif _GENERIC_AUTH_SEGMENT_RE.search(segment) or (
            not referenced and not has_explicit_target_reference
        ):
            generic_web_mandate = True
        for target in referenced:
            if target not in specifically_named:
                specifically_named.append(target)

    required = [*specifically_named]
    if generic_web_mandate:
        required.extend(web_candidates)
    if generic_all_target_mandate:
        required.extend(candidates)
    return list(dict.fromkeys(target for target in required if target not in explicitly_negated))


def _auth_coverage_gate(
    scan_config: dict[str, Any] | None,
    recognized_targets: list[tuple[str, str]],
    limitations: str,
    *,
    resolution: _CoverageResolution,
) -> dict[str, Any] | None:
    """Require authenticated coverage or a two-location blocker per application."""
    auth_targets = _auth_requirement_targets(scan_config, recognized_targets)
    if not auth_targets:
        return None
    attribution_targets = [
        target for target in recognized_targets if target[0] in {"web_application", "ip_address"}
    ]
    limitation_analysis = [
        (segment, _referenced_targets(segment, attribution_targets))
        for segment in _split_auth_segments(limitations)
    ]
    missing: list[tuple[str, bool, bool]] = []

    for target in auth_targets:
        _target_type, value = target
        _target_scheme, target_host, _target_port, _target_explicit_port, _target_path = (
            _web_asset_parts(value)
        )
        target_reference_required = len(auth_targets) > 1 or any(
            other != target and _web_asset_parts(other[1])[1] == target_host
            for other in attribution_targets
        )
        matched = _resolved_target_entries(resolution, target)
        authenticated = any(
            entry.get("status") in {"tested_with_findings", "tested_no_findings"}
            and entry.get("authentication") in {"authenticated", "both"}
            for entry in matched
        )
        if authenticated:
            continue

        # A target the agent asserts it could not test at all (every row is
        # not_tested, which already requires a factual reason in <notes> and has
        # passed the one-time not_tested soft guard) does not additionally
        # require an authentication-specific blocker. Demanding auth-blocker
        # wording here permanently blocks an honest "host unreachable" / "DNS
        # failed" reason, since a network-level cause is not an auth blocker and
        # not_tested rows are forced to authentication='not_applicable'.
        if matched and all(entry.get("status") == "not_tested" for entry in matched):
            continue

        note_has_blocker = any(
            _note_documents_target_blocker(entry.get("notes", ""), target, attribution_targets)
            for entry in matched
        )
        limitations_has_blocker = _limitations_document_target_blocker(
            limitation_analysis,
            target,
            attribution_targets,
            target_reference_required=target_reference_required,
        )
        if not (note_has_blocker and limitations_has_blocker):
            missing.append((value, note_has_blocker, limitations_has_blocker))

    if missing:
        detail_lines = []
        for value, note_has_blocker, limitations_has_blocker in missing:
            missing_locations = []
            if not note_has_blocker:
                missing_locations.append("the matching scope_coverage <notes>")
            if not limitations_has_blocker:
                missing_locations.append("limitations")
            detail_lines.append(f"- {value}: missing " + " and ".join(missing_locations))
        logger.warning(
            "[FINISH_SCAN] Blocking finish — authenticated coverage missing for: %s",
            ", ".join(value for value, _note, _limitations in missing),
        )
        return {
            "success": False,
            "error": "authenticated_coverage_missing",
            "message": (
                "The operator provided credentials authorized for use and/or required "
                "authenticated testing, but these recognized target(s) have "
                "neither authenticated coverage nor a fully documented "
                "authentication blocker:\n\n"
                + "\n".join(detail_lines)
                + "\n\nACTION REQUIRED: Attempt authenticated testing with the "
                "accounts authorized for use (role comparison, access-control, session, "
                "and business-logic testing) and set each relevant "
                "<authentication> to 'authenticated' or 'both'. If login is "
                "genuinely blocked by a factor outside tester control, document "
                "the causal blocker in BOTH that target's scope_coverage "
                "<notes> and the report limitations. Repeating finish_scan "
                "without changing the report will remain blocked."
            ),
        }

    return None


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
            _finish_scan_attempts[current_agent_id] = (
                _finish_scan_attempts.get(current_agent_id, 0) + 1
            )
            attempts = _finish_scan_attempts[current_agent_id]

            # After N failed attempts, force-stop all sub-agents
            if attempts >= _MAX_ATTEMPTS_BEFORE_FORCE:
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

        # A completed wave must reset the retry budget before any later wave
        # starts in the same scan.
        _finish_scan_attempts.pop(current_agent_id, None)

    except ImportError:
        pass
    except Exception:
        logging.exception("Error checking active agents")

    return None


@register_tool(sandbox_execution=False)
def finish_scan(  # noqa: PLR0911, PLR0912, PLR0915
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

    coverage_parse_error = False
    try:
        coverage_entries = _parse_scope_coverage(scope_coverage)
    except ValueError as exc:
        coverage_entries = []
        coverage_parse_error = True
        validation_errors.append(str(exc))
    if not coverage_entries and not coverage_parse_error:
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
            scan_agent_key = (str(tracer.run_id), str(agent_id))
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
            instruction_targets = _instruction_declared_targets(tracer.scan_config, authorized)
            recognized_targets = _dedupe_targets([*authorized, *instruction_targets])
            coverage_resolution = _resolve_coverage_entries(
                coverage_entries,
                recognized_targets,
            )
            unaccounted, not_tested = _coverage_gaps(
                coverage_entries,
                authorized,
                resolution=coverage_resolution,
            )

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
                        "<notes>. If an asset is unreachable, still add its <target> "
                        "block with status 'not_tested' and a clear reason in <notes>. "
                        "Use status 'excluded' only when the operator explicitly "
                        "excluded that asset in the rules of engagement."
                    ),
                }

            # ── Instruction-declared scope gate ──────────────────────
            # Assets the operator named as in-scope in their own rules of
            # engagement (free text) but that never became structured targets
            # must still be accounted for. Without this, a second approved app
            # mentioned only in the instructions is silently dropped and no gate
            # ever notices (the structured gate above only sees structured
            # targets). Derived solely from the operator-authored instructions.
            instruction_missing, instruction_not_tested = _coverage_gaps(
                coverage_entries,
                instruction_targets,
                resolution=coverage_resolution,
            )
            declared_error = _instruction_scope_gate(instruction_missing)
            if declared_error:
                return declared_error

            not_tested = list(dict.fromkeys([*not_tested, *instruction_not_tested]))

            coverage_entry_error = _coverage_entry_gate(
                coverage_entries,
                recognized_targets,
                resolution=coverage_resolution,
            )
            if coverage_entry_error:
                return coverage_entry_error

            structured_exclusion_error = _structured_exclusion_gate(
                tracer.scan_config,
                authorized,
                recognized_targets,
                resolution=coverage_resolution,
            )
            if structured_exclusion_error:
                return structured_exclusion_error

            # A factual contradiction is a hard error even when authentication
            # was genuinely blocked. Check every field that will be shipped,
            # including limitations and scope-coverage notes.
            contradiction_error = _report_auth_contradiction_gate(
                tracer.scan_config,
                coverage_entries,
                recognized_targets,
                executive_summary=executive_summary,
                methodology=methodology,
                technical_analysis=technical_analysis,
                recommendations=recommendations,
                limitations=limitations,
                resolution=coverage_resolution,
            )
            if contradiction_error:
                return contradiction_error

            # ── Untested-target soft guard ───────────────────────────
            # If any approved target is marked not_tested, bounce ONCE to
            # push for coverage; allow through on retry so a scan can still
            # complete with the limitation clearly documented in the report.
            if not_tested and scan_agent_key not in _incomplete_coverage_warned:
                _incomplete_coverage_warned.add(scan_agent_key)
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

            # ── Report-accuracy / authenticated-testing gates ────────
            # When the operator authorized credentials or mandated authenticated
            # testing, the report must not misrepresent the engagement.
            auth_error = _auth_coverage_gate(
                tracer.scan_config,
                recognized_targets,
                limitations,
                resolution=coverage_resolution,
            )
            if auth_error:
                return auth_error

            # ── Zero-findings guard ──────────────────────────────────
            # On the FIRST finish_scan call with 0 findings, bounce the
            # agent back so it has a chance to call
            # create_vulnerability_report.  Allow through on retry so
            # scans that genuinely find nothing can still complete.
            if vulnerability_count == 0 and scan_agent_key not in _zero_findings_warned:
                _zero_findings_warned.add(scan_agent_key)
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
        return {  # noqa: TRY300
            "success": False,
            "message": "Cannot complete scan — tracer unavailable, results not stored",
        }

    except (ImportError, AttributeError) as e:
        logger.exception("[FINISH_SCAN] EXCEPTION")
        return {"success": False, "message": f"Failed to complete scan: {e!s}"}
