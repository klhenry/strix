"""Reconcile operator free-text instructions against the structured scan scope.

The operator's rules-of-engagement text (``scan_config["user_instructions"]``) is a
second source of scope truth alongside the structured ``targets`` list.  These
helpers deliberately accept only explicit, positive scope declarations from that
text.  Merely mentioning a host -- especially in an exclusion or reference -- must
never authorize it.

All functions in this module operate only on operator-authored text.  Content found
during testing (HTTP responses, DOM text, files, or tool output) never reaches the
scope-extraction functions, preserving the prompt-injection trust boundary.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlparse


if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


__all__ = [
    "detect_auth_expectation",
    "extract_instruction_targets",
    "instruction_excludes_asset",
    "normalize_host",
    "reconcile_instruction_targets",
    "report_claims_no_credentials",
    "report_documents_auth_blocker",
]


_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
_SSH_REPOSITORY_RE = re.compile(
    r"(?<![\w@])(?:"
    r"[a-z0-9._-]+@[a-z0-9.-]+:[^\s\"'<>]+"
    r"|ssh://[^\s\"'<>]+"
    r")",
    re.IGNORECASE,
)
_LOCAL_PATH_RE = re.compile(
    r"(?<![\w:/])(?:"
    r"(?:/|\.{1,2}/|~/|[a-z]:[\\/])[^\s\"'<>]+"
    r"|(?:[a-z0-9_-]+/)+[^\s\"'<>]+"
    r")",
    re.IGNORECASE,
)
_SCHEMELESS_HOST_PATH_RE = re.compile(
    r"(?<![\w@.-])(?:"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\.?(?::\d{1,5})?"
    r"|(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?"
    r"|\[[0-9a-f:.%]+\](?::\d{1,5})?"
    r")/[^\s\"'<>]+",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[\w.!#$%&'*+/=?^`{|}~-]+@"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}\b",
    re.IGNORECASE,
)
_HANDLE_RE = re.compile(r"(?<!\w)@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", re.IGNORECASE)
_FQDN_RE = re.compile(
    r"(?<![\w@.-])"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?(?::\d{1,5})?\.?"
    r"(?![\w.-])",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\.?(?![\w.])")
_BRACKETED_IPV6_RE = re.compile(r"\[[0-9a-f:.%]+\](?::\d{1,5})?", re.IGNORECASE)
# Intentionally broad: ipaddress.ip_address performs the authoritative validation.
# Requiring two colons keeps ordinary key:value prose out of the candidate set.
_BARE_IPV6_RE = re.compile(
    r"(?<![\w:])(?:[0-9a-f.]*:[0-9a-f:.%]*:[0-9a-f:.%]*)(?![\w:])",
    re.IGNORECASE,
)

_FILE_EXT_TLDS = frozenset(
    {
        "aspx",
        "class",
        "css",
        "go",
        "htm",
        "html",
        "jar",
        "java",
        "js",
        "json",
        "jsp",
        "jsx",
        "md",
        "php",
        "py",
        "rb",
        "ts",
        "tsx",
        "txt",
        "xml",
        "yaml",
        "yml",
    }
)

_POSITIVE_SCOPE_SECTION_RE = re.compile(
    r"^(?:the\s+following\s+)?(?:"
    r"in[-\s\u2010-\u2015]?scope(?:\s+(?:applications?|apps?|assets?|hosts?|targets?))?"
    r"|authorized\s+(?:applications?|apps?|assets?|hosts?|targets?)"
    r"|targets?\s+in[-\s]?scope"
    # Bare asset-list section headers ("Targets:", "Scope:", "Assets:", "URLs:",
    # "Applications:"). Real rules of engagement list in-scope hosts beneath such
    # a heading rather than embedding a scope verb in each line.
    r"|(?:targets?|scope|assets?|urls?|hosts?|domains?|systems?|environments?"
    r"|endpoints?|sites?|applications?|apps?|web\s+applications?)"
    r")\s*(?::|$)",
    re.IGNORECASE,
)
_EXCLUSION_SCOPE_SECTION_RE = re.compile(
    r"^(?:the\s+following\s+)?(?:"
    r"out[-\s\u2010-\u2015]?of[-\s\u2010-\u2015]?scope"
    r"(?:\s+(?:applications?|apps?|assets?|hosts?|targets?))?"
    r"|excluded\s+(?:applications?|apps?|assets?|hosts?|targets?)"
    r"|exclusions?"
    r")\s*(?::|$)",
    re.IGNORECASE,
)
_REFERENCE_SCOPE_SECTION_RE = re.compile(
    r"^(?:references?|reference[-\s]+only|documentation|docs?|background|resources?)\s*"
    r"(?::|$)",
    re.IGNORECASE,
)
_OTHER_SECTION_RE = re.compile(
    r"^(?:credentials?|accounts?|authentication|authorization|contacts?|notes?|"
    r"limitations?|objectives?|rules?|testing\s+requirements?|deliverables?)\s*:",
    re.IGNORECASE,
)
# A generic labelled heading ("Additional resources:", "Background information:")
# that is neither a positive nor exclusion scope section. Any authorized-section
# state must terminate here so hosts listed under an unknown label are never
# authorized by inheritance. The label is restricted to plain words and the
# colon must be followed by whitespace or end-of-line, so a URL scheme
# ("https://..."), a host:port token, or an ordinary sentence with a mid-clause
# colon (e.g. "... but not in scope: admin.test") can never match.
_GENERIC_HEADING_RE = re.compile(
    r"^(?:the\s+following\s+)?[a-z][a-z /&-]*:(?:\s|$)",
    re.IGNORECASE,
)
_NEGATIVE_SCOPE_RE = re.compile(
    r"\b(?:"
    r"out[-\s\u2010-\u2015]?of[-\s\u2010-\u2015]?scope|outside\s+(?:the\s+)?scope|"
    r"not\s+in[-\s\u2010-\u2015]?scope"
    r"|(?:but\s+not|except(?:\s+for)?|other\s+than)(?:\s+(?:test|scan|assess|audit))?"
    r"|(?:do\s+not|don['\u2019]t)\s+(?:(?:ever|under\s+any\s+circumstances)\s+)?"
    r"(?:(?:attempt|try)\s+to\s+)?"
    r"(?:test|scan|assess|audit|attack|target|touch|use|include)"
    r"|(?:do\s+not|don['\u2019]t)\s+(?:ever\s+|perform\s+)?"
    r"(?:testing|scanning|assessment|auditing|targeting)(?:\s+(?:of|on|against))?"
    r"|(?:did\s+not|didn['\u2019]t)\s+(?:(?:attempt|try)\s+to\s+)?"
    r"(?:test|scan|assess|audit|attack|target|touch|include)"
    r"|(?:failed|fails|unable)\s+to\s+(?:test|scan|assess|audit|target|touch)"
    r"|(?:unnecessary|not\s+necessary|not\s+required|impossible)\s+to\s+"
    r"(?:test|scan|assess|audit|target|touch)"
    r"|(?:must|should)\s+not\s+(?:test|scan|assess|audit|attack|target|touch|use)"
    r"|never\b[^\n]{0,80}\b(?:test|scan|assess|audit|attack|target|touch|use)"
    r"|(?:skip|omit|avoid)(?:\s+(?:testing|scanning|assessing|auditing|targeting))?"
    r"|(?:exclude|excludes|excluded|excluding|exclusion)"
    r"|no\s+(?:testing|scanning|assessment|auditing|targeting)\s+(?:of|on|against|for)"
    r"|not\s+authorized\s+to\s+(?:test|scan|assess|audit|target|touch)"
    r"|under\s+no\s+circumstances\s+(?:should\s+you\s+)?"
    r"(?:test|scan|assess|audit|target|touch)"
    r"|(?:testing|scanning|assessment|auditing)\b[^\n]{0,160}\b"
    r"(?:(?:is|was)\s+)?(?:forbidden|prohibited|not\s+(?:authorized|permitted|allowed))"
    r"|(?:forbidden|not\s+(?:permitted|allowed|authorized))\s+to\s+"
    r"(?:test|scan|assess|audit|target|touch)"
    r"|off[-\s]+limits"
    r"|reference[-\s]+only|for\s+reference\s+only|informational\s+only"
    r"|not\s+(?:an?\s+)?authorized\s+(?:target|asset|host|application)"
    r")\b",
    re.IGNORECASE,
)
_PLAIN_NEGATIVE_SCOPE_RE = re.compile(
    r"^(?:but\s+)?not\b|^(?:except(?:\s+for)?|with\s+the\s+exception\s+of|"
    r"excluding|other\s+than)\b",
    re.IGNORECASE,
)
_SCOPE_BOUNDARY_RE = re.compile(
    r"\b(?:"
    r"(?:do\s+not|don['\u2019]t)\s+(?:test|scan|assess|audit|target|touch)\s+"
    r"(?:anything|any\s+(?:asset|host|target|application))\s+"
    r"(?:outside(?:\s+of)?|other\s+than|except(?:\s+for)?)"
    r"|(?:test|scan|assess|audit|target|touch)\s+nothing\s+"
    r"(?:except(?:\s+for)?|other\s+than)"
    r"|everything\s+except(?:\s+for)?\b[^;!?\n]{0,160}\b"
    r"out[-\s\u2010-\u2015]?of[-\s\u2010-\u2015]?scope"
    r"|out[-\s\u2010-\u2015]?of[-\s\u2010-\u2015]?scope\s*:\s*"
    r"everything\s+except(?:\s+for)?"
    r")\b",
    re.IGNORECASE,
)
_ACTIVITY_LOCATION_OBJECT_RE = re.compile(
    r"\b(?:test(?:ing)?|scan(?:ning)?|assess(?:ing)?|audit(?:ing)?|"
    r"attack(?:ing)?|target(?:ing)?|touch(?:ing)?|use|exclude|skip|omit|avoid)\s+"
    r"(?P<object>[^.;!?\n]{1,160}?)\s+(?:on|against|at)\s*$",
    re.IGNORECASE,
)
_NOMINAL_ACTIVITY_LOCATION_OBJECT_RE = re.compile(
    r"\b(?:do\s+not|don['\u2019]t|must\s+not|should\s+not|never)\s+perform\s+"
    r"(?P<object>[^.;!?\n]{1,160}?)\s+"
    r"(?:testing|scanning|assessment|auditing|attacks?|targeting)\s+"
    r"(?:on|against|at)\s*$",
    re.IGNORECASE,
)
_WHOLE_ASSET_ACTIVITY_OBJECT_RE = re.compile(
    r"(?:(?:any|all|the|this|that|these|those|whole|entire)\s+)*"
    r"(?:anything|everything|things?|testing|scanning|assessment|auditing|targeting|"
    r"applications?|apps?|assets?|hosts?|targets?|sites?|systems?|services?|endpoints?)"
    r"(?:\s+(?:else|itself))?",
    re.IGNORECASE,
)
_ACTIVITY_QUALIFIER_PATTERN = (
    r"(?:"
    r"denial[-\s]?of[-\s]?service|d?dos|brute[-\s]?force|credential[-\s]?stuffing|"
    r"password[-\s]?(?:spraying|guessing)|sql[-\s]?injection|sqli|xss|"
    r"fuzz(?:ing)?|load[-\s]?testing|stress[-\s]?testing|destructive[-\s]?testing|"
    r"authentication|log[-\s]?in|admin(?:istration)?|payment|account[-\s]?deletion|"
    r"production[-\s]?data|features?|functions?|functionality|workflows?|processing"
    r")"
)
_POSTFIX_ACTIVITY_RESTRICTION_RE = re.compile(
    rf"^\s+(?:"
    rf"on\s+(?:(?:tcp|udp)\s+)?ports?(?:\s+(?:number\s+)?\d{{1,5}})?\b|"
    rf"as\s+(?:an?\s+)?(?:callback|redirect|webhook)\s+(?:endpoint|url|target|host)\b|"
    rf"for\s+[^.;!?\n]{{0,160}}\b{_ACTIVITY_QUALIFIER_PATTERN}\b"
    rf")",
    re.IGNORECASE,
)
_POSITIVE_SCOPE_RE = re.compile(
    r"\b(?:"
    r"in[-\s]?scope|within\s+(?:the\s+)?scope"
    r"|scope\s+(?:includes?|covers?|contains?)"
    r"|authorized\s+(?:applications?|apps?|assets?|hosts?|targets?)"
    r"|targets?\s*(?:are|include|includes|:)"
    r"|(?<![.\w-])(?:(?:also|please)\s+|(?:may|must|should|will)\s+)?"
    r"(?:test|scan|assess|audit|pentest)(?=\s|:)"
    r"|(?:perform|conduct)\s+(?:an?\s+)?(?:authenticated\s+)?"
    r"(?:testing|assessment|audit|scan)(?:\s+(?:of|on|against))?"
    r"|(?:testing|assessment|auditing|scanning)\s+is\s+authorized\s+"
    r"(?:for|on|against)"
    r")",
    re.IGNORECASE,
)
# A per-target URL declaration line such as "Application URL: https://app.test",
# "Login URL: https://auth.test", or "Target URL: https://api.test". Real rules of
# engagement list each in-scope app's address under such a label rather than in a
# scope-verb sentence, and those labels frequently follow an intervening
# credentials section that resets positive-scope section tracking. The leading
# negative lookahead keeps documentation/callback/redirect URLs (which are
# references, not targets) from being authorized by an "... URL:" label.
_LABELED_URL_DECL_RE = re.compile(
    r"^(?:the\s+)?"
    r"(?!(?:see|refer|reference|references|referenced|documentation|docs?|"
    r"background|resource|resources|callback|redirect|redirection|webhook|"
    r"example|examples|sample|samples|deprecated|old|previous|former|legacy|"
    r"note|notes)\b)"
    r"(?:[a-z][a-z0-9]*\s+){0,3}"
    r"(?:url|uri|endpoint)s?\s*[:=]\s",
    re.IGNORECASE,
)
_CLAUSE_SPLIT_RE = re.compile(
    r"\s*;(?:\s+|$)|\s+\|\s+|"
    r"\s+(?=(?:and|but)\s+(?:do\s+not|don['\u2019]t|never|skip|omit|avoid)\b)|"
    r"\s+(?=with\s+no\s+(?:testing|scanning|assessment|auditing|targeting)\b)|"
    r"\s+(?=(?:and|but|while|whereas)\s+(?:authentication|authenticated\s+testing)\b)|"
    r"\s+(?=(?:but\s+not|except(?:\s+for)?|excluding|other\s+than)\b)|"
    r"\s+(?=with\s+the\s+exception\s+of\b)|"
    r"(?<=[.!?])\s+(?=[A-Z#])|"
    r",\s+(?=[^,;!?\n]{0,160}\b(?:is|are)\s+"
    r"(?:out[-\s\u2010-\u2015]?of[-\s\u2010-\u2015]?scope|not\s+in[-\s]?scope)\b)|"
    r",\s+(?=(?:but|however|except|not|never|do\s+not|don['\u2019]t|and\s+do\s+not|"
    r"out[-\s\u2010-\u2015]?of[-\s\u2010-\u2015]?scope|outside\s+(?:the\s+)?scope|"
    r"no\s+(?:testing|scanning|assessment|auditing|targeting)\b|"
    r"excluded\s+(?:applications?|apps?|assets?|hosts?|targets?))\b)",
    re.IGNORECASE,
)
_STATEMENT_SPLIT_RE = re.compile(r"\s*;(?:\s+|$)|(?<=[.!?])\s+(?=[A-Z#])")
_REFERENCE_TOKEN_PREFIX_RE = re.compile(
    r"\b(?:"
    r"(?:see|consult|refer\s+to)|"
    r"(?:documentation|docs?|references?|background|details)(?:\s+(?:is|are|at|on))?|"
    r"documented\s+at|"
    r"(?:using|via|through|backed\s+by|depends?\s+on|redirects?\s+to)|"
    r"(?:uses?|using)\s+(?:(?:an?|the|its)\s+)?"
    r"(?:cdn|identity\s+provider|authentication\s+provider|external\s+dependency)|"
    r"compar(?:e|es|ed|ing)(?:\s+\w+){0,4}\s+with|"
    r"(?:identity|authentication)\s+provider(?:\s+(?:at|is|on|via))?"
    r")\s*[:=]?\s*$",
    re.IGNORECASE,
)
_REFERENCE_TOKEN_SUFFIX_RE = re.compile(
    r"^\s+(?:(?:only\s+)?as\s+(?:(?:an?|the|its)\s+)?"
    r"(?:identity|authentication)\s+provider|"
    r"is\s+(?:an?\s+)?(?:external\s+)?dependency)\b",
    re.IGNORECASE,
)
_CREDENTIAL_USE_OPT_OUT_RE = re.compile(
    r"\b(?:do\s+not|don['\u2019]t)\s+use\s+"
    r"(?:(?:an?|any|the|these|those|provided|supplied|test)\s+)*"
    r"(?:credentials?|accounts?)\b",
    re.IGNORECASE,
)
_NON_WEB_IDENTITY_TOKEN_RE = re.compile(r"`[^`\n]+`|\"[^\"\n]+\"|'[^'\n]+'|[^\s,;!?<>()]+")
_AUTH_CONTEXT_RE = re.compile(
    r"\b(?:authenticated|authentication|authenticate|log[-\s]?in|sign[-\s]?in|"
    r"credentials?|accounts?)\b",
    re.IGNORECASE,
)
_AUTH_SCOPE_PATTERN = r"authenticated\s+(?:testing|assessment|coverage|access)"
_AUTH_OPT_OUT_STATE_PATTERN = (
    r"(?:not\s+required|not\s+requested|excluded|out[-\s]?of[-\s]?scope|prohibited)"
)
_AUTH_LOGIN_ACTION_PATTERN = r"(?:authenticate|log\s*in|sign\s*in)"

_AUTH_NEGATION_RE = re.compile(
    r"\b(?:"
    rf"no\s+(?:{_AUTH_SCOPE_PATTERN}|login\s+required|"
    r"(?:(?:application|valid|test|login|usable)\s+)*credentials?\s+"
    r"(?:(?:were|was|are|have\s+been|had\s+been|will\s+be)\s+)?"
    r"(?:currently\s+)?(?:provided|supplied|available|required|shared|issued|provisioned))"
    r"|without\s+(?:authenticated\s+(?:testing|access)|credentials?)"
    rf"|(?:{_AUTH_SCOPE_PATTERN}|login)\s+(?:is\s+|was\s+)?"
    rf"{_AUTH_OPT_OUT_STATE_PATTERN}"
    r"|(?:do\s+not|don['\u2019]t)\s+(?:perform\s+)?"
    r"(?:authenticated\s+(?:testing|assessment)|"
    rf"{_AUTH_LOGIN_ACTION_PATTERN}|use\s+"
    r"(?:(?:an?|any|the|these|those|provided|supplied|test)\s+)*"
    r"(?:credentials?|accounts?))"
    rf"|never\s+{_AUTH_LOGIN_ACTION_PATTERN}"
    r"|credentials?\s+(?:were|was|are|will\s+be|have\s+been)?\s*"
    r"(?:not|never)\s+(?:provided|supplied|available|shared|issued)"
    r"|(?:credentials?|user(?:name)?|password|pwd)\s*[:=]\s*"
    r"(?:none|n/?a|not\s+(?:provided|available)|unavailable)"
    r")\b",
    re.IGNORECASE,
)
_AUTH_HARD_OPT_OUT_RE = re.compile(
    r"\b(?:"
    rf"no\s+{_AUTH_SCOPE_PATTERN}"
    rf"|{_AUTH_SCOPE_PATTERN}\b"
    r"[^\n]{0,200}?\b(?:is\s+|was\s+)?"
    rf"{_AUTH_OPT_OUT_STATE_PATTERN}"
    r"|(?:do\s+not|don['\u2019]t)\s+(?:perform\s+)?"
    rf"(?:authenticated\s+(?:testing|assessment)|{_AUTH_LOGIN_ACTION_PATTERN})"
    rf"|never\s+{_AUTH_LOGIN_ACTION_PATTERN}"
    r"|(?:do\s+not|don['\u2019]t)\s+use\s+"
    r"(?:(?:an?|any|the|these|those|provided|supplied|provisioned|compromised|revoked|"
    r"superseded|old|test)\s+)*(?:credentials?|accounts?)"
    r"(?=\s*(?:[.!?]?\s*$|(?:for|to)\s+(?:authentication|authenticated\s+testing|"
    r"testing|log[-\s]?in)\b))"
    r"|(?:credentials?|accounts?)\s+(?:are\s+|were\s+|should\s+be\s+|must\s+be\s+)?"
    r"(?:for\s+reference\s+only|not\s+to\s+be\s+used|not\s+for\s+testing|"
    r"revoked|superseded|not\s+authorized\s+for\s+use)"
    r"|credentials?\b[^.;!?\n]{0,100}\bfor\s+reference\s+only"
    r"|(?:they|these|those|such\s+credentials?|such\s+accounts?)\s+"
    r"(?:are|were)\s+(?:for\s+reference\s+only|not\s+to\s+be\s+used|"
    r"not\s+for\s+testing|revoked|superseded|not\s+authorized\s+for\s+use)"
    r"|(?:but\s+)?not\s+authorized\s+for\s+use\s*[.!?]?$"
    r"|(?:do\s+not|don['\u2019]t)\s+use\s+(?:them|it|this|these|those)"
    r"(?:\s+(?:for|to)\s+(?:authentication|authenticated\s+testing|testing|log[-\s]?in))?"
    r"\s*[.!?]?$"
    r")",
    re.IGNORECASE,
)
_ENGAGEMENT_AUTH_OPT_OUT_RE = re.compile(
    r"\b(?:"
    rf"no\s+{_AUTH_SCOPE_PATTERN}"
    rf"|{_AUTH_SCOPE_PATTERN}\b[^\n]{{0,160}}\b{_AUTH_OPT_OUT_STATE_PATTERN}"
    r"|(?:do\s+not|don['\u2019]t)\s+(?:perform\s+)?"
    r"authenticated\s+(?:testing|assessment)"
    rf"|(?:do\s+not|don['\u2019]t)\s+{_AUTH_LOGIN_ACTION_PATTERN}\s*[.!?]?$"
    rf"|never\s+{_AUTH_LOGIN_ACTION_PATTERN}\s*[.!?]?$"
    r")",
    re.IGNORECASE,
)
_AUTH_TEST_RE = re.compile(
    r"\b(?:"
    r"authenticated\s+(?:testing|assessment|coverage|access|workflow|workflows|test|tests)"
    r"|test(?:ing)?\s+(?:both\s+)?authenticated\b"
    r"|authenticate(?:\s+(?:to|against|on))?\b"
    r"|log\s*in\s+with|sign\s*in\s+with"
    r"|use\s+(?:an?\s+|the\s+|these\s+|authorized\s+|provided\s+|supplied\s+|"
    r"provisioned\s+|test\s+|audit\s+)*"
    r"(?:credentials?|accounts?)"
    r"|test(?:ing)?\s+(?!whether\b|if\b)[^.;!?\n]{0,100}\bwith\s+"
    r"(?:(?:the|authorized|provided|supplied|test)\s+)*(?:credentials?|accounts?)"
    r"|(?:role|privilege)[-\s]+(?:based\s+)?(?:comparison|testing|coverage)"
    r")",
    re.IGNORECASE,
)
_CREDENTIAL_VALUE_RE = re.compile(
    r"\bcredentials?\s*[:=]\s*(?!none\b|n/?a\b|not\b|unavailable\b)(?:\S.+|\S)$",
    re.IGNORECASE,
)
_CREDENTIAL_PROVISION_RE = re.compile(
    r"\bcredentials?\s+(?:are\s+|were\s+|have\s+been\s+)?"
    r"(?:provided|supplied|available|attached|included|issued|provisioned|shared)\b",
    re.IGNORECASE,
)
_CREDENTIAL_OBSERVATION_RE = re.compile(
    r"\b(?:test|assess|check|verify|determine|inspect|review|whether|if)\b"
    r"[^.;!?\n]{0,120}\bcredentials?\b[^.;!?\n]{0,80}\b"
    r"(?:responses?|logs?|error\s+messages?|source\s+code|storage|telemetry|"
    r"requests?|headers?|https?|tls|secure\s+(?:transport|channels?|connections?))\b",
    re.IGNORECASE,
)
_PASSWORD_VALUE_RE = re.compile(
    r"(?:^|\b)(?:password|passwd|pwd|pass)\s*(?:[:=]|\bis\b)\s*"
    r"(?!none\b|n/?a\b|not\b|must\b|should\b|policy\b|reset\b|minimum\b)"
    r"([^\s,;]+)",
    re.IGNORECASE,
)
_PASSWORD_DESCRIPTION_RE = re.compile(
    r"\b(?:password|passwd|pwd|pass)\s+is\s+"
    r"(?:hashed|encrypted|stored|masked|redacted|logged|exposed|transmitted|"
    r"leaked|reused|validated|checked|compared|protected)\b",
    re.IGNORECASE,
)

_NO_CREDENTIALS_ENGAGEMENT_RE = re.compile(
    r"(?:"
    r"\bno\s+(?:application\s+|valid\s+|test\s+|login\s+)?credentials?"
    r"(?:\s+or\s+source\s+code)?\s+(?:were|was|had\s+been)?\s*"
    r"(?:provided|supplied|shared|issued|received|available|made\s+available)\b"
    r"|\b(?:we|testers?|assessors?|testing\s+team|assessment\s+team)\s+"
    r"(?:weren['\u2019]t|were\s+not)\s+(?:given|provided|supplied)\s+(?:any\s+)?"
    r"(?:application\s+|valid\s+|test\s+|login\s+)?credentials?\b"
    r"|\b(?:client|customer|operator|target\s+owner)\s+"
    r"(?:didn['\u2019]t|did\s+not)\s+(?:provide|supply|share|issue)\s+(?:any\s+)?"
    r"(?:application\s+|valid\s+|test\s+|login\s+)?credentials?\b"
    r"|\b(?:client|customer|operator|target\s+owner)\s+"
    r"(?:declined|refused)\s+to\s+(?:provide|supply|share|issue)\s+(?:any\s+)?"
    r"(?:application\s+|valid\s+|test\s+|login\s+)?credentials?\b"
    r"|\bonly\s+unauthenticated\s+(?:testing|assessment)\s+was\s+performed\b"
    r"|\b(?:assessment|engagement|testing)\s+(?:was\s+|were\s+)?"
    r"(?:conducted\s+|performed\s+|completed\s+|carried\s+out\s+|proceeded\s+)?"
    r"without\s+(?:any\s+)?(?:application\s+|valid\s+|test\s+|login\s+)?credentials?\b"
    r"|\b(?:assessment|engagement)\s+had\s+no\s+(?:valid\s+|test\s+|login\s+)?account\b"
    r"|\b(?:the\s+)?(?:penetration\s+)?test\s+(?:was|is)\s+"
    r"(?:conducted\s+|performed\s+)?(?:as\s+)?an?\s+"
    r"(?:external\s+)?black[-\s]?box\s+assessment\b"
    r"|\b(?:we|testers?|assessors?|testing\s+team|assessment\s+team)\s+"
    r"(?:had|have|received|were\s+(?:given|provided|supplied))\s+"
    r"no\s+(?:application\s+|valid\s+|test\s+)?credentials?\b"
    r"|\b(?:client|customer|operator|target\s+owner)\s+"
    r"(?:failed\s+to|never\s+did)\s+(?:provide|supply|share|issue)\s+(?:any\s+)?"
    r"(?:application\s+|valid\s+|test\s+)?credentials?\b"
    r"|\b(?:client|customer|operator|target\s+owner)\s+never\s+"
    r"(?:provided|supplied|shared|issued)\s+(?:any\s+)?"
    r"(?:application\s+|valid\s+|test\s+)?credentials?\b"
    r"|\b(?:client|customer|operator|target\s+owner)\s+withheld\s+"
    r"(?:the\s+|any\s+)?(?:application\s+|valid\s+|test\s+)?credentials?\b"
    r"|\b(?:we|testers?|assessors?|testing\s+team|assessment\s+team)\s+"
    r"(?:did\s+not\s+(?:receive|have|obtain)|had\s+no)\s+(?:any\s+)?"
    r"(?:application\s+|valid\s+|test\s+)?credentials?\b"
    r"|\b(?:we|testers?|assessors?|testing\s+team|assessment\s+team)\s+"
    r"never\s+(?:received|had|obtained)\s+(?:any\s+)?"
    r"(?:application\s+|valid\s+|test\s+)?credentials?\b"
    r"|\b(?:application\s+|valid\s+|test\s+)?credentials?\s+"
    r"(?:were|was)\s+(?:unavailable|not\s+(?:provided|supplied|shared|issued|available))\b"
    r"|\bno\s+(?:application\s+|valid\s+|test\s+)?accounts?\s+"
    r"(?:were|was|had\s+been)?\s*(?:provided|supplied|shared|issued|available)\b"
    r"|\b(?:we|testers?|assessors?|testing\s+team|assessment\s+team)\s+"
    r"(?:conducted|performed|completed|carried\s+out)\s+(?:the\s+)?"
    r"(?:assessment|engagement|testing)\s+without\s+(?:any\s+)?"
    r"(?:application\s+|valid\s+|test\s+)?credentials?\b"
    r"|\b(?:assessment|engagement|testing|we|testers?|assessors?)\s+"
    r"lacked\s+(?:any\s+)?(?:authenticated\s+(?:access|context)|credentials?)\b"
    r"|\b(?:assessment|engagement|testing)\s+(?:had\s+no|was\s+denied)\s+"
    r"(?:authenticated\s+(?:access|context)|credentials?)\b"
    r"|\bno\s+(?:login|authenticated)\s+access\s+"
    r"(?:was\s+|is\s+)?(?:provided|supplied|available)\b"
    r"|\bauthenticated\s+access\s+(?:was\s+|is\s+)?unavailable\s+to\s+"
    r"(?:us|testers?|assessors?|the\s+(?:testing|assessment)\s+team)\b"
    r"|\b(?:assessment|engagement|testing)\s+(?:was|is|were)\s+"
    r"(?:entirely\s+|solely\s+|strictly\s+)?unauthenticated\b"
    r"|\b(?:the\s+)?(?:assessment|engagement|testing)\s+(?:was|is)\s+"
    r"(?:an?\s+)?(?:external\s+)?(?:unauthenticated\s+)?black[-\s]?box"
    r"(?:\s+(?:assessment|engagement))?\b"
    r"|\b(?:this|the)\s+(?:assessment|engagement|testing)\s+was\s+"
    r"credential[-\s]?free\b"
    r"|\b(?:testers?|assessors?|testing\s+team|assessment\s+team)\s+lacked\s+"
    r"(?:(?:an?|any)\s+)?(?:valid\s+|test\s+)?accounts?\b"
    r"|\b(?:assessment|engagement)\s+type\s*:\s*"
    r"(?:external\s+)?(?:unauthenticated\s+)?black[-\s]?box\b"
    r"|\b(?:this|it)\s+was\s+an?\s+(?:external\s+)?"
    r"(?:unauthenticated\s+)?black[-\s]?box\s+(?:assessment|engagement)\b"
    r"|\b(?:assessment|engagement|test|testing)\s+(?:was\s+|were\s+)?"
    r"(?:conducted\s+|performed\s+)?(?:as\s+)?an?\s+"
    r"unauthenticated\s+black[-\s]?box\b"
    r"|\b(?:assessment|engagement|test|testing)\s+(?:was\s+|were\s+)?"
    r"(?:conducted\s+|performed\s+)?(?:entirely|solely|strictly)\s+"
    r"(?:as\s+)?(?:an?\s+)?(?:unauthenticated\s+)?black[-\s]?box\b"
    r"|^\s*(?:an?\s+)?(?:external\s*,?\s+)?(?:unauthenticated\s+)?black[-\s]?box\s+"
    r"(?:assessment|engagement)\s*[.!?]?\s*$"
    r")",
    re.IGNORECASE,
)
_NO_CREDENTIALS_FINDING_SUFFIX_RE = re.compile(
    r"^\s+(?:in|within|from|through|via|by|to|during)\s+(?:"
    r"(?:[a-z-]+\s+){0,4}(?:logs?|log\s+files?|responses?|error\s+messages?|api|source|"
    r"source\s+code|repositories?|"
    r"commits?|files?|storage|telemetry|users?|clients?|attackers?|"
    r"registration|password\s+reset|(?:un)?authorized\s+(?:users?|clients?))"
    r")\b",
    re.IGNORECASE,
)
_NO_CREDENTIALS_FINDING_PREFIX_RE = re.compile(
    r"\b(?:assessment|engagement|testing|testers?|assessors?)\s+"
    r"(?:found|identified|confirmed|verified|observed|showed|demonstrated)\b",
    re.IGNORECASE,
)

_AUTH_PROVIDER_CORE_PATTERN = (
    r"identity\s+provider|idp|sso|login\s+service|authentication\s+service"
)
_AUTH_PROVIDER_FAILURE_PATTERN = r"unavailable|inaccessible|timed?\s*out|outage|failed"
_AUTH_FACTOR_CORE_PATTERN = (
    r"otp|mfa|2fa|one[-\s]?time\s+(?:password|passcode|code)|"
    r"verification\s+code|authenticator(?:\s+code)?"
)
_AUTH_FACTOR_PATTERN = rf"(?:{_AUTH_FACTOR_CORE_PATTERN}|multi[-\s]?factor(?:\s+authentication)?)"

_DIRECT_AUTH_BLOCKER_RE = re.compile(
    r"\b(?:"
    r"(?:login|log[-\s]?in|sign[-\s]?in|authentication)\s+"
    r"(?:service|endpoint|flow)\s+(?:was\s+|is\s+)?"
    r"(?:unavailable|inaccessible|not\s+available)"
    r"|(?:(?:provided|supplied|provisioned|test)\s+)?"
    r"(?:account|credentials?)\s+(?:was|were|is|are)\s+"
    r"(?:rejected|invalid|expired|locked|disabled|not\s+activated)"
    r")\b",
    re.IGNORECASE,
)
_CAUSAL_AUTH_BLOCKER_RE = re.compile(
    r"\b(?:"
    r"(?:could\s+not|couldn['\u2019]t|cannot|can't|unable\s+to|failed\s+to|"
    r"not\s+able\s+to)\s+"
    r"(?:log\s*in|sign\s*in|authenticate|access\s+(?:the\s+)?authenticated\s+area)"
    r"|(?:login|log[-\s]?in|sign[-\s]?in|authentication|"
    r"authenticated\s+(?:testing|access))\s+(?:was\s+|is\s+)?"
    r"(?:blocked|prevented|denied|failed|not\s+possible)"
    r"|authenticated\s+testing\s+(?:could\s+not|cannot|was\s+unable\s+to)\s+proceed"
    r")\b[^.;!?\n]{0,80}\b(?:because|due\s+to|as\s+a\s+result\s+of)\b"
    r"[^.;!?\n]{0,100}\b(?:"
    r"(?:provided|supplied|provisioned|test)\s+(?:account|credentials?)\s+"
    r"(?:was|were)?\s*(?:rejected|invalid|expired|locked|disabled|not\s+activated)"
    rf"|(?:{_AUTH_PROVIDER_CORE_PATTERN}|login\s+endpoint)\b[^.;!?\n]{{0,40}}\b"
    rf"(?:{_AUTH_PROVIDER_FAILURE_PATTERN}|returned\s+(?:5\d\d|an?\s+error))"
    rf"|(?:unavailable|inaccessible)\s+(?:{_AUTH_PROVIDER_CORE_PATTERN})"
    rf"|(?:{_AUTH_FACTOR_CORE_PATTERN})\b[^.;!?\n]{{0,50}}\b"
    r"(?:unavailable|inaccessible|not\s+(?:available|received)|expired|external\s+inbox|"
    r"routed|sent|delivered|outside\s+(?:the\s+)?(?:tester(?:'s)?|team(?:'s)?|our)\s+control)"
    r"|(?:tls|ssl|certificate)\s+(?:error|failure)\b[^.;!?\n]{0,60}\b"
    rf"(?:{_AUTH_PROVIDER_CORE_PATTERN})"
    r")\b",
    re.IGNORECASE,
)
_PROVIDER_AUTH_BLOCKER_RE = re.compile(
    rf"\b(?:{_AUTH_PROVIDER_CORE_PATTERN})\b"
    rf"[^.;!?\n]{{0,60}}\b(?:{_AUTH_PROVIDER_FAILURE_PATTERN})\b"
    r"[^.;!?\n]{0,60}\b(?:prevent(?:ed|ing)|block(?:ed|ing)|den(?:ied|ying))\b"
    r"[^.;!?\n]{0,30}\b(?:authentication|login|log[-\s]?in|sign[-\s]?in|access)\b"
    r"|\b(?:authentication|login|log[-\s]?in|sign[-\s]?in)\b"
    r"[^.;!?\n]{0,30}\b(?:blocked|prevented|denied)\s+by\s+an?\s+unavailable\s+"
    rf"(?:{_AUTH_PROVIDER_CORE_PATTERN})\b",
    re.IGNORECASE,
)
_AUTH_FAILURE_PROVIDER_COLON_RE = re.compile(
    r"\b(?:could\s+not|couldn['\u2019]t|cannot|can't|unable\s+to|failed\s+to)\s+"
    r"(?:log\s*in|sign\s*in|authenticate)\s*:\s*"
    rf"(?:the\s+)?(?:{_AUTH_PROVIDER_CORE_PATTERN})\b[^.;!?\n]{{0,40}}\b"
    rf"(?:{_AUTH_PROVIDER_FAILURE_PATTERN})\b",
    re.IGNORECASE,
)
_FACTOR_UNAVAILABLE_RE = re.compile(
    rf"\b{_AUTH_FACTOR_PATTERN}\b"
    r"(?:\s+(?:verification\s+)?codes?|\s+(?:challenge|service|device|app|delivery))?"
    r"\s+(?:(?:was|were|is|are)\s+)?"
    r"(?:unavailable|not\s+available|not\s+received|wasn['\u2019]t\s+received|"
    r"never\s+(?:received|arrived)|inaccessible|expired|invalid|"
    r"could\s+not\s+be\s+(?:accessed|obtained|retrieved|received))\b",
    re.IGNORECASE,
)
_FACTOR_PREVENTS_AUTH_RE = re.compile(
    rf"\b{_AUTH_FACTOR_PATTERN}\b"
    r"(?:\s+(?:requirement|challenge|code))?\s+(?:blocked|prevented|denied)\s+"
    r"(?:(?:the\s+)?(?:tester|testing\s+team|team|us)\s+from\s+)?"
    r"(?:login|logging\s+in|log[-\s]?in|signing\s+in|sign[-\s]?in|authentication|access)\b",
    re.IGNORECASE,
)
_FACTOR_OUTSIDE_CONTROL_RE = re.compile(
    rf"\b{_AUTH_FACTOR_PATTERN}\b[^.;!?\n]{{0,80}}\b"
    r"(?:routed|sent|delivered)\b[^.;!?\n]{0,80}\b"
    r"(?:outside\s+(?:the\s+)?(?:tester(?:'s)?|team(?:'s)?|our)\s+control|"
    r"inaccessible|unavailable|uncontrolled)\b",
    re.IGNORECASE,
)
_SELF_CAUSED_AUTH_FAILURE_RE = re.compile(
    r"\b(?:because|due\s+to|as\s+a\s+result\s+of)\b[^.;!?\n]{0,120}\b"
    r"(?:we|us|tester|testers|testing\s+team|assessment\s+team|team)\b"
    r"[^.;!?\n]{0,80}\b(?:"
    r"intentionally|deliberately|knowingly|purposely|"
    r"entered\b[^.;!?\n]{0,30}\b(?:incorrectly|wrong)|"
    r"used\b[^.;!?\n]{0,30}\b(?:invalid|incorrect|wrong)\s+(?:password|credentials?)|"
    r"waited\b|disabled\b|deleted\b|revoked\b|misconfigured\b"
    r")",
    re.IGNORECASE,
)
_AUTH_BLOCKER_PATTERNS = (
    _DIRECT_AUTH_BLOCKER_RE,
    _CAUSAL_AUTH_BLOCKER_RE,
    _PROVIDER_AUTH_BLOCKER_RE,
    _AUTH_FAILURE_PROVIDER_COLON_RE,
    _FACTOR_UNAVAILABLE_RE,
    _FACTOR_PREVENTS_AUTH_RE,
    _FACTOR_OUTSIDE_CONTROL_RE,
)


def _trim_token(value: str) -> str:
    token = (value or "").strip()
    if token.startswith("<") and token.endswith(">"):
        token = token[1:-1].strip()
    token = token.strip("\"'")
    token = token.rstrip(".,;!?")
    for opener, closer in (("(", ")"), ("{", "}"), ("[", "]")):
        while token.endswith(closer) and token.count(closer) > token.count(opener):
            token = token[:-1]
    return token


def _canonical_ip(value: str) -> str:
    candidate = value.replace("%25", "%")
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def normalize_host(value: str) -> str:  # noqa: PLR0911
    """Reduce a URL or host string to a canonical, comparable hostname.

    Parsing uses :attr:`urllib.parse.ParseResult.hostname`, so userinfo and ports
    (including bracketed IPv6 ports) are handled without hand-splitting on ``@`` or
    ``:``.  Domain names are lowercased, IDNA-normalized, stripped of a trailing dot,
    while preserving DNS labels such as ``www``. IP literals are canonicalized
    with :mod:`ipaddress`.
    """
    token = _trim_token(value)
    if not token:
        return ""

    # urlparse cannot distinguish the colons of an unbracketed IPv6 literal from a
    # port separator.  Recognize a literal before asking it to parse a netloc.
    direct_ip = _canonical_ip(token)
    if direct_ip:
        return direct_ip

    parsed_value = token if "://" in token else f"//{token}"
    try:
        host = urlparse(parsed_value).hostname or ""
    except ValueError:
        return ""
    host = _trim_token(host).rstrip(".").lower()
    if not host:
        return ""

    canonical_ip = _canonical_ip(host)
    if canonical_ip:
        return canonical_ip
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


def _is_ip(host: str) -> bool:
    return bool(_canonical_ip(host))


def _acceptable_host(host: str) -> bool:
    if not host:
        return False
    canonical = _canonical_ip(host)
    if canonical:
        # The unspecified ("::"/"0.0.0.0") and loopback literals name the
        # scanner's own host, never an engagement target. Free-text prose must
        # not promote them to authorized scope; a real local target is provided
        # as an explicit structured target instead.
        ip = ipaddress.ip_address(canonical)
        return not (ip.is_unspecified or ip.is_loopback)
    if len(host) > 253 or "." not in host:
        return False
    labels = host.split(".")
    if labels[-1].lower() in _FILE_EXT_TLDS:
        return False
    return all(
        0 < len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(char.isalnum() or char == "-" for char in label)
        for label in labels
    )


@dataclass(frozen=True)
class _AssetReference:
    """Normalized asset identity retained while reconciling free-text clauses."""

    host: str
    scheme: str | None = None
    port: int | None = None
    # ``None`` means a host/root declaration. Non-root paths retain repeated
    # interior slashes; a trailing slash is a canonical equivalent.
    path: str | None = None


@dataclass(frozen=True)
class _CandidateToken:
    """A source token and its exact span in the containing clause."""

    start: int
    end: int
    value: str


def _asset_reference(value: str) -> _AssetReference | None:
    token = _trim_token(value)
    host = normalize_host(token)
    if not _acceptable_host(host):
        return None

    if _canonical_ip(token):
        return _AssetReference(host=host)

    parsed_value = token if "://" in token else f"//{token}"
    try:
        parsed = urlparse(parsed_value)
        port = parsed.port
    except ValueError:
        return None

    scheme = parsed.scheme.lower() or None
    if port == {"http": 80, "https": 443}.get(scheme or ""):
        port = None
    path = (parsed.path or "").rstrip("/")
    return _AssetReference(
        host=host,
        scheme=scheme,
        port=port,
        path=path or None,
    )


def _reference_value(reference: _AssetReference) -> str:
    """Serialize a parsed target without losing its origin or path identity."""
    needs_ipv6_brackets = bool(
        _is_ip(reference.host)
        and ":" in reference.host
        and (reference.scheme or reference.port is not None or reference.path)
    )
    host = f"[{reference.host}]" if needs_ipv6_brackets else reference.host
    authority = f"{host}:{reference.port}" if reference.port is not None else host
    if reference.scheme is not None:
        return f"{reference.scheme}://{authority}{reference.path or '/'}"
    return f"{authority}{reference.path or ''}"


def _effective_port(reference: _AssetReference) -> int | None:
    if reference.port is not None:
        return reference.port
    return {"http": 80, "https": 443}.get(reference.scheme or "")


def _exclusion_covers(  # noqa: PLR0911
    exclusion: _AssetReference,
    asset: _AssetReference,
) -> bool:
    """Match an explicit exclusion without substring, sibling, or path widening."""
    if exclusion.path is None:
        host_matches = asset.host == exclusion.host or (
            not _is_ip(asset.host)
            and not _is_ip(exclusion.host)
            and asset.host.endswith(f".{exclusion.host}")
        )
    else:
        # Path-specific exclusions never flow to a parent domain's subdomains.
        host_matches = asset.host == exclusion.host
    if not host_matches:
        return False

    # A bare host/domain exclusion covers every origin on that host. An explicit
    # URL/service exclusion must match the requested asset's known origin.
    if exclusion.scheme is not None:
        if asset.scheme is None or asset.scheme != exclusion.scheme:
            return False
        if _effective_port(asset) != _effective_port(exclusion):
            return False
    elif exclusion.port is not None and _effective_port(asset) != exclusion.port:
        return False

    if exclusion.path is None:
        return True
    if asset.path is None:
        return False
    return asset.path == exclusion.path or asset.path.startswith(f"{exclusion.path}/")


def _clean_line(line: str) -> str:
    return re.sub(r"^\s*(?:#{1,6}\s*|[-*+]\s+|\d+[.)]\s+)", "", line).strip()


def _clean_instruction_lines(instruction: str) -> Iterator[tuple[str, bool]]:
    for raw_line in instruction.splitlines():
        line = _clean_line(raw_line)
        if line:
            yield line, bool(re.match(r"^\s*#{1,6}\s+", raw_line))


def _section_state(current: str | None, text: str, *, is_heading: bool = False) -> str | None:
    if _POSITIVE_SCOPE_SECTION_RE.match(text):
        return "authorized"
    if _EXCLUSION_SCOPE_SECTION_RE.match(text):
        return "excluded"
    if _REFERENCE_SCOPE_SECTION_RE.match(text) or _OTHER_SECTION_RE.match(text) or is_heading:
        return None
    # An unknown labelled heading ("Additional resources:", "Background
    # information:") terminates an authorized section only when it carries no
    # asset of its own. A labelled item that names a host on the same line
    # ("WellReceived: https://app.test") is an in-scope entry, not a new
    # section, and must keep inheriting the current section.
    if _GENERIC_HEADING_RE.match(text) and not _candidate_tokens(
        text, suppress_reference_tokens=False
    ):
        return None
    return current


def _split_clauses(text: str) -> list[str]:
    return [clause.strip() for clause in _CLAUSE_SPLIT_RE.split(text) if clause.strip()]


def _is_negative_scope_clause(clause: str) -> bool:
    return bool(_NEGATIVE_SCOPE_RE.search(clause) or _PLAIN_NEGATIVE_SCOPE_RE.search(clause))


def _authorized_fragments(instruction: str) -> Iterator[str]:
    """Yield positive scope clauses, tracking explicit in-scope sections."""
    section: str | None = None
    for line, is_heading in _clean_instruction_lines(instruction):
        section = _section_state(section, line, is_heading=is_heading)

        for clause in _split_clauses(line):
            section = _section_state(section, clause)
            # Exclusion wording always wins, including inside an in-scope section
            # or a mixed line such as "Test A; do not test B".
            if _is_negative_scope_clause(clause):
                continue
            if (
                section == "authorized"
                or _POSITIVE_SCOPE_RE.search(clause)
                or _LABELED_URL_DECL_RE.match(clause)
            ):
                yield clause


def _explicit_exclusion_fragments(instruction: str) -> Iterator[str]:
    """Yield only clauses that explicitly exclude assets from testing."""
    section: str | None = None
    for line, is_heading in _clean_instruction_lines(instruction):
        section = _section_state(section, line, is_heading=is_heading)

        for statement in _STATEMENT_SPLIT_RE.split(line):
            # A negative boundary describes everything *around* the named asset;
            # the exception itself is not excluded. Check before relational clause
            # splitting can detach "except/other than <asset>" from its antecedent.
            if _SCOPE_BOUNDARY_RE.search(statement):
                continue
            for clause in _split_clauses(statement):
                section = _section_state(section, clause)
                if section == "excluded":
                    yield clause
                    continue
                if not _is_negative_scope_clause(clause):
                    continue
                clause_without_assets = _without_candidate_tokens(clause)
                line_without_assets = _without_candidate_tokens(line)
                if _AUTH_HARD_OPT_OUT_RE.search(
                    clause_without_assets
                ) or _CREDENTIAL_USE_OPT_OUT_RE.search(clause_without_assets):
                    continue
                # "Authenticated testing for all apps except B" narrows the auth
                # requirement; it does not remove B from the engagement scope. Bare
                # relational exclusions are scope exclusions only in an explicit
                # scope section or a non-auth testing/scope declaration.
                if (
                    _PLAIN_NEGATIVE_SCOPE_RE.search(clause)
                    and _AUTH_CONTEXT_RE.search(line_without_assets)
                    and not _POSITIVE_SCOPE_SECTION_RE.match(line)
                ):
                    continue
                yield clause


def _without_candidate_tokens(text: str) -> str:
    """Remove asset tokens before classifying surrounding auth/scope prose."""
    sanitized = text
    for candidate in reversed(_candidate_tokens(text, suppress_reference_tokens=False)):
        sanitized = f"{sanitized[: candidate.start]} {sanitized[candidate.end :]}"
    return sanitized


def _overlaps(span: tuple[int, int], occupied: Iterable[tuple[int, int]]) -> bool:
    start, end = span
    return any(start < known_end and known_start < end for known_start, known_end in occupied)


def _candidate_tokens(
    fragment: str,
    *,
    suppress_reference_tokens: bool = True,
) -> list[_CandidateToken]:
    """Return URL/domain/IP tokens in source order, excluding email/handle domains."""
    protected = [match.span() for match in _EMAIL_RE.finditer(fragment)]
    protected.extend(match.span() for match in _HANDLE_RE.finditer(fragment))
    # Repository identities are non-web targets. Protect their complete span so
    # the FQDN pass cannot reinterpret ``github.com`` or ``Repo.git`` as a web
    # application named in otherwise-positive prose.
    protected.extend(match.span() for match in _SSH_REPOSITORY_RE.finditer(fragment))
    protected.extend(match.span() for match in _LOCAL_PATH_RE.finditer(fragment))

    candidates: list[_CandidateToken] = []
    occupied: list[tuple[int, int]] = []
    for pattern, may_overlap_email in (
        (_URL_RE, True),
        (_SCHEMELESS_HOST_PATH_RE, True),
        (_BRACKETED_IPV6_RE, False),
        (_IPV4_RE, False),
        (_BARE_IPV6_RE, False),
        (_FQDN_RE, False),
    ):
        for match in pattern.finditer(fragment):
            span = match.span()
            if _overlaps(span, occupied):
                continue
            if not may_overlap_email and _overlaps(span, protected):
                continue
            # A positive clause can still contain a separate documentation or
            # reference URL ("Test app.example; see docs.vendor").  A nearby
            # reference marker is not an authorization signal for that token.
            prefix = fragment[max(0, span[0] - 80) : span[0]]
            suffix = fragment[span[1] : span[1] + 100]
            if suppress_reference_tokens and (
                _REFERENCE_TOKEN_PREFIX_RE.search(prefix)
                or _REFERENCE_TOKEN_SUFFIX_RE.match(suffix)
            ):
                # Reserve the skipped URL span so the later FQDN pass cannot
                # rediscover its hostname as a separate candidate.
                occupied.append(span)
                continue
            candidates.append(_CandidateToken(span[0], span[1], match.group(0)))
            occupied.append(span)
    candidates.sort(key=lambda item: item.start)
    return candidates


def _candidate_is_activity_location(fragment: str, token_start: int) -> bool:
    """Return whether a host merely locates a restricted technique or feature.

    In ``do not test payment processing on app.test``, the direct object of the
    prohibition is the feature and the host after ``on`` only says where that
    restriction applies. Treating the host as wholly excluded would erase a
    separate authorization for the rest of the application. Broad objects such as
    ``anything`` retain whole-asset semantics, and a URL/path used directly as the
    verb's object never reaches this locative branch.
    """
    prefix = fragment[:token_start]
    match = _ACTIVITY_LOCATION_OBJECT_RE.search(prefix)
    if match is None:
        match = _NOMINAL_ACTIVITY_LOCATION_OBJECT_RE.search(prefix)
    if match is None:
        return False
    restricted_object = match.group("object").strip()
    return not bool(_WHOLE_ASSET_ACTIVITY_OBJECT_RE.fullmatch(restricted_object))


def _candidate_has_activity_qualifier(fragment: str, token_end: int) -> bool:
    """Return whether a direct host object is narrowed to an activity or use."""
    return bool(_POSTFIX_ACTIVITY_RESTRICTION_RE.match(fragment[token_end:]))


def _excluded_asset_references(instruction: str) -> list[_AssetReference]:
    exclusions: list[_AssetReference] = []
    for fragment in _explicit_exclusion_fragments(instruction):
        # Reference-marker suppression is a positive-scope safeguard only. In an
        # exclusion clause it must never drop a host, or an operator exclusion
        # such as "Out of scope: the identity provider auth.test" would silently
        # fail to exclude the asset. Over-recognizing an exclusion is the safe
        # direction; under-recognizing one lets an excluded asset be tested.
        for candidate in _candidate_tokens(fragment, suppress_reference_tokens=False):
            if _candidate_is_activity_location(
                fragment, candidate.start
            ) or _candidate_has_activity_qualifier(fragment, candidate.end):
                continue
            reference = _asset_reference(candidate.value)
            if reference is not None and reference not in exclusions:
                exclusions.append(reference)
    return exclusions


def _normalize_non_web_identity(value: str) -> str:
    """Normalize only presentation wrappers for an exact non-web identity."""
    identity = (value or "").strip()
    if len(identity) >= 2 and identity[0] == identity[-1] and identity[0] in {'"', "'", "`"}:
        identity = identity[1:-1].strip()
    identity = _trim_token(identity)
    if identity != "/":
        identity = identity.rstrip("/")
    return identity


def _fragment_excludes_exact_non_web_identity(fragment: str, asset: str) -> bool:
    expected = _normalize_non_web_identity(asset)
    if not expected:
        return False
    return any(
        _normalize_non_web_identity(match.group(0)) == expected
        for match in _NON_WEB_IDENTITY_TOKEN_RE.finditer(fragment)
    )


def instruction_excludes_asset(instruction: str, asset: str) -> bool:
    """Return whether operator text explicitly excludes ``asset`` from testing.

    Only negative clauses and out-of-scope/exclusion sections contribute. Plain
    references and documentation sections do not. Bare host exclusions cover true
    DNS subdomains; IPs match exactly. A non-root URL exclusion is path-specific
    and covers only that path or descendants on the same origin. Non-web targets
    such as local-code paths and SSH repositories require an exact, case-sensitive
    identity match (apart from a presentation-only trailing slash).
    """
    if not instruction or not instruction.strip():
        return False
    asset_reference = _asset_reference(asset)
    if asset_reference is None:
        return any(
            _fragment_excludes_exact_non_web_identity(fragment, asset)
            for fragment in _explicit_exclusion_fragments(instruction)
        )
    return any(
        _exclusion_covers(exclusion, asset_reference)
        for exclusion in _excluded_asset_references(instruction)
    )


def extract_instruction_targets(instruction: str) -> list[str]:
    """Extract authorized web/IP identities while retaining origin and path.

    Values are canonicalized for comparison: scheme-bearing roots end in ``/`` and
    non-root trailing slashes are equivalent, while repeated interior slashes and
    ``www`` labels remain significant.
    """
    if not instruction or not instruction.strip():
        return []

    targets: list[str] = []
    seen: set[_AssetReference] = set()
    exclusions = _excluded_asset_references(instruction)
    for fragment in _authorized_fragments(instruction):
        for candidate in _candidate_tokens(fragment):
            reference = _asset_reference(candidate.value)
            if reference is None or reference in seen:
                continue
            if any(_exclusion_covers(exclusion, reference) for exclusion in exclusions):
                continue
            seen.add(reference)
            targets.append(_reference_value(reference))
    return targets


def _structured_reference_covers(  # noqa: PLR0911
    structured: _AssetReference,
    declared: _AssetReference,
) -> bool:
    """Return whether a structured target semantically covers a declaration."""
    if structured.host != declared.host:
        return False
    if _is_ip(structured.host):
        structured_is_bare_ip = (
            structured.scheme is None and structured.port is None and structured.path is None
        )
        declared_is_bare_ip = (
            declared.scheme is None and declared.port is None and declared.path is None
        )
        # A bare IP is a network target; an IP URL is a distinct web target even
        # when both spell the same address. Finish coverage represents them with
        # different target types and therefore needs both identities surfaced.
        if structured_is_bare_ip != declared_is_bare_ip:
            return False
    if structured.path != declared.path:
        return False
    structured_has_scheme_less_port = structured.scheme is None and structured.port is not None
    declared_has_scheme_less_port = declared.scheme is None and declared.port is not None
    if structured_has_scheme_less_port or declared_has_scheme_less_port:
        # ``host:443`` is an explicit scheme-less service identity, not an alias
        # for either bare ``host`` or ``https://host``. Finish-time coverage keeps
        # these identities distinct, so reconciliation must do the same in both
        # directions. Two scheme-less explicit ports cover only an exact port.
        return (
            structured_has_scheme_less_port
            and declared_has_scheme_less_port
            and structured.port == declared.port
        )
    if structured.scheme is not None and declared.scheme is not None:
        return structured.scheme == declared.scheme and _effective_port(
            structured
        ) == _effective_port(declared)

    structured_port = _effective_port(structured)
    declared_port = _effective_port(declared)
    if structured_port is not None and declared_port is not None:
        return structured_port == declared_port
    if structured_port is None and declared_port is None:
        return True

    # A scheme-less target with no explicit port is an origin wildcard for this
    # exact host/path. This mirrors finish-time matching and prevents a duplicate
    # coverage row for ``app.test`` beside structured ``https://app.test``. An
    # explicit non-default port is never widened, and explicit schemes stay exact.
    scheme_less = structured if structured.scheme is None else declared
    return scheme_less.port is None


def reconcile_instruction_targets(
    structured_target_values: list[str],
    instruction: str,
) -> list[str]:
    """Return full operator-declared target identities absent from structured scope."""
    declared_values = extract_instruction_targets(instruction)
    structured = [
        reference
        for value in structured_target_values
        if (reference := _asset_reference(value)) is not None
    ]
    missing: list[str] = []
    for value in declared_values:
        reference = _asset_reference(value)
        if reference is not None and not any(
            _structured_reference_covers(known, reference) for known in structured
        ):
            missing.append(value)
    return missing


def _clause_asset_references(clause: str) -> list[_AssetReference]:
    return [
        reference
        for candidate in _candidate_tokens(clause)
        if (reference := _asset_reference(candidate.value)) is not None
    ]


def _target_qualified_credential_opt_out(clause: str) -> bool:
    opt_out = _CREDENTIAL_USE_OPT_OUT_RE.search(clause)
    if opt_out is None:
        return False
    return any(
        candidate.start >= opt_out.end()
        and re.fullmatch(
            r"\s+(?:for|on|at)\s+",
            clause[opt_out.end() : candidate.start],
            re.IGNORECASE,
        )
        for candidate in _candidate_tokens(clause)
    )


def _clause_has_positive_auth_signal(clause: str) -> bool:
    if _AUTH_NEGATION_RE.search(clause):
        return False
    credential_provision = bool(_CREDENTIAL_PROVISION_RE.search(clause))
    if credential_provision and _CREDENTIAL_OBSERVATION_RE.search(clause):
        credential_provision = False
    password_value = bool(_PASSWORD_VALUE_RE.search(clause))
    if password_value and _PASSWORD_DESCRIPTION_RE.search(clause):
        password_value = False
    return bool(
        _AUTH_TEST_RE.search(clause)
        or _CREDENTIAL_VALUE_RE.search(clause)
        or credential_provision
        or password_value
    )


def _auth_clause_survives_exclusions(
    clause: str,
    exclusions: list[_AssetReference],
) -> bool:
    assets = _clause_asset_references(clause)
    return not assets or any(
        not any(_exclusion_covers(exclusion, asset) for exclusion in exclusions) for asset in assets
    )


def detect_auth_expectation(instruction: str) -> bool:
    """Return whether instructions affirmatively require or provide authenticated access.

    Detection is clause-based so explicit negations such as "no authenticated
    testing" do not become positive merely because they contain an auth keyword.
    Credential fields support ordinary usernames and passwords; an email address,
    generic authorization wording, contact details, or a login URL alone is not an
    authentication-testing mandate.
    """
    if not instruction or not instruction.strip():
        return False

    clauses = _split_clauses(instruction.replace("\n", ";"))
    positive_clauses = [
        (index, clause)
        for index, clause in enumerate(clauses)
        if _clause_has_positive_auth_signal(clause)
    ]
    opt_out_clauses = [
        (index, clause)
        for index, clause in enumerate(clauses)
        if _AUTH_HARD_OPT_OUT_RE.search(clause) or _target_qualified_credential_opt_out(clause)
    ]

    if not positive_clauses:
        return False
    if not opt_out_clauses:
        return True

    # A target-free opt-out ("do not use these credentials" / "no authenticated
    # testing") is engagement-wide and wins. Target-specific opt-outs narrow only
    # those targets, so a positive requirement for another target must survive.
    qualified_opt_outs: list[tuple[int, str, list[_AssetReference]]] = [
        (index, clause, _clause_asset_references(clause)) for index, clause in opt_out_clauses
    ]
    target_free = [(index, clause) for index, clause, assets in qualified_opt_outs if not assets]
    if any(_ENGAGEMENT_AUTH_OPT_OUT_RE.search(clause) for _index, clause in target_free):
        return False
    if target_free:
        # A credential set can be revoked/superseded and replaced later. An
        # affirmative clause after the last set-specific prohibition is treated as
        # the replacement; otherwise the prohibition wins.
        last_opt_out = max(index for index, _clause in target_free)
        if not any(index > last_opt_out for index, _clause in positive_clauses):
            return False

    excluded_assets = [asset for _index, _clause, assets in qualified_opt_outs for asset in assets]
    return any(
        _auth_clause_survives_exclusions(clause, excluded_assets)
        for _index, clause in positive_clauses
    )


def report_claims_no_credentials(*texts: str) -> bool:
    """Return whether report prose claims the engagement lacked credentials.

    Security findings such as "no credentials were exposed/stored in logs" are not
    engagement-methodology claims and therefore do not trigger this classifier.
    """
    joined = "\n".join(text for text in texts if text)
    if not joined:
        return False
    for unit in re.split(r"(?<=[.!?])\s+|\n+", joined):
        for match in _NO_CREDENTIALS_ENGAGEMENT_RE.finditer(unit):
            prefix = unit[: match.start()]
            suffix = unit[match.end() : match.end() + 100]
            if _NO_CREDENTIALS_FINDING_PREFIX_RE.search(prefix):
                continue
            if _NO_CREDENTIALS_FINDING_SUFFIX_RE.match(suffix):
                continue
            return True
    return False


def report_documents_auth_blocker(*texts: str) -> bool:
    """Return whether report prose documents a concrete authentication blocker.

    A bare mention of MFA, OTP, an authenticator, or a verification code is not a
    blocker.  The text must say login/authentication failed or causally associate an
    authentication factor with blocked or unavailable access.
    """
    joined = "\n".join(text for text in texts if text)
    if not joined:
        return False
    units = re.split(r"(?<=[.!?])\s+|\n+", joined)
    for unit in units:
        if _SELF_CAUSED_AUTH_FAILURE_RE.search(unit):
            continue
        if any(pattern.search(unit) for pattern in _AUTH_BLOCKER_PATTERNS):
            return True
    return False
