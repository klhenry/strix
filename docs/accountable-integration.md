# Accountable integration

This fork follows upstream Strix 1.7 while retaining the Accountable Railway
service, branded HTML/PDF/JSON/SARIF reports, dashboard, and signed callbacks.

The CLI uses upstream's Docker backend by default. The web service registers a
`railway` backend around the Agents SDK Unix local session. Railway supplies the
outer container; each spawned scan worker owns its workspace, Caido proxy,
browser session, SDK conversation store, and report state. Model tools receive
only runtime environment values, not the service's provider/API/webhook secrets.

## Existing app API

`POST /api/v1/scans` continues accepting `scan_id`, `scan_type`, `target_url` or
`target_urls`, `instruction`, `callback_url`, and `upload_url`. It continues
returning `external_scan_id`. Existing signed heartbeat/completion callbacks and
presigned PDF uploads are preserved. `model` optionally selects a provider model
for one request; omitting it uses the deployed `STRIX_LLM` default.

## Authenticated assessments

Supply the login URL, authorized test credentials, exact account/tenant and rules
of engagement in `instruction`. Specify which hosts require authenticated testing,
and prohibit changes to unrelated accounts or destructive actions as appropriate.
The upstream browser CLI performs login and protected-page testing. These operator
rules propagate into every child agent's system scope.

Accountable's finish tool requires per-asset scope coverage and limitations.
Providing credentials cannot silently become an unauthenticated-only report:
each relevant target needs authenticated coverage or a documented causal blocker.
A scan cannot succeed without completed narrative sections and a generated PDF;
the app only receives completion after the PDF upload succeeds.

Do not commit credentials or API keys. Provider and API settings belong in Railway
variables. Benchmark requests must use identical authorized scope, instructions,
scan mode and budget, and must retain run records, coverage, findings and PDF output.
Select a model using verified coverage, reproducibility, report accuracy and
completion reliability, with cost and duration as secondary comparisons.


For a CLI comparison without an app callback, send an authenticated
`POST /api/v1/assessments` with `target_urls`, `instruction`, `model`, and
`scan_mode`. Poll `/api/v1/scans/{external_scan_id}/status` using the same API key.
The existing `/api/v1/scans` callback contract is unchanged.

## Model evaluation (2026-10-16)

All three requested OpenRouter models completed the same initial deep assessment
with the same three-host scope, employee login and $6 scan budget. Saved SDK
conversations confirmed protected-dashboard access for every model. Private
reports and evidence are retained outside this public repository.

| Model | Duration | Scan-record LLM cost | Review outcome |
| --- | --- | --- | --- |
| GLM 5.3 | 13m 58s | $1.46 | Completed; its principal finding was not substantiated as written. |
| DeepSeek V4.1 Flash | 50m 26s | $1.77 | Selected for stronger discovery and authenticated coverage; three findings supported after triage. |
| Muse Spark Open | 4m 50s | $5.93 | Completed quickly; no confirmed findings and less depth before budget wind-down. |

These are scan-record costs, not a reconciled provider invoice. Eight raw
DeepSeek findings do not mean eight verified vulnerabilities: five require
further validation or lack demonstrated unauthorized impact. GLM and DeepSeek
received the same live scope/evidence reminder. Review copies remove unrelated
customer details and signed access tokens, and explain reviewer dispositions.

The evaluation exposed a live-instruction delivery gap: operator comments must
reach every active SDK agent, including waiting children, rather than only the
root. Default Accountable operating instructions now explicitly constrain tenant
access, persistent changes and external canaries, and distinguish observations
from demonstrated exploitation. These are model instructions, not a network
security boundary; deployments still require authorized scope and review of
significant findings. Long reports also now retain print margins and running
confidentiality headers/page numbers on continuation pages.
