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
