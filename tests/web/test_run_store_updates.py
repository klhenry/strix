"""Dashboard projections must show the SDK's final finding revisions and deletions."""

import json

from strix.web.services.run_store import RunStore


def test_current_index_replaces_older_finding_events(tmp_path):
    run = tmp_path / "revised"
    run.mkdir()
    (run / "events.jsonl").write_text(
        json.dumps(
            {
                "event_type": "finding.created",
                "payload": {"report": {"id": "vuln-0001", "title": "Original", "severity": "high"}},
            }
        )
        + "\n"
    )
    index = run / "vulnerabilities.json"
    index.write_text(json.dumps([{"id": "vuln-0001", "title": "Validated", "severity": "low"}]))
    store = RunStore(tmp_path)
    detail = store.get_run("revised")
    assert detail.vulnerabilities[0]["title"] == "Validated"
    assert detail.summary.severity_counts["high"] == 0
    assert detail.summary.severity_counts["low"] == 1
    index.write_text("[]")
    assert store.get_run("revised").summary.vulnerability_count == 0
