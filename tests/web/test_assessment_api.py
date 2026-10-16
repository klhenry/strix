"""The model-comparison endpoint uses existing scanner API authentication."""

from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from strix.web.app import create_app


def test_assessment_requires_key_and_passes_model(monkeypatch, tmp_path):
    monkeypatch.setenv("API_KEY", "fixture-scanner-token")
    app = create_app(tmp_path)
    start = AsyncMock(return_value="accountable-evaluation")
    app.state.scan_manager.start_scan = start
    body = {
        "target_urls": ["https://example.test"],
        "model": "openrouter/z-ai/glm-5.3",
        "instruction": "Use the authorized test account.",
        "scan_mode": "deep",
    }
    client = TestClient(app)
    assert client.post("/api/v1/assessments", json=body).status_code == 401
    response = client.post(
        "/api/v1/assessments", json=body, headers={"Authorization": "Bearer fixture-scanner-token"}
    )
    assert response.status_code == 200
    assert response.json()["external_scan_id"] == "accountable-evaluation"
    start.assert_awaited_once_with(
        targets=["https://example.test/"],
        model=body["model"],
        instruction=body["instruction"],
        scan_mode="deep",
    )


def test_private_evidence_requires_key_and_preserves_sdk_store(monkeypatch, tmp_path):
    import io
    import zipfile

    monkeypatch.setenv("API_KEY", "fixture-scanner-token")
    run = tmp_path / "finished"
    (run / ".state").mkdir(parents=True)
    (run / ".state/agents.db").write_bytes(b"fixture-sdk-conversation")
    (run / "run.json").write_text("{}")
    app = create_app(tmp_path)
    client = TestClient(app)
    assert client.get("/api/v1/scans/finished/evidence").status_code == 401
    response = client.get(
        "/api/v1/scans/finished/evidence", headers={"Authorization": "Bearer fixture-scanner-token"}
    )
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert archive.read(".state/agents.db") == b"fixture-sdk-conversation"
        assert set(archive.namelist()) == {"run.json", ".state/agents.db"}
