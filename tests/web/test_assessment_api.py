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
