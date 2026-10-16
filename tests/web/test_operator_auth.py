"""Scanner artifacts and controls require operator authentication in production."""

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from strix.web.app import create_app, run_server


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/scans/private",
        "/api/scans/private/findings",
        "/api/scans/private/events/stream",
        "/scans/private/reports/pdf",
        "/openapi.json",
    ],
)
def test_confidential_routes_require_key(monkeypatch, tmp_path, path):
    monkeypatch.setenv("API_KEY", "fixture-private-key")
    client = TestClient(create_app(tmp_path))
    response = client.get(path)
    assert response.status_code == 401
    assert response.headers["Cache-Control"] == "no-store"
    assert client.get("/health").status_code == 200
    assert (
        client.get("/", headers={"Authorization": "Bearer fixture-private-key"}).status_code == 200
    )
    assert client.get("/", auth=("operator", "fixture-private-key")).status_code == 200
    assert client.get("/", auth=("operator", "wrong")).status_code == 401
    assert client.get("/", headers={"Authorization": "Basic malformed"}).status_code == 401


def test_control_auth_and_browser_origin_guard(monkeypatch, tmp_path):
    monkeypatch.setenv("API_KEY", "fixture-private-key")
    app = create_app(tmp_path)
    app.state.scan_manager.start_scan = AsyncMock(return_value="fixture-run")
    client = TestClient(app)
    data = {"target": "https://example.test/"}
    assert client.post("/api/scans", data=data).status_code == 401
    assert (
        client.post("/api/scans", data=data, auth=("operator", "fixture-private-key")).status_code
        == 403
    )
    assert (
        client.post(
            "/api/scans",
            data=data,
            auth=("operator", "fixture-private-key"),
            headers={"Origin": "https://attacker.example"},
        ).status_code
        == 403
    )
    assert app.state.scan_manager.start_scan.await_count == 0
    response = client.post(
        "/api/scans",
        data=data,
        auth=("operator", "fixture-private-key"),
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert app.state.scan_manager.start_scan.await_count == 1
    response = client.post(
        "/api/scans",
        data=data,
        headers={"Authorization": "Bearer fixture-private-key"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert app.state.scan_manager.start_scan.await_count == 2


def test_public_bind_requires_key(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.setattr("strix.web.app._load_strix_config", lambda: None)
    with pytest.raises(RuntimeError, match="API_KEY is required"):
        run_server(host="0.0.0.0")
