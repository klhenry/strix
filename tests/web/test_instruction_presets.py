"""Credential handoff must be exact, short-lived, single-use, and authenticated."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from strix.web.app import create_app
from strix.web.models.api_v1 import InstructionPresetRequest, ScanRequest
from strix.web.services.instruction_presets import InstructionPresets


def preset():
    return InstructionPresetRequest(
        target_url="https://app.example.test/?evaluation=nonce",
        callback_origin="https://app.example.test",
        instruction="Private authorized test instructions",
    )


def scan(**changes):
    values = {
        "scan_id": "unique",
        "scan_type": "penetration_test",
        "target_url": "https://app.example.test/?evaluation=nonce",
        "callback_url": "https://app.example.test/webhooks/token",
        "upload_url": "https://storage.example.test/report",
    }
    return ScanRequest(**{**values, **changes})


def test_preset_never_applies_to_other_targets_origins_or_scan_types():
    store = InstructionPresets()
    store.register(preset())
    for request in [
        scan(target_url="https://app.example.test/"),
        scan(target_url="https://app.example.test/?evaluation=other"),
        scan(callback_url="https://other.example.test/webhooks/token"),
        scan(scan_type="vulnerability_scan"),
        scan(target_urls=["https://other.example.test/"]),
    ]:
        assert store.consume(request) == ""
    assert store.consume(scan()) == preset().instruction
    assert store.consume(scan(scan_id="second")) == ""


def test_expiry_duplicate_and_revocation(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("strix.web.services.instruction_presets.time.monotonic", lambda: now[0])
    store = InstructionPresets()
    identifier = store.register(preset())
    with pytest.raises(RuntimeError, match="already matches"):
        store.register(preset())
    store.revoke(identifier)
    assert store.consume(scan()) == ""
    store.register(preset())
    now[0] += 901
    assert store.consume(scan()) == ""
    store.register(preset())


def test_preset_api_authentication_and_no_secret_readback(monkeypatch, tmp_path):
    monkeypatch.setenv("API_KEY", "fixture-token")
    client = TestClient(create_app(tmp_path))
    body = preset().model_dump(mode="json")
    assert client.post("/api/v1/instruction-presets", json=body).status_code == 401
    response = client.post(
        "/api/v1/instruction-presets", json=body, headers={"Authorization": "Bearer fixture-token"}
    )
    assert response.status_code == 200
    assert "Private authorized" not in response.text
    identifier = response.json()["preset_id"]
    assert client.delete(f"/api/v1/instruction-presets/{identifier}").status_code == 401
    assert client.delete(
        f"/api/v1/instruction-presets/{identifier}",
        headers={"Authorization": "Bearer fixture-token"},
    ).json() == {"revoked": True}


@pytest.mark.parametrize(
    "origin",
    [
        "http://app.example.test",
        "https://app.example.test/path",
        "https://app.example.test/?query=x",
        "https://user:password@app.example.test",
    ],
)
def test_callback_must_be_a_trusted_https_origin(origin):
    with pytest.raises(ValidationError):
        InstructionPresetRequest(**{**preset().model_dump(), "callback_origin": origin})
