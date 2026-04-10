"""Tests for v1 API model validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from strix.web.models.api_v1 import ScanRequest

_VALID_BASE = {
    "scan_id": "test-123",
    "scan_type": "vulnerability_scan",
    "target_url": "https://example.com",
    "upload_url": "https://s3.amazonaws.com/bucket/key?X-Amz-Signature=abc",
}


def _make_request(**overrides: str) -> ScanRequest:
    return ScanRequest(**{**_VALID_BASE, **overrides})


class TestCallbackUrlLoopbackRejection:
    def test_rejects_localhost(self) -> None:
        with pytest.raises(ValidationError, match="localhost.*loopback"):
            _make_request(callback_url="https://localhost:3000/webhooks/callback")

    def test_rejects_localhost_no_port(self) -> None:
        with pytest.raises(ValidationError, match="localhost.*loopback"):
            _make_request(callback_url="https://localhost/webhooks/callback")

    def test_rejects_127_0_0_1(self) -> None:
        with pytest.raises(ValidationError, match="localhost.*loopback"):
            _make_request(callback_url="https://127.0.0.1:3000/webhooks/callback")

    def test_rejects_ipv6_loopback(self) -> None:
        with pytest.raises(ValidationError, match="localhost.*loopback"):
            _make_request(callback_url="https://[::1]:3000/webhooks/callback")

    def test_accepts_public_url(self) -> None:
        req = _make_request(
            callback_url="https://app.accountablehq.com/webhooks/security_scans/abc/callback"
        )
        assert "accountablehq.com" in str(req.callback_url)

    def test_accepts_private_network_url(self) -> None:
        req = _make_request(callback_url="https://internal.example.com/callback")
        assert req.callback_url is not None
