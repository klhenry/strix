"""Tests for v1 API model validation."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from strix.web.models.api_v1 import ScanRequest


_VALID_BASE = {
    "scan_id": "test-123",
    "scan_type": "vulnerability_scan",
    "target_url": "https://example.com",
    "upload_url": "https://s3.amazonaws.com/bucket/key?X-Amz-Signature=abc",
}


def _make_request(**overrides: Any) -> ScanRequest:
    return ScanRequest(**{**_VALID_BASE, **overrides})


class TestTargetsAndInstructions:
    def test_accepts_legacy_singular_target(self) -> None:
        req = _make_request(callback_url="https://app.example.com/callback")

        assert req.resolved_targets() == ["https://example.com/"]

    def test_combines_and_deduplicates_multiple_targets(self) -> None:
        req = _make_request(
            callback_url="https://app.example.com/callback",
            target_urls=["https://example.com", "https://setmore.example.com"],
        )

        assert req.resolved_targets() == [
            "https://example.com/",
            "https://setmore.example.com/",
        ]

    def test_accepts_targets_and_custom_instructions_aliases(self) -> None:
        req = ScanRequest(
            scan_id="test-123",
            scan_type="penetration_test",
            targets=["https://wellreceived.example.com", "https://setmore.example.com"],
            custom_instructions="Use the approved admin and staff audit accounts.",
            callback_url="https://app.example.com/callback",
            upload_url="https://s3.amazonaws.com/bucket/report",
        )

        assert req.resolved_targets() == [
            "https://wellreceived.example.com/",
            "https://setmore.example.com/",
        ]
        assert req.instruction == "Use the approved admin and staff audit accounts."

    def test_rejects_request_without_targets(self) -> None:
        request = {key: value for key, value in _VALID_BASE.items() if key != "target_url"}
        request["callback_url"] = "https://app.example.com/callback"

        with pytest.raises(ValidationError, match="at least one target_url"):
            ScanRequest(**request)


class TestCallbackUrlLoopbackRejection:
    def test_rejects_localhost(self) -> None:
        with pytest.raises(ValidationError, match=r"localhost.*loopback"):
            _make_request(callback_url="https://localhost:3000/webhooks/callback")

    def test_rejects_localhost_no_port(self) -> None:
        with pytest.raises(ValidationError, match=r"localhost.*loopback"):
            _make_request(callback_url="https://localhost/webhooks/callback")

    def test_rejects_127_0_0_1(self) -> None:
        with pytest.raises(ValidationError, match=r"localhost.*loopback"):
            _make_request(callback_url="https://127.0.0.1:3000/webhooks/callback")

    def test_rejects_ipv6_loopback(self) -> None:
        with pytest.raises(ValidationError, match=r"localhost.*loopback"):
            _make_request(callback_url="https://[::1]:3000/webhooks/callback")

    def test_accepts_public_url(self) -> None:
        req = _make_request(
            callback_url="https://app.accountablehq.com/webhooks/security_scans/abc/callback"
        )
        assert "accountablehq.com" in str(req.callback_url)

    def test_accepts_private_network_url(self) -> None:
        req = _make_request(callback_url="https://internal.example.com/callback")
        assert req.callback_url is not None
