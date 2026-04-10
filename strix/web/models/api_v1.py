"""Pydantic models for the v1 webhook API."""

from __future__ import annotations

import ipaddress
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, HttpUrl, field_validator


def _is_loopback_url(url: str) -> bool:
    """Return True if the URL points to localhost or a loopback address."""
    parsed = urlparse(str(url))
    hostname = parsed.hostname or ""

    if hostname in ("localhost", ""):
        return True

    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_loopback
    except ValueError:
        return False


class ScanRequest(BaseModel):
    scan_id: str
    scan_type: Literal["vulnerability_scan", "penetration_test"]
    target_url: HttpUrl
    callback_url: HttpUrl
    upload_url: str  # pre-signed S3 URL

    @field_validator("callback_url")
    @classmethod
    def reject_loopback_callback(cls, v: HttpUrl) -> HttpUrl:
        if _is_loopback_url(str(v)):
            msg = (
                "callback_url must not point to localhost or a loopback address — "
                "the scan will be unable to deliver results"
            )
            raise ValueError(msg)
        return v


class ScanAcceptedResponse(BaseModel):
    external_scan_id: str
    status: str = "accepted"


class ScanStatusResponse(BaseModel):
    status: Literal["pending", "in_progress", "completed", "failed", "callback_failed"]
    progress: int = 0
    error_message: str | None = None
