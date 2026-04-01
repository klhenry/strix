"""Pydantic models for the v1 webhook API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, HttpUrl


class ScanRequest(BaseModel):
    scan_id: str
    scan_type: Literal["vulnerability_scan", "penetration_test"]
    target_url: HttpUrl
    callback_url: HttpUrl
    upload_url: str  # pre-signed S3 URL


class ScanAcceptedResponse(BaseModel):
    external_scan_id: str
    status: str = "accepted"


class ScanStatusResponse(BaseModel):
    status: Literal["pending", "in_progress", "completed", "failed"]
    progress: int = 0
    error_message: str | None = None
