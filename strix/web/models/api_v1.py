"""Pydantic models for the v1 webhook API."""

from __future__ import annotations

import ipaddress
from typing import Literal
from urllib.parse import urlparse

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    field_validator,
    model_validator,
)


def _is_loopback_url(url: str) -> bool:
    """Return True if the URL points to localhost or a loopback address."""
    parsed = urlparse(str(url))
    hostname = parsed.hostname or ""

    if hostname in ("localhost", ""):
        return True

    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    else:
        return addr.is_loopback


class ScanRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    scan_id: str
    scan_type: Literal["vulnerability_scan", "penetration_test"]
    target_url: HttpUrl | None = None
    target_urls: list[HttpUrl] = Field(
        default_factory=list,
        validation_alias=AliasChoices("target_urls", "targets"),
    )
    instruction: str = Field(
        default="",
        validation_alias=AliasChoices(
            "instruction",
            "instructions",
            "custom_instruction",
            "custom_instructions",
        ),
    )
    callback_url: HttpUrl
    upload_url: str  # pre-signed S3 URL

    @model_validator(mode="after")
    def require_target(self) -> ScanRequest:
        if self.target_url is None and not self.target_urls:
            msg = "at least one target_url or target_urls entry is required"
            raise ValueError(msg)
        return self

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

    def resolved_targets(self) -> list[str]:
        """Return all authorized targets in request order without duplicates."""
        raw_targets = ([self.target_url] if self.target_url is not None else []) + self.target_urls
        targets: list[str] = []
        for raw_target in raw_targets:
            target = str(raw_target)
            if target not in targets:
                targets.append(target)
        return targets


class ScanAcceptedResponse(BaseModel):
    external_scan_id: str
    status: str = "accepted"


class ScanStatusResponse(BaseModel):
    status: Literal["pending", "in_progress", "completed", "failed", "callback_failed"]
    progress: int = 0
    error_message: str | None = None
