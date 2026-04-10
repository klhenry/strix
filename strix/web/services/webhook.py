"""Webhook callback utilities: HMAC signing, callback POST, S3 upload."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from pathlib import Path
from typing import Any

import requests
from tenacity import retry, retry_if_exception, retry_if_not_exception_type, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


class CallbackDeliveryError(Exception):
    """Raised when a callback or upload cannot be delivered (e.g. wrong host)."""

    def __init__(self, message: str, *, is_connection_error: bool = False) -> None:
        super().__init__(message)
        self.is_connection_error = is_connection_error


def sign_payload(body: str, secret: str) -> tuple[str, str]:
    """Compute HMAC-SHA256 signature and timestamp for a request body.

    Signature is computed over ``{timestamp}.{body}`` to prevent replay attacks.
    """
    timestamp = str(int(time.time()))
    message = f"{timestamp}.{body}"
    signature = hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return signature, timestamp


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=2, max=30),
    retry=retry_if_not_exception_type(CallbackDeliveryError),
)
def post_callback(url: str, payload: dict[str, Any], secret: str) -> bool:
    """POST an HMAC-signed JSON payload to the callback URL. Retries 3x.

    Raises ``CallbackDeliveryError`` immediately on connection errors (wrong
    host, refused, DNS failure) since retrying cannot fix those.
    """
    body = json.dumps(payload)
    signature, timestamp = sign_payload(body, secret)

    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Timestamp": timestamp,
    }

    logger.info("Sending callback to %s (status=%s)", url, payload.get("status"))
    try:
        resp = requests.post(url, data=body, headers=headers, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as exc:
        raise CallbackDeliveryError(
            f"Connection failed for callback to {url}: {exc}",
            is_connection_error=True,
        ) from exc
    logger.info("Callback accepted: %s %s", resp.status_code, resp.reason)
    return True


def _is_presigned_s3_url(url: str) -> bool:
    """Return True if the URL looks like a pre-signed S3 URL."""
    return "X-Amz-Signature" in url or "x-amz-signature" in url


def _is_retryable_upload_error(exc: BaseException) -> bool:
    """Return True for transient errors worth retrying (5xx, timeouts)."""
    if isinstance(exc, CallbackDeliveryError):
        return False
    if isinstance(exc, requests.exceptions.HTTPError) and exc.response is not None:
        return exc.response.status_code >= 500
    return not isinstance(exc, requests.exceptions.HTTPError)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=2, max=30),
    retry=retry_if_exception(_is_retryable_upload_error),
)
def upload_pdf(upload_url: str, pdf_path: Path, api_key: str = "") -> bool:
    """PUT the PDF report to the upload endpoint.

    For pre-signed S3 URLs, only ``Content-Type`` is sent (no Bearer token)
    because S3 rejects requests that mix pre-signed query-string auth with an
    ``Authorization`` header.

    Raises ``CallbackDeliveryError`` immediately on connection errors.
    """
    if not pdf_path.exists():
        logger.error("PDF not found at %s", pdf_path)
        return False

    pdf_bytes = pdf_path.read_bytes()
    logger.info("Uploading PDF (%d KB) to %s", len(pdf_bytes) // 1024, upload_url)

    headers: dict[str, str] = {"Content-Type": "application/pdf"}
    if api_key and not _is_presigned_s3_url(upload_url):
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        resp = requests.put(
            upload_url,
            data=pdf_bytes,
            headers=headers,
            timeout=120,
        )
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as exc:
        raise CallbackDeliveryError(
            f"Connection failed for PDF upload to {upload_url}: {exc}",
            is_connection_error=True,
        ) from exc
    logger.info("PDF upload accepted: %s %s", resp.status_code, resp.reason)
    return True


def build_findings_summary(run_dir: Path) -> dict[str, int]:
    """Parse completed scan results into severity counts by CVSS buckets."""
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}

    events_file = run_dir / "events.jsonl"
    if not events_file.exists():
        return summary

    with events_file.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue

            if evt.get("event_type") != "finding.created":
                continue

            payload = evt.get("payload") or {}
            report = payload.get("report") or {}
            cvss = report.get("cvss")

            if cvss is None:
                summary["informational"] += 1
            elif cvss >= 9.0:
                summary["critical"] += 1
            elif cvss >= 7.0:
                summary["high"] += 1
            elif cvss >= 4.0:
                summary["medium"] += 1
            elif cvss > 0:
                summary["low"] += 1
            else:
                summary["informational"] += 1

    return summary
