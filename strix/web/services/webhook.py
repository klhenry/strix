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
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


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


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=30))
def post_callback(url: str, payload: dict[str, Any], secret: str) -> bool:
    """POST an HMAC-signed JSON payload to the callback URL. Retries 3x."""
    body = json.dumps(payload)
    signature, timestamp = sign_payload(body, secret)

    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Timestamp": timestamp,
    }

    logger.info("Sending callback to %s (status=%s)", url, payload.get("status"))
    resp = requests.post(url, data=body, headers=headers, timeout=30)
    resp.raise_for_status()
    logger.info("Callback accepted: %s %s", resp.status_code, resp.reason)
    return True


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=30))
def upload_pdf(upload_url: str, pdf_path: Path, api_key: str = "") -> bool:
    """PUT the PDF report to the upload endpoint with Bearer auth."""
    if not pdf_path.exists():
        logger.error("PDF not found at %s", pdf_path)
        return False

    pdf_bytes = pdf_path.read_bytes()
    logger.info("Uploading PDF (%d KB) to %s", len(pdf_bytes) // 1024, upload_url)

    headers: dict[str, str] = {"Content-Type": "application/pdf"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    resp = requests.put(
        upload_url,
        data=pdf_bytes,
        headers=headers,
        timeout=120,
    )
    resp.raise_for_status()
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
