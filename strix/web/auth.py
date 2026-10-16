"""Bearer token authentication for the webhook API."""

from __future__ import annotations

import base64
import binascii
import os
import secrets
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.responses import JSONResponse, Response


if TYPE_CHECKING:
    from starlette.middleware.base import RequestResponseEndpoint


_bearer_scheme = HTTPBearer(auto_error=False)


def _authorization_mode(header: str, expected: str) -> Literal["bearer", "basic"] | None:
    scheme, _, value = header.partition(" ")
    supplied = value
    if scheme.lower() == "basic":
        try:
            username, separator, supplied = (
                base64.b64decode(value, validate=True).decode().partition(":")
            )
        except (ValueError, binascii.Error):
            return None
        if username != "operator" or not separator:
            return None
    elif scheme.lower() != "bearer":
        return None
    if secrets.compare_digest(supplied.encode(), expected.encode()):
        return "basic" if scheme.lower() == "basic" else "bearer"
    return None


async def protect_operator_console(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    """Protect scan controls and confidential artifacts using the existing service key."""
    key = os.environ.get("API_KEY")
    if not key or request.url.path == "/health":
        return await call_next(request)
    mode = _authorization_mode(request.headers.get("Authorization", ""), key)
    if mode is None:
        return JSONResponse(
            {"detail": "Invalid or missing API key"},
            status_code=401,
            headers={
                "WWW-Authenticate": 'Basic realm="Strix operator"',
                "Cache-Control": "no-store",
            },
        )
    if mode == "basic" and request.method not in {"GET", "HEAD", "OPTIONS"}:
        try:
            origin = urlsplit(request.headers.get("Origin", ""))
        except ValueError:
            return JSONResponse({"detail": "Invalid request origin"}, status_code=403)
        local = request.url.hostname in {"localhost", "127.0.0.1", "::1"}
        if (
            origin.netloc.lower() != request.headers.get("Host", "").lower()
            or origin.username
            or origin.path not in {"", "/"}
            or origin.query
            or origin.fragment
            or not (origin.scheme == "https" or (local and origin.scheme == "http"))
        ):
            return JSONResponse(
                {"detail": "Same-origin operator request required"}, status_code=403
            )
    response = await call_next(request)
    response.headers["Cache-Control"] = "private, no-store"
    return response


async def require_api_key(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer_scheme),
) -> str:
    """FastAPI dependency that validates the Bearer token against API_KEY env var."""
    api_key = os.environ.get("API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="API_KEY not configured on server",
        )
    if credentials is None or not secrets.compare_digest(
        credentials.credentials.encode(), api_key.encode()
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )
    return credentials.credentials
