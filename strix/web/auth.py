"""Bearer token authentication for the webhook API."""

from __future__ import annotations

import os

from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer_scheme = HTTPBearer(auto_error=False)


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
    if credentials is None or credentials.credentials != api_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )
    return credentials.credentials
