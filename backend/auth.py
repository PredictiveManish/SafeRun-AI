"""
API-key authentication.

SafeRun executes arbitrary code, so every endpoint that scans, executes or
reads history has to be authenticated. Keys come from SAFERUN_API_KEYS
(comma separated); if none is configured the endpoints refuse to serve
unless SAFERUN_ALLOW_ANONYMOUS=1 was set deliberately for local use.

Policy overrides are a separate, stronger credential (SAFERUN_ADMIN_KEY):
turning the policy engine off is an operator decision, not a client one.
"""

import secrets
from typing import List, Optional

from fastapi import Header, HTTPException, status

from backend.config import settings


def _matches(candidate: str, keys: List[str]) -> bool:
    """Constant-time comparison against every configured key."""
    matched = False
    for key in keys:
        if secrets.compare_digest(candidate, key):
            matched = True
    return matched


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> str:
    """FastAPI dependency: reject requests without a valid X-API-Key."""
    keys = settings.api_key_list

    if not keys:
        if settings.allow_anonymous:
            return "anonymous"
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "This server has no API key configured. Set SAFERUN_API_KEYS "
                "before exposing it, or set SAFERUN_ALLOW_ANONYMOUS=1 for a "
                "local, throwaway instance."
            ),
        )

    if not x_api_key or not _matches(x_api_key, keys):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return x_api_key


def require_admin_key(x_admin_key: Optional[str] = Header(default=None)) -> None:
    """FastAPI dependency: reject requests without the admin key."""
    admin = settings.admin_key
    if not admin or not x_admin_key or not secrets.compare_digest(x_admin_key, admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Policy override requires an admin key (X-Admin-Key)",
        )
