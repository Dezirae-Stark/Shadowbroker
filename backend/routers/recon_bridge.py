"""Recon bridge — HTTP API consumed by deep-eye.

Endpoints (Plan A):
  POST /bridge/scope/check          — validate a target against a scope manifest
  GET  /bridge/enrich/{target}      — aggregate enrichment intel (Task 12)

Auth: HMAC-SHA256 (services.recon_bridge.hmac_auth) on every endpoint, with
a test-only bypass toggleable via set_hmac_bypass_for_tests().
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from services.recon_bridge.scope_manifest import (
    ScopeManifest,
    ScopeManifestError,
    Target,
    load_manifest,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/bridge", tags=["recon-bridge"])


# Configuration (set at app boot — Task 14)
_scope_dir: Optional[Path] = None
_hmac_bypass = False


def set_scope_manifest_dir(path: Path) -> None:
    global _scope_dir
    _scope_dir = Path(path)


def set_hmac_bypass_for_tests(enabled: bool) -> None:
    """Test-only toggle. Production code MUST NOT call this.

    The hmac dependency on each endpoint reads this flag and returns early when
    True. Production startup leaves it False.
    """
    global _hmac_bypass
    _hmac_bypass = enabled


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class TargetIn(BaseModel):
    kind: str = Field(..., pattern=r"^(url|ip|cidr|asn|pin)$")
    value: str = Field(..., min_length=1)


class ScopeCheckRequest(BaseModel):
    target: TargetIn
    scope_token: str = Field(..., min_length=1)


class ScopeCheckResponse(BaseModel):
    in_scope: bool
    reason: str
    manifest_id: str
    mode: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_scope(scope_token: str) -> ScopeManifest:
    if _scope_dir is None:
        raise HTTPException(500, "scope manifest dir not configured")
    path = _scope_dir / f"{scope_token}.yml"
    if not path.exists():
        raise HTTPException(404, f"no manifest for scope_token={scope_token!r}")
    try:
        return load_manifest(path)
    except ScopeManifestError as exc:
        raise HTTPException(500, f"manifest load failed: {exc}")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scope/check", response_model=ScopeCheckResponse)
async def scope_check(req: ScopeCheckRequest, request: Request) -> ScopeCheckResponse:
    if not _hmac_bypass:
        await _enforce_hmac(request)

    manifest = _load_scope(req.scope_token)
    target = Target(kind=req.target.kind, value=req.target.value)
    result = manifest.validate(target)
    return ScopeCheckResponse(
        in_scope=result.in_scope,
        reason=result.reason,
        manifest_id=result.manifest_id,
        mode=result.mode,
    )


# ---------------------------------------------------------------------------
# HMAC enforcement (used by both endpoints; tests can bypass)
# ---------------------------------------------------------------------------

async def _enforce_hmac(request: Request) -> None:
    """Verify the inbound HMAC signature; raise HTTPException(401) on failure.

    Wired up properly in Task 13 once we have the key store. For Plan A's
    early endpoints, this is a placeholder that always rejects unless the
    test bypass is active — production uses Task 13's real implementation.
    """
    raise HTTPException(
        501,
        "HMAC enforcement not yet wired (Task 13). Tests use set_hmac_bypass_for_tests(True).",
    )
