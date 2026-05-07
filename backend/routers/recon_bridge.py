"""Recon bridge — HTTP API consumed by deep-eye.

Endpoints (Plan A):
  POST /bridge/scope/check          — validate a target against a scope manifest
  GET  /bridge/enrich/{target}      — aggregate enrichment intel (Task 12)

Auth: HMAC-SHA256 (services.recon_bridge.hmac_auth) on every endpoint, with
a test-only bypass toggleable via set_hmac_bypass_for_tests().
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import unquote, urlparse

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from services.recon_bridge.enrichment_aggregator import EnrichmentResult
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
_aggregator: Any = None


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


def set_enrichment_aggregator(agg: Any) -> None:
    """Inject the EnrichmentAggregator at app boot. Pass None to clear (used
    by tests to assert the not-initialized branch)."""
    global _aggregator
    _aggregator = agg


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


class EnrichmentResponse(BaseModel):
    target: str
    resolved_ips: list[str] = []
    shodan: Optional[dict[str, Any]] = None
    geo: Optional[dict[str, Any]] = None
    region_dossier: Optional[dict[str, Any]] = None
    geopolitics_alerts: list[dict[str, Any]] = []
    ct_logs: list[dict[str, Any]] = []
    feed_errors: dict[str, str] = {}
    stale_after: str

    @classmethod
    def from_result(cls, r: EnrichmentResult) -> "EnrichmentResponse":
        return cls(
            target=r.target,
            resolved_ips=r.resolved_ips,
            shodan=r.shodan,
            geo=r.geo,
            region_dossier=r.region_dossier,
            geopolitics_alerts=r.geopolitics_alerts,
            ct_logs=r.ct_logs,
            feed_errors=r.feed_errors,
            stale_after=datetime.fromtimestamp(r.stale_after, tz=timezone.utc).isoformat(),
        )


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


def _normalize_target_path(raw: str) -> str:
    """URL-decode and strip scheme/path so the aggregator sees a stable host.

    /bridge/enrich/https%3A%2F%2Facme.com%2Fpath  →  acme.com
    /bridge/enrich/acme.com                       →  acme.com
    /bridge/enrich/8.8.8.8                        →  8.8.8.8
    """
    decoded = unquote(raw)
    if "://" in decoded:
        host = urlparse(decoded).hostname
        return host or decoded
    return decoded


@router.get("/enrich/{target:path}", response_model=EnrichmentResponse)
async def enrich(target: str, request: Request) -> EnrichmentResponse:
    if not _hmac_bypass:
        await _enforce_hmac(request)
    if _aggregator is None:
        raise HTTPException(503, "enrichment aggregator not initialized")
    canonical = _normalize_target_path(target)
    result = await _aggregator.aggregate(canonical)
    return EnrichmentResponse.from_result(result)


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
