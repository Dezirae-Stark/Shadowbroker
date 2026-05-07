"""Boot-time helper: register the recon-bridge router on a FastAPI app.

This is the single composition root for the bridge. It reads env config,
instantiates the aggregator + nonce cache, applies fail-closed guards, and
mounts the router. main.py calls configure_bridge(app) once at startup;
end-to-end tests can mount a minimal FastAPI() the same way without dragging
in the rest of the monolith.

Env vars:
    SHADOWBROKER_BRIDGE_ENABLED   "true" to enable; anything else => no-op
    SCOPE_MANIFEST_DIR            absolute or relative to cwd; default
                                   "config/scope" (resolved against cwd at
                                   call time, which in production is the
                                   backend/ dir).
    RECON_BRIDGE_HMAC_KEYS        "keyid:hex,keyid2:hex" — required when
                                   bridge is enabled; missing/empty fails
                                   closed.

Fail-closed posture: when SHADOWBROKER_BRIDGE_ENABLED=true, missing keys or
a missing scope dir raises BridgeBootError. We never register the router in
a half-configured state — better a loud crash at boot than a silently-open
endpoint.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI

logger = logging.getLogger(__name__)


class BridgeBootError(RuntimeError):
    """Raised at boot when the bridge is enabled but misconfigured."""


def _is_enabled() -> bool:
    return os.environ.get("SHADOWBROKER_BRIDGE_ENABLED", "").strip().lower() == "true"


def _resolve_scope_dir() -> Path:
    raw = os.environ.get("SCOPE_MANIFEST_DIR", "").strip()
    return Path(raw) if raw else Path("config") / "scope"


def configure_bridge(app: FastAPI) -> bool:
    """Mount /bridge/* on `app` if SHADOWBROKER_BRIDGE_ENABLED=true.

    Returns True iff the router was registered. Raises BridgeBootError if
    the bridge is enabled but config is incomplete.
    """
    if not _is_enabled():
        logger.info("recon-bridge: SHADOWBROKER_BRIDGE_ENABLED!=true, not mounting /bridge/*")
        return False

    from routers.recon_bridge import (
        router,
        set_enrichment_aggregator,
        set_hmac_keys,
        set_nonce_cache,
        set_scope_manifest_dir,
        _resolve_keys,
    )
    from services.recon_bridge.enrichment_aggregator import (
        CTLogsAdapter,
        EnrichmentAggregator,
        GeopoliticsAdapter,
        RegionDossierAdapter,
        ShodanConnectorAdapter,
    )
    from services.recon_bridge.hmac_auth import NonceCache

    scope_dir = _resolve_scope_dir()
    if not scope_dir.is_dir():
        raise BridgeBootError(
            f"recon-bridge: scope manifest dir {scope_dir!r} does not exist"
        )

    # set_hmac_keys({}) followed by _resolve_keys() exercises the env path;
    # if the resulting map is empty, we fail closed.
    set_hmac_keys({})
    keys = _resolve_keys()
    if not keys:
        raise BridgeBootError(
            "recon-bridge: enabled but no HMAC keys configured "
            "(set RECON_BRIDGE_HMAC_KEYS=keyid:hex,...)"
        )

    set_scope_manifest_dir(scope_dir)
    set_hmac_keys(keys)
    set_nonce_cache(NonceCache())
    set_enrichment_aggregator(
        EnrichmentAggregator(
            shodan=ShodanConnectorAdapter(),
            region_dossier=RegionDossierAdapter(),
            geopolitics=GeopoliticsAdapter(),
            ct_logs=CTLogsAdapter(),
        )
    )

    app.include_router(router)
    logger.info(
        "recon-bridge: mounted /bridge/* with %d HMAC key(s) from scope_dir=%s",
        len(keys),
        scope_dir,
    )
    return True
