"""Aggregate Shadowbroker OSINT feeds into a single enrichment record.

Feeds are called in parallel via asyncio.gather. Each feed runs under its own
asyncio.wait_for budget (default 5s) so a single hung upstream cannot block the
whole aggregate call. Any feed exception OR timeout is caught, recorded under
feed_errors, and the rest of the result still returns. The cache is per-target,
in-memory, and shared across requests.

Geopolitics is sequenced *after* region dossier because it keys on the org
field. This means total latency ~= max(shodan, region, ct) + geopolitics.
Concurrent-request coalescing (in-flight dedup) is intentionally deferred —
mocked-feed traffic doesn't justify it yet (Plan A Task 07 design note).
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

logger = logging.getLogger(__name__)


class ShodanFeed(Protocol):
    async def lookup(self, target: str) -> dict[str, Any]: ...


class RegionDossierFeed(Protocol):
    async def lookup(self, target: str) -> dict[str, Any]: ...


class GeopoliticsFeed(Protocol):
    async def alerts(self, org: str) -> list[dict[str, Any]]: ...


class CTFeed(Protocol):
    async def certificates(self, target: str) -> list[dict[str, Any]]: ...


@dataclass
class EnrichmentResult:
    target: str
    resolved_ips: list[str] = field(default_factory=list)
    shodan: Optional[dict[str, Any]] = None
    geo: Optional[dict[str, Any]] = None
    region_dossier: Optional[dict[str, Any]] = None
    geopolitics_alerts: list[dict[str, Any]] = field(default_factory=list)
    ct_logs: list[dict[str, Any]] = field(default_factory=list)
    feed_errors: dict[str, str] = field(default_factory=dict)
    stale_after: float = 0.0


@dataclass
class _FeedError:
    detail: str


class EnrichmentAggregator:
    def __init__(
        self,
        *,
        shodan: ShodanFeed,
        region_dossier: RegionDossierFeed,
        geopolitics: GeopoliticsFeed,
        ct_logs: CTFeed,
        cache_ttl_seconds: int = 60,
        feed_timeout_seconds: float = 5.0,
    ) -> None:
        self._shodan = shodan
        self._region = region_dossier
        self._geo = geopolitics
        self._ct = ct_logs
        self._ttl = cache_ttl_seconds
        self._timeout = feed_timeout_seconds
        self._cache: dict[str, tuple[float, EnrichmentResult]] = {}

    async def aggregate(self, target: str) -> EnrichmentResult:
        now = time.time()
        cached = self._cache.get(target)
        if cached and cached[0] > now:
            return cached[1]

        result = EnrichmentResult(target=target, stale_after=now + self._ttl)

        shodan_data, region_data, ct_data = await asyncio.gather(
            self._safe(self._shodan.lookup(target), "shodan"),
            self._safe(self._region.lookup(target), "region_dossier"),
            self._safe(self._ct.certificates(target), "ct_logs"),
        )

        if isinstance(shodan_data, dict):
            result.shodan = shodan_data
            ip = shodan_data.get("ip_str") or shodan_data.get("ip")
            if ip:
                result.resolved_ips = [ip]
        elif isinstance(shodan_data, _FeedError):
            result.feed_errors["shodan"] = shodan_data.detail

        if isinstance(region_data, dict):
            result.region_dossier = region_data
            geo = {
                k: region_data.get(k) for k in ("country", "asn", "org")
                if region_data.get(k) is not None
            }
            result.geo = geo or None
        elif isinstance(region_data, _FeedError):
            result.feed_errors["region_dossier"] = region_data.detail

        if isinstance(ct_data, list):
            result.ct_logs = ct_data
        elif isinstance(ct_data, _FeedError):
            result.feed_errors["ct_logs"] = ct_data.detail

        org = (result.geo or {}).get("org") if result.geo else None
        if org:
            geo_alerts = await self._safe(self._geo.alerts(org), "geopolitics")
            if isinstance(geo_alerts, list):
                result.geopolitics_alerts = geo_alerts
            elif isinstance(geo_alerts, _FeedError):
                result.feed_errors["geopolitics"] = geo_alerts.detail

        self._cache[target] = (now + self._ttl, result)
        return result

    async def _safe(self, coro, name: str):
        try:
            return await asyncio.wait_for(coro, timeout=self._timeout)
        except asyncio.TimeoutError:
            logger.warning("Enrichment feed %s timed out after %.2fs", name, self._timeout)
            return _FeedError(detail=f"timeout after {self._timeout:.2f}s")
        except Exception as exc:  # noqa: BLE001 — degrade gracefully per spec §9
            logger.warning("Enrichment feed %s failed: %s", name, exc)
            return _FeedError(detail=str(exc))
