"""Enrichment aggregator — parallel fan-out, per-feed timeout, 60s cache."""

import asyncio

import pytest

from services.recon_bridge.enrichment_aggregator import (
    EnrichmentAggregator,
    EnrichmentResult,
)


class FakeShodan:
    def __init__(self, response):
        self._response = response
        self.calls = 0

    async def lookup(self, target: str) -> dict:
        self.calls += 1
        return self._response


class FakeRegionDossier:
    async def lookup(self, target: str) -> dict:
        return {"country": "US", "asn": "AS15169", "org": "Example LLC"}


class FakeGeopolitics:
    async def alerts(self, org: str) -> list[dict]:
        return [{"id": "evt-1", "headline": "Example event"}]


class FakeCT:
    async def certificates(self, target: str) -> list[dict]:
        return [{"cn": target, "issuer": "Test CA"}]


@pytest.fixture
def agg():
    return EnrichmentAggregator(
        shodan=FakeShodan({"ports": [80, 443], "cves": ["CVE-2021-1"]}),
        region_dossier=FakeRegionDossier(),
        geopolitics=FakeGeopolitics(),
        ct_logs=FakeCT(),
        cache_ttl_seconds=60,
    )


@pytest.mark.asyncio
async def test_aggregate_returns_merged_result(agg):
    r = await agg.aggregate("example.com")
    assert isinstance(r, EnrichmentResult)
    assert r.target == "example.com"
    assert r.shodan == {"ports": [80, 443], "cves": ["CVE-2021-1"]}
    assert r.geo["org"] == "Example LLC"
    assert len(r.geopolitics_alerts) == 1
    assert r.ct_logs[0]["cn"] == "example.com"


@pytest.mark.asyncio
async def test_aggregate_caches_for_ttl(agg):
    await agg.aggregate("example.com")
    await agg.aggregate("example.com")
    assert agg._shodan.calls == 1  # second call hit cache


@pytest.mark.asyncio
async def test_aggregate_failed_feed_does_not_blow_up_others():
    class BrokenShodan:
        async def lookup(self, target: str) -> dict:
            raise RuntimeError("shodan down")

    agg = EnrichmentAggregator(
        shodan=BrokenShodan(),
        region_dossier=FakeRegionDossier(),
        geopolitics=FakeGeopolitics(),
        ct_logs=FakeCT(),
        cache_ttl_seconds=60,
    )
    r = await agg.aggregate("example.com")
    assert r.shodan is None
    assert r.geo is not None
    assert r.feed_errors and "shodan" in r.feed_errors


@pytest.mark.asyncio
async def test_resolved_ips_populated_from_shodan_when_available():
    class ShodanWithIPs:
        async def lookup(self, target: str) -> dict:
            return {"ip_str": "1.2.3.4", "ports": [80]}

    agg = EnrichmentAggregator(
        shodan=ShodanWithIPs(),
        region_dossier=FakeRegionDossier(),
        geopolitics=FakeGeopolitics(),
        ct_logs=FakeCT(),
        cache_ttl_seconds=60,
    )
    r = await agg.aggregate("example.com")
    assert r.resolved_ips == ["1.2.3.4"]


@pytest.mark.asyncio
async def test_slow_feed_times_out_and_other_feeds_still_return():
    """Per-feed timeout: a hung feed becomes a feed_error, not a hang."""
    class SlowShodan:
        async def lookup(self, target: str) -> dict:
            await asyncio.sleep(1.0)  # far longer than the test timeout
            return {"ports": []}

    agg = EnrichmentAggregator(
        shodan=SlowShodan(),
        region_dossier=FakeRegionDossier(),
        geopolitics=FakeGeopolitics(),
        ct_logs=FakeCT(),
        cache_ttl_seconds=60,
        feed_timeout_seconds=0.05,
    )
    r = await agg.aggregate("example.com")
    assert r.shodan is None
    assert "shodan" in r.feed_errors
    assert "timeout" in r.feed_errors["shodan"].lower()
    # Other feeds unaffected
    assert r.geo is not None
    assert r.ct_logs


class TestShodanConnectorAdapter:
    @pytest.mark.asyncio
    async def test_adapter_calls_underlying_connector_in_executor(self, monkeypatch):
        from services.recon_bridge.enrichment_aggregator import ShodanConnectorAdapter

        captured = {}

        def fake_host_lookup(target: str) -> dict:
            captured["target"] = target
            return {"ip_str": "1.2.3.4", "ports": [80, 443]}

        monkeypatch.setenv("SHODAN_API_KEY", "fake-key-for-test")
        monkeypatch.setattr(
            "services.shodan_connector.host_lookup_for_recon_bridge",
            fake_host_lookup,
            raising=False,
        )

        adapter = ShodanConnectorAdapter()
        result = await adapter.lookup("example.com")
        assert result == {"ip_str": "1.2.3.4", "ports": [80, 443]}
        assert captured["target"] == "example.com"

    @pytest.mark.asyncio
    async def test_adapter_returns_empty_when_api_key_missing(self, monkeypatch):
        from services.recon_bridge.enrichment_aggregator import ShodanConnectorAdapter

        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        adapter = ShodanConnectorAdapter()
        result = await adapter.lookup("example.com")
        # Per the spec: enrichment is opportunistic. No API key → empty result, no raise.
        assert result == {}

    @pytest.mark.asyncio
    async def test_wrapper_uses_host_endpoint_for_ip_target(self, monkeypatch):
        """host_lookup_for_recon_bridge dispatches IP → lookup_shodan_host
        and extracts the inner host dict from the envelope."""
        from services import shodan_connector

        captured = {}

        def fake_lookup_host(ip: str, history: bool = False) -> dict:
            captured["ip"] = ip
            return {"ok": True, "source": "Shodan", "host": {"ip": ip, "ports": [22]}}

        monkeypatch.setattr(shodan_connector, "lookup_shodan_host", fake_lookup_host)
        result = shodan_connector.host_lookup_for_recon_bridge("8.8.8.8")
        assert captured["ip"] == "8.8.8.8"
        assert result == {"ip": "8.8.8.8", "ports": [22]}

    @pytest.mark.asyncio
    async def test_wrapper_uses_search_for_hostname_target(self, monkeypatch):
        """host_lookup_for_recon_bridge dispatches hostname → search_shodan."""
        from services import shodan_connector

        captured = {}

        def fake_search(query: str, page: int = 1, facets=None) -> dict:
            captured["query"] = query
            return {"matches": [{"ip_str": "1.1.1.1", "hostname": "acme.com"}]}

        monkeypatch.setattr(shodan_connector, "search_shodan", fake_search)
        result = shodan_connector.host_lookup_for_recon_bridge("acme.com")
        assert captured["query"] == "hostname:acme.com"
        assert result == {"ip_str": "1.1.1.1", "hostname": "acme.com"}

    def test_wrapper_swallows_connector_error(self, monkeypatch):
        """Per spec §9: enrichment misses are not errors."""
        from services import shodan_connector

        def boom(ip: str, history: bool = False) -> dict:
            raise shodan_connector.ShodanConnectorError("rate limited", status_code=429)

        monkeypatch.setattr(shodan_connector, "lookup_shodan_host", boom)
        assert shodan_connector.host_lookup_for_recon_bridge("8.8.8.8") == {}
