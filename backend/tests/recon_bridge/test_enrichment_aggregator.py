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


class TestRegionDossierAdapter:
    @pytest.mark.asyncio
    async def test_adapter_returns_country_asn_org(self, monkeypatch):
        from services.recon_bridge.enrichment_aggregator import RegionDossierAdapter

        def fake_lookup(target: str) -> dict:
            return {"country": "US", "asn": "AS15169", "org": "Google LLC"}

        monkeypatch.setattr(
            "services.region_dossier.lookup_for_recon_bridge",
            fake_lookup,
            raising=False,
        )
        adapter = RegionDossierAdapter()
        r = await adapter.lookup("example.com")
        assert r["country"] == "US"
        assert r["asn"] == "AS15169"
        assert r["org"] == "Google LLC"

    def test_wrapper_extracts_country_asn_org_from_ip_api_response(self, monkeypatch):
        from services import region_dossier

        class FakeResp:
            status_code = 200
            def json(self):
                return {
                    "status": "success",
                    "country": "United States",
                    "org": "Google Public DNS",
                    "as": "AS15169 Google LLC",
                    "query": "8.8.8.8",
                }

        monkeypatch.setattr(region_dossier._requests, "get", lambda *a, **kw: FakeResp())
        result = region_dossier.lookup_for_recon_bridge("8.8.8.8")
        assert result["country"] == "United States"
        assert result["asn"] == "AS15169"
        assert result["org"] == "Google Public DNS"

    def test_wrapper_resolves_hostname_to_ip_before_query(self, monkeypatch):
        from services import region_dossier

        captured = {}

        def fake_gethostbyname(host: str) -> str:
            captured["host"] = host
            return "1.2.3.4"

        class FakeResp:
            status_code = 200
            def json(self):
                captured["url_called"] = True
                return {"status": "success", "country": "X", "org": "Y", "as": "AS1 Z"}

        monkeypatch.setattr("socket.gethostbyname", fake_gethostbyname)
        monkeypatch.setattr(region_dossier._requests, "get", lambda *a, **kw: FakeResp())
        result = region_dossier.lookup_for_recon_bridge("example.com")
        assert captured["host"] == "example.com"
        assert captured.get("url_called") is True
        assert result["country"] == "X"

    def test_wrapper_strips_url_scheme_before_resolving(self, monkeypatch):
        from services import region_dossier

        captured = {}

        def fake_gethostbyname(host: str) -> str:
            captured["host"] = host
            return "1.2.3.4"

        class FakeResp:
            status_code = 200
            def json(self):
                return {"status": "success", "country": "X", "org": "Y", "as": "AS1 Z"}

        monkeypatch.setattr("socket.gethostbyname", fake_gethostbyname)
        monkeypatch.setattr(region_dossier._requests, "get", lambda *a, **kw: FakeResp())
        region_dossier.lookup_for_recon_bridge("https://api.example.com/path?q=1")
        assert captured["host"] == "api.example.com"

    def test_wrapper_returns_empty_on_dns_failure(self, monkeypatch):
        from services import region_dossier
        import socket

        def fake_gethostbyname(host: str) -> str:
            raise socket.gaierror("nope")

        monkeypatch.setattr("socket.gethostbyname", fake_gethostbyname)
        assert region_dossier.lookup_for_recon_bridge("nonexistent.example") == {}

    def test_wrapper_returns_empty_on_ip_api_failure(self, monkeypatch):
        from services import region_dossier

        class FakeResp:
            status_code = 500
            def json(self):
                return {}

        monkeypatch.setattr(region_dossier._requests, "get", lambda *a, **kw: FakeResp())
        assert region_dossier.lookup_for_recon_bridge("8.8.8.8") == {}

    def test_wrapper_returns_empty_on_ip_api_status_fail(self, monkeypatch):
        """ip-api.com returns 200 with status='fail' for invalid lookups."""
        from services import region_dossier

        class FakeResp:
            status_code = 200
            def json(self):
                return {"status": "fail", "message": "invalid query"}

        monkeypatch.setattr(region_dossier._requests, "get", lambda *a, **kw: FakeResp())
        assert region_dossier.lookup_for_recon_bridge("8.8.8.8") == {}


class TestGeopoliticsAdapter:
    @pytest.mark.asyncio
    async def test_adapter_returns_alerts_for_org(self, monkeypatch):
        from services.recon_bridge.enrichment_aggregator import GeopoliticsAdapter

        def fake_alerts(org: str, *, max_results: int = 10) -> list[dict]:
            return [{"id": "evt-1", "headline": f"Event involving {org}"}]

        monkeypatch.setattr(
            "services.geopolitics.alerts_for_org_recon_bridge",
            fake_alerts,
            raising=False,
        )
        adapter = GeopoliticsAdapter()
        alerts = await adapter.alerts("Example LLC")
        assert len(alerts) == 1
        assert "Example LLC" in alerts[0]["headline"]

    def test_wrapper_substring_matches_actor(self, monkeypatch):
        from services import geopolitics
        from services.fetchers import _store

        fake_features = [
            {"properties": {"name": "Border skirmish", "actor1": "ACME CORPORATION",
                            "actor2": "OTHER", "event_date": "20260301"}},
            {"properties": {"name": "Unrelated event", "actor1": "FOO", "actor2": "BAR",
                            "event_date": "20260301"}},
        ]
        monkeypatch.setitem(_store.latest_data, "gdelt", fake_features)
        results = geopolitics.alerts_for_org_recon_bridge("Acme Corporation")
        assert len(results) == 1
        assert "ACME" in (results[0]["actor1"] or "")

    def test_wrapper_substring_matches_headline(self, monkeypatch):
        from services import geopolitics
        from services.fetchers import _store

        fake_features = [
            {"properties": {"name": "Lockheed Martin announces new contract",
                            "actor1": "USA", "actor2": "GOV", "event_date": "20260301"}},
        ]
        monkeypatch.setitem(_store.latest_data, "gdelt", fake_features)
        results = geopolitics.alerts_for_org_recon_bridge("Lockheed Martin")
        assert len(results) == 1
        assert results[0]["headline"] == "Lockheed Martin announces new contract"

    def test_wrapper_returns_empty_when_no_match(self, monkeypatch):
        from services import geopolitics
        from services.fetchers import _store

        fake_features = [
            {"properties": {"name": "Border skirmish", "actor1": "X", "actor2": "Y",
                            "event_date": "20260301"}},
        ]
        monkeypatch.setitem(_store.latest_data, "gdelt", fake_features)
        assert geopolitics.alerts_for_org_recon_bridge("UnrelatedCorp") == []

    def test_wrapper_returns_empty_when_cache_empty(self, monkeypatch):
        from services import geopolitics
        from services.fetchers import _store

        monkeypatch.setitem(_store.latest_data, "gdelt", [])
        assert geopolitics.alerts_for_org_recon_bridge("Anything") == []

    def test_wrapper_rejects_short_org_name(self):
        from services import geopolitics
        assert geopolitics.alerts_for_org_recon_bridge("US") == []
        assert geopolitics.alerts_for_org_recon_bridge("") == []

    def test_wrapper_respects_max_results(self, monkeypatch):
        from services import geopolitics
        from services.fetchers import _store

        fake_features = [
            {"properties": {"name": f"Event {i} mentions GlobalCorp",
                            "actor1": "X", "actor2": "Y", "event_date": "20260301"}}
            for i in range(20)
        ]
        monkeypatch.setitem(_store.latest_data, "gdelt", fake_features)
        results = geopolitics.alerts_for_org_recon_bridge("GlobalCorp", max_results=5)
        assert len(results) == 5


class TestCTLogsAdapter:
    @pytest.mark.asyncio
    async def test_adapter_returns_certs_from_crtsh(self, respx_mock):
        from services.recon_bridge.enrichment_aggregator import CTLogsAdapter

        respx_mock.get("https://crt.sh/").respond(
            200,
            json=[
                {"name_value": "example.com", "issuer_name": "Test CA"},
                {"name_value": "api.example.com", "issuer_name": "Test CA"},
            ],
        )
        adapter = CTLogsAdapter()
        certs = await adapter.certificates("example.com")
        assert len(certs) == 2
        assert certs[0]["cn"] == "example.com"
        assert certs[0]["issuer"] == "Test CA"

    @pytest.mark.asyncio
    async def test_adapter_returns_empty_on_http_error(self, respx_mock):
        from services.recon_bridge.enrichment_aggregator import CTLogsAdapter

        respx_mock.get("https://crt.sh/").respond(503)
        adapter = CTLogsAdapter()
        certs = await adapter.certificates("example.com")
        assert certs == []

    @pytest.mark.asyncio
    async def test_adapter_returns_empty_on_network_error(self, respx_mock):
        import httpx
        from services.recon_bridge.enrichment_aggregator import CTLogsAdapter

        respx_mock.get("https://crt.sh/").mock(side_effect=httpx.ConnectError("nope"))
        adapter = CTLogsAdapter()
        certs = await adapter.certificates("example.com")
        assert certs == []

    @pytest.mark.asyncio
    async def test_adapter_skips_entries_without_name_value(self, respx_mock):
        from services.recon_bridge.enrichment_aggregator import CTLogsAdapter

        respx_mock.get("https://crt.sh/").respond(
            200,
            json=[
                {"name_value": "example.com", "issuer_name": "Test CA"},
                {"issuer_name": "Test CA"},  # no name_value, skipped
                {"name_value": "", "issuer_name": "Test CA"},  # empty, skipped
            ],
        )
        adapter = CTLogsAdapter()
        certs = await adapter.certificates("example.com")
        assert len(certs) == 1

    @pytest.mark.asyncio
    async def test_adapter_returns_empty_for_empty_target(self):
        from services.recon_bridge.enrichment_aggregator import CTLogsAdapter

        adapter = CTLogsAdapter()
        assert await adapter.certificates("") == []
