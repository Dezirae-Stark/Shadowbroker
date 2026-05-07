"""End-to-end /bridge/* tests through configure_bridge.

These tests build a real (small) FastAPI app via configure_bridge — the same
helper main.py uses — and drive it with the live HMAC primitives. Feed-side
adapters are replaced with in-memory fakes via set_enrichment_aggregator so
the test stays hermetic (no Shodan/crt.sh/ip-api/GDELT calls).

Scope: verify the *wiring* end-to-end, not the crypto (Task 03 covers that)
and not feed semantics (Tasks 08–11 cover those).
"""

from __future__ import annotations

import json as _json
import time as _time
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient


KEY_ID = "e2e-key"
KEY_BYTES = b"end-to-end-test-bridge-secret-x" + b"x"  # 32 bytes


@pytest.fixture
def e2e_app(tmp_path: Path, monkeypatch):
    """Build a real FastAPI app with the bridge fully configured."""
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    (scope_dir / "engagement-e2e.yml").write_text(yaml.safe_dump({
        "version": 1,
        "manifest_id": "engagement-e2e",
        "mode": "engagement",
        "created_at": "2025-01-01T00:00:00Z",
        "expires_at": datetime(2030, 1, 1, tzinfo=timezone.utc).isoformat(),
        "authorization": {"contract_ref": "TEST-001", "contact": "ops@e2e.test"},
        "targets": {
            "include": {"domains": ["acme.com", "*.acme.com"]},
            "exclude": {"domains": ["admin.acme.com"]},
        },
    }))

    monkeypatch.setenv("SHADOWBROKER_BRIDGE_ENABLED", "true")
    monkeypatch.setenv("SCOPE_MANIFEST_DIR", str(scope_dir))
    monkeypatch.setenv("RECON_BRIDGE_HMAC_KEYS", f"{KEY_ID}:{KEY_BYTES.hex()}")

    from services.recon_bridge.wiring import configure_bridge

    app = FastAPI()
    assert configure_bridge(app) is True

    # Replace the production aggregator with a hermetic fake so we don't
    # touch network. configure_bridge already called set_enrichment_aggregator
    # with real adapters; we override after the fact.
    from routers import recon_bridge as rb
    from services.recon_bridge.enrichment_aggregator import EnrichmentResult

    class HermeticAggregator:
        def __init__(self):
            self.calls: list[str] = []

        async def aggregate(self, target: str) -> EnrichmentResult:
            self.calls.append(target)
            return EnrichmentResult(
                target=target,
                resolved_ips=["203.0.113.42"],
                shodan={"ports": [80, 443], "ip_str": "203.0.113.42"},
                geo={"country": "US", "asn": "AS64500", "org": "ACME E2E"},
                region_dossier={"country": "US", "asn": "AS64500", "org": "ACME E2E"},
                geopolitics_alerts=[],
                ct_logs=[{"cn": target, "issuer": "Test CA"}],
                stale_after=_time.time() + 60,
            )

    fake = HermeticAggregator()
    rb.set_enrichment_aggregator(fake)
    yield TestClient(app), fake

    # Teardown — clear router state so subsequent tests start clean.
    rb.set_enrichment_aggregator(None)
    rb.set_hmac_keys({})
    rb.set_nonce_cache(None)


def _sign(method: str, path: str, body: bytes, *, ts: int | None = None) -> dict[str, str]:
    """Sign with Shadowbroker's hmac_auth — cross-compat with deep-eye verified
    by Task 03's vectors test."""
    from services.recon_bridge.hmac_auth import sign_request

    if ts is None:
        ts = int(_time.time())
    return {
        "X-Bridge-Key-Id": KEY_ID,
        "X-Bridge-Timestamp": str(ts),
        "X-Bridge-Signature": sign_request(KEY_BYTES, method, path, ts, body),
    }


class TestEndToEnd:
    def test_scope_check_then_enrich_happy_path(self, e2e_app):
        client, fake = e2e_app

        # 1) Scope-check the target.
        body = _json.dumps({
            "target": {"kind": "url", "value": "https://api.acme.com"},
            "scope_token": "engagement-e2e",
        }).encode("utf-8")
        headers = _sign("POST", "/bridge/scope/check", body)
        headers["Content-Type"] = "application/json"
        r1 = client.post("/bridge/scope/check", content=body, headers=headers)
        assert r1.status_code == 200, r1.text
        assert r1.json()["in_scope"] is True
        assert r1.json()["mode"] == "engagement"

        # 2) Now enrich it.
        path = "/bridge/enrich/api.acme.com"
        headers2 = _sign("GET", path, b"")
        r2 = client.get(path, headers=headers2)
        assert r2.status_code == 200, r2.text
        intel = r2.json()
        assert intel["target"] == "api.acme.com"
        assert intel["resolved_ips"] == ["203.0.113.42"]
        assert intel["geo"]["org"] == "ACME E2E"
        assert intel["ct_logs"][0]["cn"] == "api.acme.com"
        assert fake.calls == ["api.acme.com"]

    def test_unsigned_request_is_rejected(self, e2e_app):
        client, _fake = e2e_app
        r = client.get("/bridge/enrich/api.acme.com")
        assert r.status_code == 401

    def test_replay_blocked_across_channel(self, e2e_app):
        """Same nonce cache must reject a replay even though the first request
        was on /scope/check and the second is on /enrich (different paths but
        same key_id+timestamp+signature triple — though the *signature* is
        path-bound, this exercises the shared cache infrastructure)."""
        client, _fake = e2e_app

        path = "/bridge/enrich/api.acme.com"
        headers = _sign("GET", path, b"")
        r1 = client.get(path, headers=headers)
        assert r1.status_code == 200
        r2 = client.get(path, headers=headers)
        assert r2.status_code == 401
        assert "replay" in r2.json()["detail"].lower()

    def test_out_of_scope_target_returns_in_scope_false(self, e2e_app):
        client, _fake = e2e_app
        body = _json.dumps({
            "target": {"kind": "url", "value": "https://other.test"},
            "scope_token": "engagement-e2e",
        }).encode("utf-8")
        headers = _sign("POST", "/bridge/scope/check", body)
        headers["Content-Type"] = "application/json"
        r = client.post("/bridge/scope/check", content=body, headers=headers)
        assert r.status_code == 200
        assert r.json()["in_scope"] is False

    def test_enrich_url_target_normalized_through_full_stack(self, e2e_app):
        """URL-encoded target on the path: configure_bridge → router →
        _normalize_target_path → aggregator must all cooperate.

        Signing convention: deep-eye signs the *decoded* canonical path and
        then URL-encodes for wire transport. The bridge reads request.url.path
        which is also decoded, so signatures match end-to-end.
        """
        client, fake = e2e_app
        decoded_target = "https://api.acme.com/health"
        encoded_target = "https%3A%2F%2Fapi.acme.com%2Fhealth"
        canonical_path = f"/bridge/enrich/{decoded_target}"
        wire_path = f"/bridge/enrich/{encoded_target}"
        headers = _sign("GET", canonical_path, b"")  # sign decoded form
        r = client.get(wire_path, headers=headers)   # send encoded form
        assert r.status_code == 200, r.text
        # Aggregator must have seen the normalized hostname, not the URL.
        assert fake.calls == ["api.acme.com"]

    def test_unknown_scope_token_404_not_401(self, e2e_app):
        """HMAC must succeed first, then scope manifest 404 surfaces."""
        client, _fake = e2e_app
        body = _json.dumps({
            "target": {"kind": "url", "value": "https://acme.com"},
            "scope_token": "no-such-engagement",
        }).encode("utf-8")
        headers = _sign("POST", "/bridge/scope/check", body)
        headers["Content-Type"] = "application/json"
        r = client.post("/bridge/scope/check", content=body, headers=headers)
        assert r.status_code == 404
