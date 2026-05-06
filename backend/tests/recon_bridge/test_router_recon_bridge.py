"""HTTP-level tests for /bridge/* endpoints.

These tests bypass the HMAC layer using a dependency override so we can
focus on routing, request validation, and response shape.
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient


@pytest.fixture
def manifest_dir(tmp_path: Path) -> Path:
    d = tmp_path / "scope"
    d.mkdir()
    (d / "engagement-test.yml").write_text(yaml.safe_dump({
        "version": 1,
        "manifest_id": "engagement-test",
        "mode": "engagement",
        "created_at": "2025-01-01T00:00:00Z",
        "expires_at": (datetime(2030, 1, 1, tzinfo=timezone.utc)).isoformat(),
        "authorization": {"contract_ref": "x", "contact": "y@z"},
        "targets": {
            "include": {"domains": ["acme.com", "*.acme.com"]},
            "exclude": {"domains": ["admin.acme.com"]},
        },
    }))
    return d


@pytest.fixture
def app_client(manifest_dir: Path):
    """Build a FastAPI app exposing only the recon_bridge router for testing."""
    from fastapi import FastAPI
    from routers.recon_bridge import router, set_scope_manifest_dir, set_hmac_bypass_for_tests

    set_scope_manifest_dir(manifest_dir)
    set_hmac_bypass_for_tests(True)
    app = FastAPI()
    app.include_router(router)
    yield TestClient(app)
    set_hmac_bypass_for_tests(False)


# ---------------------------------------------------------------------------
# /bridge/scope/check
# ---------------------------------------------------------------------------

class TestScopeCheck:
    def test_in_scope_returns_in_scope_true(self, app_client):
        resp = app_client.post("/bridge/scope/check", json={
            "target": {"kind": "url", "value": "https://api.acme.com"},
            "scope_token": "engagement-test",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["in_scope"] is True
        assert body["manifest_id"] == "engagement-test"
        assert body["mode"] == "engagement"
        assert "matched domain pattern *.acme.com" in body["reason"]

    def test_out_of_scope_returns_in_scope_false(self, app_client):
        resp = app_client.post("/bridge/scope/check", json={
            "target": {"kind": "url", "value": "https://other.test"},
            "scope_token": "engagement-test",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["in_scope"] is False
        assert "no scope rule matched" in body["reason"]

    def test_excluded_target_returns_excluded_reason(self, app_client):
        resp = app_client.post("/bridge/scope/check", json={
            "target": {"kind": "url", "value": "https://admin.acme.com"},
            "scope_token": "engagement-test",
        })
        assert resp.status_code == 200
        assert resp.json()["in_scope"] is False
        assert "excluded" in resp.json()["reason"]

    def test_unknown_scope_token_404(self, app_client):
        resp = app_client.post("/bridge/scope/check", json={
            "target": {"kind": "url", "value": "https://acme.com"},
            "scope_token": "no-such-engagement",
        })
        assert resp.status_code == 404
        assert "no manifest" in resp.json()["detail"].lower()

    def test_malformed_request_422(self, app_client):
        resp = app_client.post("/bridge/scope/check", json={"target": {"kind": "url"}})
        assert resp.status_code == 422
