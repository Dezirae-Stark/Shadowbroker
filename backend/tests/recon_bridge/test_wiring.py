"""Tests for services.recon_bridge.wiring — the boot-time helper that
registers /bridge/* on the FastAPI app, instantiates the aggregator and
nonce cache, and applies the fail-closed/feature-gate policies.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI


@pytest.fixture
def bridge_env(tmp_path: Path, monkeypatch):
    """Helper: prepares a scope dir + valid env for the wiring helper.
    Tests can monkeypatch.delenv(...) any of these to test failure paths.
    """
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    monkeypatch.setenv("SHADOWBROKER_BRIDGE_ENABLED", "true")
    monkeypatch.setenv("SCOPE_MANIFEST_DIR", str(scope_dir))
    monkeypatch.setenv("RECON_BRIDGE_HMAC_KEYS", "k1:" + ("ab" * 16))
    return scope_dir


class TestConfigureBridge:
    def test_disabled_by_default_returns_false(self, monkeypatch):
        from services.recon_bridge.wiring import configure_bridge

        monkeypatch.delenv("SHADOWBROKER_BRIDGE_ENABLED", raising=False)
        app = FastAPI()
        assert configure_bridge(app) is False
        # No /bridge/* routes registered.
        assert not any(r.path.startswith("/bridge") for r in app.router.routes)

    def test_enabled_with_full_env_registers_router(self, bridge_env):
        from services.recon_bridge.wiring import configure_bridge

        app = FastAPI()
        assert configure_bridge(app) is True
        bridge_paths = [r.path for r in app.router.routes if r.path.startswith("/bridge")]
        assert any("scope/check" in p for p in bridge_paths)
        assert any("enrich" in p for p in bridge_paths)

    def test_enabled_but_no_keys_fails_closed(self, bridge_env, monkeypatch):
        from services.recon_bridge.wiring import BridgeBootError, configure_bridge

        monkeypatch.delenv("RECON_BRIDGE_HMAC_KEYS", raising=False)
        app = FastAPI()
        with pytest.raises(BridgeBootError, match="no HMAC keys"):
            configure_bridge(app)

    def test_enabled_but_scope_dir_missing_fails_closed(self, bridge_env, monkeypatch, tmp_path):
        from services.recon_bridge.wiring import BridgeBootError, configure_bridge

        monkeypatch.setenv("SCOPE_MANIFEST_DIR", str(tmp_path / "does-not-exist"))
        app = FastAPI()
        with pytest.raises(BridgeBootError, match="scope"):
            configure_bridge(app)

    def test_default_scope_dir_is_config_scope(self, monkeypatch, tmp_path):
        """Without SCOPE_MANIFEST_DIR, default to <backend>/config/scope.
        Test creates that dir under tmp_path and chdir's so the relative
        default resolves there.
        """
        from services.recon_bridge.wiring import configure_bridge

        backend_root = tmp_path / "backend"
        scope_dir = backend_root / "config" / "scope"
        scope_dir.mkdir(parents=True)
        monkeypatch.chdir(backend_root)
        monkeypatch.delenv("SCOPE_MANIFEST_DIR", raising=False)
        monkeypatch.setenv("SHADOWBROKER_BRIDGE_ENABLED", "true")
        monkeypatch.setenv("RECON_BRIDGE_HMAC_KEYS", "k1:" + ("ab" * 16))

        app = FastAPI()
        assert configure_bridge(app) is True

    def test_enabled_with_false_value_returns_false(self, bridge_env, monkeypatch):
        from services.recon_bridge.wiring import configure_bridge

        monkeypatch.setenv("SHADOWBROKER_BRIDGE_ENABLED", "false")
        app = FastAPI()
        assert configure_bridge(app) is False

    def test_keys_loaded_via_setter_propagate_to_router(self, bridge_env):
        """After configure_bridge, the router's _hmac_keys map must be populated."""
        from services.recon_bridge.wiring import configure_bridge
        from routers import recon_bridge as rb

        app = FastAPI()
        configure_bridge(app)
        assert "k1" in rb._hmac_keys
        assert rb._hmac_keys["k1"] == bytes.fromhex("ab" * 16)
        assert rb._nonce_cache is not None
        assert rb._aggregator is not None
