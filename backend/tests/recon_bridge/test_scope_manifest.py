"""Scope manifest loading and target validation.

Manifest schema and validation rules: see
docs/superpowers/specs/2026-05-05-shadowbroker-integration-design.md §7.
"""

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from services.recon_bridge.scope_manifest import (
    ScopeManifest,
    ScopeManifestError,
    Target,
    load_manifest,
)


def _manifest_dict(*, mode="engagement", expires_in_days=30, **overrides):
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    base = {
        "version": 1,
        "manifest_id": "engagement-test",
        "mode": mode,
        "created_at": now_utc.isoformat(),
        "expires_at": (now_utc + timedelta(days=expires_in_days)).isoformat(),
        "authorization": {
            "contract_ref": "test SOW",
            "contact": "test@example.com",
        },
        "targets": {
            "include": {
                "domains": ["acme.com", "*.acme.com"],
                "ip_cidrs": ["198.51.100.0/24"],
                "asns": ["AS64512"],
            },
            "exclude": {
                "domains": ["admin.acme.com"],
                "ip_cidrs": ["198.51.100.5/32"],
            },
        },
    }
    base.update(overrides)
    return base


def _manifest(**overrides):
    return ScopeManifest.from_dict(_manifest_dict(**overrides))


def _target(kind, value):
    return Target(kind=kind, value=value)


# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------


class TestLoad:
    def test_loads_minimal_manifest(self):
        m = _manifest()
        assert m.manifest_id == "engagement-test"
        assert m.mode == "engagement"

    def test_rejects_missing_expires_at(self, tmp_path: Path):
        d = _manifest_dict()
        del d["expires_at"]
        f = tmp_path / "x.yml"
        f.write_text(yaml.safe_dump(d))
        with pytest.raises(ScopeManifestError, match="expires_at is required"):
            load_manifest(f)

    def test_rejects_unknown_top_level_field(self, tmp_path: Path):
        d = _manifest_dict()
        d["unexpected"] = "value"
        f = tmp_path / "x.yml"
        f.write_text(yaml.safe_dump(d))
        with pytest.raises(ScopeManifestError, match="unknown field"):
            load_manifest(f)

    def test_rejects_unknown_mode(self):
        with pytest.raises(ScopeManifestError, match="unknown mode"):
            ScopeManifest.from_dict(_manifest_dict(mode="freeform"))


# ---------------------------------------------------------------------------
# Validation rules — order matters: expired > exclude > lab > include > deny
# ---------------------------------------------------------------------------


class TestValidate:
    def test_expired_manifest_rejects_anything(self):
        m = _manifest(expires_in_days=-1)  # already expired
        result = m.validate(_target("url", "https://acme.com"), now=lambda: time.time())
        assert result.in_scope is False
        assert "expired" in result.reason

    def test_exclude_wins_over_include(self):
        m = _manifest()
        result = m.validate(_target("url", "https://admin.acme.com"))
        assert result.in_scope is False
        assert "excluded" in result.reason

    def test_domain_wildcard_match(self):
        m = _manifest()
        result = m.validate(_target("url", "https://api.acme.com"))
        assert result.in_scope is True
        assert "matched domain pattern *.acme.com" in result.reason

    def test_ip_cidr_match(self):
        m = _manifest()
        result = m.validate(_target("ip", "198.51.100.42"))
        assert result.in_scope is True

    def test_asn_match(self):
        m = _manifest()
        result = m.validate(_target("asn", "AS64512"))
        assert result.in_scope is True

    def test_no_match_rejects(self):
        m = _manifest()
        result = m.validate(_target("url", "https://other.test"))
        assert result.in_scope is False
        assert "no scope rule matched" in result.reason

    def test_lab_mode_with_region_lock(self):
        d = _manifest_dict(mode="lab")
        d["lab"] = {"region_lock": "10.0.0.0/8"}
        d["targets"] = {"include": {}, "exclude": {}}  # no normal include rules
        m = ScopeManifest.from_dict(d)
        assert m.validate(_target("ip", "10.5.6.7")).in_scope is True
        assert m.validate(_target("ip", "192.168.1.1")).in_scope is False

    def test_lab_mode_still_expires(self):
        d = _manifest_dict(mode="lab", expires_in_days=-1)
        d["lab"] = {"region_lock": "10.0.0.0/8"}
        m = ScopeManifest.from_dict(d)
        assert m.validate(_target("ip", "10.5.6.7")).in_scope is False


# ---------------------------------------------------------------------------
# Target normalization (URL → host comparison, etc.)
# ---------------------------------------------------------------------------


class TestTargetNormalization:
    @pytest.mark.parametrize(
        "raw,host",
        [
            ("https://acme.com/path?q=1", "acme.com"),
            ("http://acme.com:8080/", "acme.com"),
            ("acme.com", "acme.com"),
        ],
    )
    def test_url_extracts_host(self, raw, host):
        m = _manifest()
        # If host is "acme.com" and acme.com is included, in_scope=True
        if host == "acme.com":
            assert m.validate(_target("url", raw)).in_scope is True

    def test_invalid_ip_rejected_with_clear_reason(self):
        m = _manifest()
        result = m.validate(_target("ip", "not.an.ip"))
        assert result.in_scope is False
        assert "invalid ip" in result.reason.lower()
