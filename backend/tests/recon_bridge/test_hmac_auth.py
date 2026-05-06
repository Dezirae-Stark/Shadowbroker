"""HMAC-SHA256 signing/verification for the recon bridge channel.

Mirrors the canonical request format used by services/openclaw_channel.py:
  signed_str = METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + SHA256(BODY)
"""

import hashlib
import hmac
import time

import pytest

from services.recon_bridge.hmac_auth import (
    BridgeAuthError,
    canonical_signed_string,
    sign_request,
    verify_request,
)


KEY = b"test-shared-key-32bytes-minimum-padding"
KEY_ID = "deep-eye-agent"


class TestCanonicalString:
    def test_includes_all_four_components(self):
        body = b'{"target":"example.com"}'
        s = canonical_signed_string("GET", "/bridge/enrich/example.com", 1700000000, body)
        body_sha = hashlib.sha256(body).hexdigest()
        assert s == f"GET\n/bridge/enrich/example.com\n1700000000\n{body_sha}"

    def test_empty_body_uses_sha256_of_empty_bytes(self):
        s = canonical_signed_string("POST", "/bridge/scope/check", 1700000000, b"")
        empty_sha = hashlib.sha256(b"").hexdigest()
        assert s.endswith(f"\n{empty_sha}")


class TestSignAndVerify:
    def test_roundtrip_succeeds(self):
        body = b'{"x":1}'
        ts = 1700000000
        sig = sign_request(KEY, "POST", "/bridge/scope/check", ts, body)
        # Should not raise
        verify_request(KEY, "POST", "/bridge/scope/check", ts, body, sig, now=lambda: ts)

    def test_tampered_body_rejected(self):
        ts = 1700000000
        sig = sign_request(KEY, "POST", "/bridge/scope/check", ts, b'{"x":1}')
        with pytest.raises(BridgeAuthError, match="signature mismatch"):
            verify_request(KEY, "POST", "/bridge/scope/check", ts, b'{"x":2}', sig, now=lambda: ts)

    def test_tampered_path_rejected(self):
        ts = 1700000000
        sig = sign_request(KEY, "POST", "/bridge/scope/check", ts, b"")
        with pytest.raises(BridgeAuthError, match="signature mismatch"):
            verify_request(KEY, "POST", "/bridge/elsewhere", ts, b"", sig, now=lambda: ts)

    def test_wrong_key_rejected(self):
        ts = 1700000000
        sig = sign_request(KEY, "GET", "/bridge/enrich/x", ts, b"")
        with pytest.raises(BridgeAuthError, match="signature mismatch"):
            verify_request(b"different-key", "GET", "/bridge/enrich/x", ts, b"", sig, now=lambda: ts)

    def test_timestamp_too_old_rejected(self):
        ts = 1700000000
        sig = sign_request(KEY, "GET", "/bridge/enrich/x", ts, b"")
        # Server clock is 70s ahead; our window is 60s
        with pytest.raises(BridgeAuthError, match="timestamp out of window"):
            verify_request(KEY, "GET", "/bridge/enrich/x", ts, b"", sig, now=lambda: ts + 70)

    def test_timestamp_in_future_rejected(self):
        ts = 1700000000
        sig = sign_request(KEY, "GET", "/bridge/enrich/x", ts, b"")
        # Client clock is 70s ahead; server now is older
        with pytest.raises(BridgeAuthError, match="timestamp out of window"):
            verify_request(KEY, "GET", "/bridge/enrich/x", ts, b"", sig, now=lambda: ts - 70)

    def test_signature_is_lowercase_hex(self):
        sig = sign_request(KEY, "GET", "/x", 1700000000, b"")
        assert sig == sig.lower()
        assert all(c in "0123456789abcdef" for c in sig)
        assert len(sig) == 64  # HMAC-SHA256 hex


class TestNonceReplay:
    def test_replay_with_same_signature_rejected(self):
        from services.recon_bridge.hmac_auth import NonceCache

        cache = NonceCache(max_size=100, ttl_seconds=300)
        ts = 1700000000
        sig = sign_request(KEY, "GET", "/x", ts, b"")
        cache.assert_unseen(KEY_ID, ts, sig)
        with pytest.raises(BridgeAuthError, match="replay"):
            cache.assert_unseen(KEY_ID, ts, sig)

    def test_different_signatures_both_accepted(self):
        from services.recon_bridge.hmac_auth import NonceCache

        cache = NonceCache(max_size=100, ttl_seconds=300)
        cache.assert_unseen(KEY_ID, 1700000000, "a" * 64)
        cache.assert_unseen(KEY_ID, 1700000000, "b" * 64)  # different sig, ok
