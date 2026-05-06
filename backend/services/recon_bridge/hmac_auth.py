"""HMAC-SHA256 auth for the recon bridge channel.

Pattern mirrors services/openclaw_channel.py:
  signed_str = METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + SHA256(BODY)

The deep-eye client side has an independent but cross-compatible implementation
under modules/reconnaissance/hmac_auth.py — both must produce identical
signatures for identical inputs (verified by Plan A's cross-compatibility test).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from collections import OrderedDict
from threading import Lock
from typing import Callable

logger = logging.getLogger(__name__)

# Maximum allowed clock skew between client and server, in seconds.
TIMESTAMP_WINDOW_SECONDS = 60


class BridgeAuthError(Exception):
    """Raised when a bridge HMAC check fails."""


def canonical_signed_string(method: str, path: str, timestamp: int, body: bytes) -> str:
    """Build the canonical string to sign / verify."""
    body_sha = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{path}\n{int(timestamp)}\n{body_sha}"


def sign_request(key: bytes, method: str, path: str, timestamp: int, body: bytes) -> str:
    """Return the lowercase hex HMAC-SHA256 signature for the canonical string."""
    msg = canonical_signed_string(method, path, timestamp, body).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_request(
    key: bytes,
    method: str,
    path: str,
    timestamp: int,
    body: bytes,
    signature: str,
    *,
    now: Callable[[], int] = lambda: int(time.time()),
) -> None:
    """Raise BridgeAuthError if the signature/timestamp combination is invalid."""
    delta = now() - int(timestamp)
    if abs(delta) > TIMESTAMP_WINDOW_SECONDS:
        raise BridgeAuthError(
            f"timestamp out of window: delta={delta}s, max={TIMESTAMP_WINDOW_SECONDS}s"
        )
    expected = sign_request(key, method, path, timestamp, body)
    if not hmac.compare_digest(expected.lower(), signature.lower()):
        raise BridgeAuthError("signature mismatch")


class NonceCache:
    """In-memory LRU of (key_id, timestamp, signature) triples to block replays.

    Per the spec: timestamp window is 60s, nonce TTL is 5 minutes. The cache is
    process-local; horizontal scaling of the bridge would require a shared store.
    """

    def __init__(self, max_size: int = 4096, ttl_seconds: int = 300) -> None:
        self._entries: OrderedDict[tuple[str, int, str], int] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl_seconds
        self._lock = Lock()

    def assert_unseen(self, key_id: str, timestamp: int, signature: str) -> None:
        """Raise BridgeAuthError if this triple has been seen recently."""
        nonce = (key_id, int(timestamp), signature.lower())
        now = int(time.time())
        with self._lock:
            self._evict_expired(now)
            if nonce in self._entries:
                raise BridgeAuthError("replay detected")
            self._entries[nonce] = now
            if len(self._entries) > self._max_size:
                self._entries.popitem(last=False)

    def _evict_expired(self, now: int) -> None:
        cutoff = now - self._ttl
        while self._entries:
            _, ts = next(iter(self._entries.items()))
            if ts >= cutoff:
                return
            self._entries.popitem(last=False)
