"""Signature scheme for certificates and anchors.

HMAC-SHA256 over canonical JSON with a deployment-scoped key. Isolated here so a
KMS asymmetric-sign implementation can drop in without touching callers (notes N3).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os

_DEFAULT_KEY_ENV = "ENGRAM_SIGNING_KEY"


def canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


class Signer:
    def __init__(self, key: bytes | None = None):
        if key is None:
            key = os.environ.get(_DEFAULT_KEY_ENV, "memwarden-dev-signing-key").encode()
        self._key = key

    def sign(self, body: dict) -> str:
        return hmac.new(self._key, canonical(body), hashlib.sha256).hexdigest()

    def verify(self, body: dict, signature: str) -> bool:
        return hmac.compare_digest(self.sign(body), signature)


def actor_hash(actor_id: str) -> str:
    """Truncated SHA-256; certificates carry no raw identifiers (design §4.4)."""
    return hashlib.sha256(actor_id.encode("utf-8")).hexdigest()[:16]
