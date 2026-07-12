"""Audit anchor: Merkle cross-anchoring of per-tenant chain heads (design §10)."""

from __future__ import annotations

import time
from typing import Protocol

from . import signing
from .audit import merkle_root


class AnchorStore(Protocol):
    def put_anchor(self, anchor: dict) -> str:
        """Persist under write-once semantics; returns a location key."""


class LocalAnchorStore:
    def __init__(self):
        self.anchors: list[dict] = []

    def put_anchor(self, anchor: dict) -> str:
        self.anchors.append(anchor)
        return f"local://anchors/{len(self.anchors) - 1}"


def anchor_chains(sidecar, tenants: list[str], store: AnchorStore,
                  signer: signing.Signer | None = None, now: float | None = None) -> dict:
    signer = signer or signing.Signer()
    now = time.time() if now is None else now
    heads = {t: sidecar.chain_head(t) for t in tenants}
    root = merkle_root(list(heads.values()))
    body = {"ts": now, "chain_heads": heads, "merkle_root": root}
    anchor = dict(body)
    anchor["signature"] = signer.sign(body)
    location = store.put_anchor(anchor)
    for t in tenants:
        sidecar.audit_append(t, "ANCHOR", detail={"merkle_root": root, "location": location})
    return anchor
