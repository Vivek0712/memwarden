"""Per-tenant hash-chained audit log with Merkle cross-anchoring (design §4.3, §10)."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, asdict
from typing import Iterable, Optional

GENESIS = "0" * 64


def canonical_body(body: dict) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _entry_hash(prev_hash: str, body) -> str:
    """body may be the dict or its canonical JSON string. Durable stores keep
    the canonical string verbatim, so storage number typing (e.g. DynamoDB
    normalizing 0.0 to 0) can never perturb the hash."""
    payload = body if isinstance(body, str) else canonical_body(body)
    return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()


def _h(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


@dataclass
class AuditEntry:
    seq: int
    op: str
    record_id_hash: str
    actor_hash: str
    detail: dict
    ts: float
    prev_hash: str
    entry_hash: str

    def body(self) -> dict:
        return {"seq": self.seq, "op": self.op, "record_id_hash": self.record_id_hash,
                "actor_hash": self.actor_hash, "detail": self.detail, "ts": self.ts}


class AuditChain:
    """One chain per tenant. Storage-agnostic: subclasses override _read_head /
    _append_item / entries(). This base class is the in-memory reference."""

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self._entries: list[AuditEntry] = []

    # -- append protocol ----------------------------------------------------
    def append(self, op: str, record_id: str = "", actor_id: str = "",
               detail: Optional[dict] = None, ts: Optional[float] = None) -> AuditEntry:
        prev = self._entries[-1].entry_hash if self._entries else GENESIS
        seq = len(self._entries)
        body = {"seq": seq, "op": op,
                "record_id_hash": _h(record_id) if record_id else "",
                "actor_hash": _h(actor_id) if actor_id else "",
                "detail": detail or {}, "ts": ts if ts is not None else time.time()}
        entry = AuditEntry(prev_hash=prev, entry_hash=_entry_hash(prev, body), **body)
        self._entries.append(entry)
        return entry

    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def head(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS

    # -- verification (engram-verify replays this) --------------------------
    @staticmethod
    def verify(entries: Iterable[AuditEntry]) -> tuple[bool, Optional[int]]:
        """Replay the chain; returns (ok, first_bad_seq)."""
        prev = GENESIS
        for i, e in enumerate(entries):
            if e.seq != i or e.prev_hash != prev or _entry_hash(prev, e.body()) != e.entry_hash:
                return False, i
            prev = e.entry_hash
        return True, None


def merkle_root(leaves: list[str]) -> str:
    """Merkle root over chain heads for cross-anchoring (design §10)."""
    if not leaves:
        return GENESIS
    level = [hashlib.sha256(x.encode()).hexdigest() for x in sorted(leaves)]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256((a + b).encode()).hexdigest()
                 for a, b in zip(level[::2], level[1::2])]
    return level[0]
