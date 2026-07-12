"""Redis backend adapter (beta).

Transport only, per the protocol contract. Records live in Redis hashes keyed by
namespace+id; an actor secondary index supports the erasure walk. Retrieval is a
keyword scan over the namespace (non-semantic) — adequate for exact/keyword
recall and for the conformance suite; pair with RediSearch/vector for semantic
ranking in production. Requires `pip install engram[redis]`.
"""

from __future__ import annotations

import json
import uuid
from typing import Iterator, Optional

from .base import Page, Record


class RedisBackend:
    def __init__(self, url: str = "redis://localhost:6379/0", client=None,
                 key_prefix: str = "engram"):
        if client is None:
            import redis  # lazy: only needed if this adapter is used
            client = redis.Redis.from_url(url, decode_responses=True)
        self.r = client
        self.p = key_prefix

    def _rkey(self, ns: str, rid: str) -> str:
        return f"{self.p}:rec:{ns}:{rid}"

    def _nskey(self, ns: str) -> str:
        return f"{self.p}:ns:{ns}"

    def _actorkey(self, actor_id: str) -> str:
        return f"{self.p}:actor:{actor_id}"

    def put(self, ns: str, content: str, meta: dict) -> str:
        rid = uuid.uuid4().hex
        self.r.hset(self._rkey(ns, rid),
                    mapping={"content": content, "meta": json.dumps(meta), "ns": ns})
        self.r.sadd(self._nskey(ns), rid)
        if meta.get("actor_id"):
            self.r.sadd(self._actorkey(meta["actor_id"]), f"{ns}\x00{rid}")
        return rid

    def get(self, ns: str, record_id: str) -> Optional[Record]:
        h = self.r.hgetall(self._rkey(ns, record_id))
        if not h:
            return None
        return Record(record_id, ns, h["content"], json.loads(h.get("meta", "{}")))

    def retrieve(self, ns: str, query: str, k: int = 8) -> list[Record]:
        q = set(query.lower().split())
        scored = []
        for rid in self.r.smembers(self._nskey(ns)):
            rec = self.get(ns, rid)
            if rec is None:
                continue
            overlap = len(q & set(rec.content.lower().split()))
            scored.append((overlap, rec.record_id, rec))
        scored.sort(key=lambda t: (-t[0], t[1]))
        return [rec for _, _, rec in scored[:k]]

    def list(self, ns: str, cursor: Optional[str] = None) -> Page:
        ids = sorted(self.r.smembers(self._nskey(ns)))
        start = ids.index(cursor) + 1 if cursor in ids else 0
        chunk = ids[start:start + 100]
        nxt = chunk[-1] if len(chunk) == 100 and chunk[-1] != ids[-1] else None
        return Page([r for r in (self.get(ns, i) for i in chunk) if r], nxt)

    def delete(self, ns: str, record_id: str) -> bool:
        existed = self.r.delete(self._rkey(ns, record_id)) > 0
        self.r.srem(self._nskey(ns), record_id)
        return existed

    def batch_delete(self, ns: str, record_ids: list[str]) -> int:
        return sum(1 for rid in record_ids if self.delete(ns, rid))

    def list_by_actor(self, actor_id: str) -> Iterator[Record]:
        for entry in self.r.smembers(self._actorkey(actor_id)):
            ns, rid = entry.split("\x00", 1)
            rec = self.get(ns, rid)
            if rec is not None:
                yield rec
