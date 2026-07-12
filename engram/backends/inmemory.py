"""In-memory reference backend: the conformance reference and the CI default."""

from __future__ import annotations

import uuid
from typing import Iterator, Optional

from .base import Page, Record


class InMemoryBackend:
    PAGE_SIZE = 100

    def __init__(self):
        self._records: dict[str, dict[str, Record]] = {}  # ns -> id -> Record
        # short-term event tier, mirroring AgentCore's two-tier shape
        self._events: dict[str, list[dict]] = {}          # actor_id -> events

    # -- seven-operation protocol -------------------------------------------
    def put(self, ns: str, content: str, meta: dict) -> str:
        rid = uuid.uuid4().hex
        self._records.setdefault(ns, {})[rid] = Record(rid, ns, content, dict(meta))
        return rid

    def get(self, ns: str, record_id: str) -> Optional[Record]:
        return self._records.get(ns, {}).get(record_id)

    def retrieve(self, ns: str, query: str, k: int = 8) -> list[Record]:
        # Lexical overlap stands in for semantic search; ranking quality is the
        # store's concern, not the governance layer's.
        q = set(query.lower().split())
        scored = []
        for rec in self._records.get(ns, {}).values():
            overlap = len(q & set(rec.content.lower().split()))
            scored.append((overlap, rec.record_id, rec))
        scored.sort(key=lambda t: (-t[0], t[1]))
        return [rec for _, _, rec in scored[:k]]

    def list(self, ns: str, cursor: Optional[str] = None) -> Page:
        ids = sorted(self._records.get(ns, {}))
        start = ids.index(cursor) + 1 if cursor in ids else 0
        chunk = ids[start:start + self.PAGE_SIZE]
        next_cursor = chunk[-1] if len(chunk) == self.PAGE_SIZE and chunk[-1] != ids[-1] else None
        return Page(records=[self._records[ns][i] for i in chunk], cursor=next_cursor)

    def delete(self, ns: str, record_id: str) -> bool:
        return self._records.get(ns, {}).pop(record_id, None) is not None

    def batch_delete(self, ns: str, record_ids: list[str]) -> int:
        return sum(1 for rid in record_ids if self.delete(ns, rid))

    def list_by_actor(self, actor_id: str) -> Iterator[Record]:
        for ns, recs in self._records.items():
            for rec in recs.values():
                if rec.meta.get("actor_id") == actor_id:
                    yield rec

    # -- event tier ----------------------------------------------------------
    def create_event(self, actor_id: str, session_id: str, payload: str) -> None:
        self._events.setdefault(actor_id, []).append(
            {"session_id": session_id, "payload": payload})

    def event_count(self, actor_id: str) -> int:
        return len(self._events.get(actor_id, []))

    def delete_actor_events(self, actor_id: str) -> int:
        return len(self._events.pop(actor_id, []))
