"""The seven-operation MemoryBackend protocol — the portability contract (design §5.1).

Adapters own transport only. No adapter contains policy, detection, audit, or
erasure logic. A backend passes the conformance suite or it does not ship.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional, Protocol, runtime_checkable


@dataclass
class Record:
    record_id: str
    namespace: str
    content: str
    meta: dict = field(default_factory=dict)


@dataclass
class Page:
    records: list[Record]
    cursor: Optional[str] = None


@runtime_checkable
class MemoryBackend(Protocol):
    def put(self, ns: str, content: str, meta: dict) -> str: ...
    def get(self, ns: str, record_id: str) -> Optional[Record]: ...
    def retrieve(self, ns: str, query: str, k: int = 8) -> list[Record]: ...
    def list(self, ns: str, cursor: Optional[str] = None) -> Page: ...
    def delete(self, ns: str, record_id: str) -> bool: ...
    def batch_delete(self, ns: str, record_ids: list[str]) -> int: ...
    def list_by_actor(self, actor_id: str) -> Iterator[Record]: ...


class EventTierBackend(Protocol):
    """Optional short-term event tier (AgentCore has one; most stores do not)."""

    def delete_actor_events(self, actor_id: str) -> int: ...
