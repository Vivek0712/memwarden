"""pgvector (Postgres) backend adapter — interface stub (beta).

The seven-operation surface is defined here against a `records` table with a
`vector` column; `retrieve` is a cosine-distance nearest-neighbor query. Wiring
to an embedding function is deployment-specific, so `_embed` is left as the one
integration point. Requires `pip install memwarden[pgvector]`.

This adapter is a documented stub: the method bodies show the intended SQL and
raise NotImplementedError where the embedding hook must be supplied. It passes
the protocol's *shape* check; the conformance suite runs against a live database
once `_embed` is provided.
"""

from __future__ import annotations

from typing import Callable, Iterator, Optional

from .base import Page, Record


class PgVectorBackend:
    def __init__(self, dsn: str, embed: Optional[Callable[[str], list[float]]] = None,
                 table: str = "memwarden_records", conn=None):
        self.dsn = dsn
        self.table = table
        self._embed_fn = embed
        self._conn = conn  # inject a psycopg connection, or lazily connect

    def _embed(self, text: str) -> list[float]:
        if self._embed_fn is None:
            raise NotImplementedError(
                "PgVectorBackend needs an embedding function: "
                "PgVectorBackend(dsn, embed=my_embed_fn)")
        return self._embed_fn(text)

    # Intended SQL is shown per method; implement against psycopg once embed is set.
    def put(self, ns: str, content: str, meta: dict) -> str:  # pragma: no cover
        # INSERT INTO {table}(id, ns, content, meta, embedding) VALUES (...)
        raise NotImplementedError("provide a psycopg connection and embed fn")

    def get(self, ns: str, record_id: str) -> Optional[Record]:  # pragma: no cover
        raise NotImplementedError

    def retrieve(self, ns: str, query: str, k: int = 8) -> list[Record]:  # pragma: no cover
        # SELECT ... ORDER BY embedding <=> %(qvec)s LIMIT k  WHERE ns = %(ns)s
        raise NotImplementedError

    def list(self, ns: str, cursor: Optional[str] = None) -> Page:  # pragma: no cover
        raise NotImplementedError

    def delete(self, ns: str, record_id: str) -> bool:  # pragma: no cover
        raise NotImplementedError

    def batch_delete(self, ns: str, record_ids: list[str]) -> int:  # pragma: no cover
        raise NotImplementedError

    def list_by_actor(self, actor_id: str) -> Iterator[Record]:  # pragma: no cover
        raise NotImplementedError
