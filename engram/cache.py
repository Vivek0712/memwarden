"""Verdict-stream cache: removes the sidecar hop from the common read (design §8.4).

The quarantine set is small and negative-heavy: most retrieved records have no
verdict row at all. A Bloom filter of verdict-bearing record ids, rebuilt from
the verdict stream, answers "definitely no verdict -> fail closed without a
sidecar lookup" for the common untrusted read; an LRU of recent verdicts serves
the positive case (a CLEARED record read repeatedly) without a hop either. The
filter has no false negatives, so a negative answer is authoritative and the
fail-closed guarantee is preserved.
"""

from __future__ import annotations

import hashlib
import math
from collections import OrderedDict
from typing import Optional

from .sidecar.base import Verdict


class BloomFilter:
    def __init__(self, capacity: int = 100_000, error_rate: float = 0.01):
        self.capacity = max(1, capacity)
        self.error_rate = error_rate
        self.size = max(1, int(-self.capacity * math.log(error_rate) / (math.log(2) ** 2)))
        self.hashes = max(1, int(round((self.size / self.capacity) * math.log(2))))
        self.bits = bytearray((self.size + 7) // 8)
        self.count = 0

    def _positions(self, item: str):
        h = hashlib.sha256(item.encode()).digest()
        h1 = int.from_bytes(h[:8], "big")
        h2 = int.from_bytes(h[8:16], "big") | 1
        for i in range(self.hashes):
            yield (h1 + i * h2) % self.size

    def add(self, item: str) -> None:
        for pos in self._positions(item):
            self.bits[pos >> 3] |= (1 << (pos & 7))
        self.count += 1

    def __contains__(self, item: str) -> bool:
        return all(self.bits[pos >> 3] & (1 << (pos & 7)) for pos in self._positions(item))


class QuarantineOracle:
    """Combines a Bloom filter (membership: does this id have any verdict) with
    an LRU of exact verdicts. Fed by the L2 scanner's verdict stream.

    Read-path contract:
      - `maybe_has_verdict(id)` False  -> caller knows there is no verdict,
        no sidecar lookup needed (fail-closed for untrusted still applies).
      - cached_verdict(id) returns a Verdict for a hot record without a hop.
    A miss on the LRU while the Bloom says "maybe" falls through to the sidecar.
    """

    def __init__(self, capacity: int = 100_000, error_rate: float = 0.01,
                 lru_size: int = 10_000):
        self.bloom = BloomFilter(capacity, error_rate)
        self.lru: "OrderedDict[str, Verdict]" = OrderedDict()
        self.lru_size = lru_size
        self.stats = {"bloom_negative": 0, "lru_hit": 0, "sidecar_fallthrough": 0}

    def publish(self, record_id: str, verdict: Verdict) -> None:
        self.bloom.add(record_id)
        self.lru[record_id] = verdict
        self.lru.move_to_end(record_id)
        while len(self.lru) > self.lru_size:
            self.lru.popitem(last=False)

    def maybe_has_verdict(self, record_id: str) -> bool:
        return record_id in self.bloom

    def lookup(self, record_id: str) -> tuple[str, Optional[Verdict]]:
        """Returns (source, verdict). source in {'bloom_negative','lru','sidecar'}."""
        if record_id not in self.bloom:
            self.stats["bloom_negative"] += 1
            return "bloom_negative", None
        v = self.lru.get(record_id)
        if v is not None:
            self.stats["lru_hit"] += 1
            self.lru.move_to_end(record_id)
            return "lru", v
        self.stats["sidecar_fallthrough"] += 1
        return "sidecar", None

    def hit_rate(self) -> float:
        total = sum(self.stats.values())
        served = self.stats["bloom_negative"] + self.stats["lru_hit"]
        return served / total if total else 0.0
