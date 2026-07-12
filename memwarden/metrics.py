"""Minimal metrics registry (design §15). Namespace `memwarden`."""

from __future__ import annotations

from collections import defaultdict


class Metrics:
    def __init__(self):
        self.counters: dict[str, int] = defaultdict(int)

    def incr(self, name: str, value: int = 1, **dims) -> None:
        key = name if not dims else name + "[" + ",".join(f"{k}={v}" for k, v in sorted(dims.items())) + "]"
        self.counters[key] += value

    def get(self, name: str, **dims) -> int:
        key = name if not dims else name + "[" + ",".join(f"{k}={v}" for k, v in sorted(dims.items())) + "]"
        return self.counters[key]


registry = Metrics()
