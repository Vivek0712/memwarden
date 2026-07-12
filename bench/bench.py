"""Reference benchmark harness (paper §6.1–§6.2): 8,000 governed writes and
3,000 governed retrievals against the raw in-memory backend on identical inputs,
per-stage decomposition, content-length scaling, and sustained throughput.

Single process, library topology: the reported deltas are the pure
governance-layer cost. Run: python bench/bench.py [--out results.json]
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from memwarden.backends.inmemory import InMemoryBackend
from memwarden.detect import rules
from memwarden.envelope import GovernanceEnvelope
from memwarden.governed import GovernedMemory
from memwarden.policy import Policy
from memwarden.sidecar.local import LocalSidecar

POLICY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "policies", "policy.yaml")
NS = "tenants/acme/bench/actor1"

WORDS = ("meeting schedule preference dashboard release vendor invoice summary "
         "customer ticket roadmap deploy branch review metric alert channel "
         "quarter travel booking laptop docking calendar timezone budget").split()


def synth_content(rng: random.Random, tokens: int = 24) -> str:
    """Sentence-shaped agent-memory statements (~10-word sentences)."""
    words = [rng.choice(WORDS) for _ in range(tokens)]
    for i in range(9, len(words), 10):
        words[i] += "."
    return " ".join(words)


def pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def summarize(xs_ms: list[float]) -> dict:
    return {"p50": round(pct(xs_ms, 50), 4), "p95": round(pct(xs_ms, 95), 4),
            "p99": round(pct(xs_ms, 99), 4), "mean": round(statistics.fmean(xs_ms), 4)}


def bench_writes(n: int = 8000) -> dict:
    rng = random.Random(42)
    contents = [synth_content(rng) for _ in range(n)]

    raw = InMemoryBackend()
    t_raw = []
    for c in contents:
        t0 = time.perf_counter_ns()
        raw.put(NS, c, {"actor_id": "actor1"})
        t_raw.append((time.perf_counter_ns() - t0) / 1e6)

    gov = GovernedMemory(InMemoryBackend(), "acme", Policy.load(POLICY), LocalSidecar())
    t_gov = []
    for c in contents:
        t0 = time.perf_counter_ns()
        gov.write(c, NS, "user_turn", "actor1")
        t_gov.append((time.perf_counter_ns() - t0) / 1e6)

    raw_s, gov_s = summarize(t_raw), summarize(t_gov)
    overhead = {k: round(gov_s[k] - raw_s[k], 4) for k in raw_s}
    pct_of_rtt = {k: f"{overhead[k] / 25.0 * 100:.2f}%" for k in overhead}
    return {"n": n, "raw_write_ms": raw_s, "governed_write_ms": gov_s,
            "write_overhead_ms": overhead, "overhead_as_pct_of_25ms_rtt": pct_of_rtt}


def bench_reads(n: int = 3000, corpus_size: int = 1000) -> dict:
    rng = random.Random(43)
    backend_raw, backend_gov = InMemoryBackend(), InMemoryBackend()
    gov = GovernedMemory(backend_gov, "acme", Policy.load(POLICY), LocalSidecar())
    for _ in range(corpus_size):
        c = synth_content(rng)
        backend_raw.put(NS, c, {"actor_id": "actor1"})
        gov.write(c, NS, "user_turn", "actor1")
    queries = [synth_content(rng, tokens=5) for _ in range(n)]

    t_raw = []
    for q in queries:
        t0 = time.perf_counter_ns()
        backend_raw.retrieve(NS, q, k=8)
        t_raw.append((time.perf_counter_ns() - t0) / 1e6)
    t_gov = []
    for q in queries:
        t0 = time.perf_counter_ns()
        gov.retrieve(NS, q, k=8)
        t_gov.append((time.perf_counter_ns() - t0) / 1e6)

    raw_s, gov_s = summarize(t_raw), summarize(t_gov)
    return {"n": n, "corpus_size": corpus_size, "raw_read_ms": raw_s,
            "governed_read_ms": gov_s,
            "read_overhead_ms": {k: round(gov_s[k] - raw_s[k], 4) for k in raw_s}}


def bench_stages(n: int = 8000) -> dict:
    """Per-stage decomposition (paper Fig. 4)."""
    rng = random.Random(44)
    contents = [synth_content(rng) for _ in range(n)]
    policy = Policy.load(POLICY)
    sidecar = LocalSidecar()
    gov = GovernedMemory(InMemoryBackend(), "acme", policy, sidecar)

    stages: dict[str, list[float]] = {k: [] for k in
                                      ("l1_scan", "envelope_stamp", "retention_resolve",
                                       "audit_append", "read_admission")}
    now = time.time()
    for c in contents:
        t0 = time.perf_counter_ns()
        rules.scan(c, source_untrusted=True)
        stages["l1_scan"].append((time.perf_counter_ns() - t0) / 1e6)

        t0 = time.perf_counter_ns()
        rc = policy.resolve_retention("user_turn", NS)
        stages["retention_resolve"].append((time.perf_counter_ns() - t0) / 1e6)

        t0 = time.perf_counter_ns()
        GovernanceEnvelope.stamp(tenant_id="acme", actor_id="a", namespace=NS,
                                 channel="user_turn", content=c, retention_class=rc.name,
                                 expires_at_epoch=now + 86400, created_at=now,
                                 policy_version=policy.version)
        stages["envelope_stamp"].append((time.perf_counter_ns() - t0) / 1e6)

        t0 = time.perf_counter_ns()
        sidecar.audit_append("acme", "WRITE", record_id="r", actor_id="a",
                             detail={"namespace": NS})
        stages["audit_append"].append((time.perf_counter_ns() - t0) / 1e6)

    rid = gov.write(contents[0], NS, "user_turn", "a")
    rec = gov.backend.get(NS, rid)
    for _ in range(3000):
        t0 = time.perf_counter_ns()
        gov._admit(rec)
        stages["read_admission"].append((time.perf_counter_ns() - t0) / 1e6)

    return {name: summarize(xs) for name, xs in stages.items()}


def bench_scaling() -> dict:
    """L1 cost vs content length (paper Fig. 5a)."""
    rng = random.Random(45)
    out = {}
    for tokens in (8, 16, 32, 64, 128):
        samples = [synth_content(rng, tokens) for _ in range(2000)]
        ts = []
        for s in samples:
            t0 = time.perf_counter_ns()
            rules.scan(s, source_untrusted=True)
            ts.append((time.perf_counter_ns() - t0) / 1e6)
        out[str(tokens)] = summarize(ts)
    return out


def bench_throughput(seconds: float = 5.0) -> dict:
    """Sustained governed write throughput, single process (paper Fig. 5b)."""
    rng = random.Random(46)
    contents = [synth_content(rng) for _ in range(4000)]
    gov = GovernedMemory(InMemoryBackend(), "acme", Policy.load(POLICY), LocalSidecar())
    n, i = 0, 0
    t_end = time.perf_counter() + seconds
    while time.perf_counter() < t_end:
        gov.write(contents[i % len(contents)], NS, "user_turn", "actor1")
        n += 1
        i += 1
    return {"duration_s": seconds, "governed_writes_per_s": int(n / seconds)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    results = {
        "writes": bench_writes(),
        "reads": bench_reads(),
        "stages": bench_stages(),
        "l1_scaling_by_tokens": bench_scaling(),
        "throughput": bench_throughput(),
    }
    print(json.dumps(results, indent=2))
    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()
