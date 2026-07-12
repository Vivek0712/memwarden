"""Permanent regression gates required by the round-3 AWS review:

1. The held-out corpus runs on every change; L1 recall must stay at the paper's
   measured envelope (low on OOD attacks) and precision must stay 1.00.
2. The gate-attribution harness: of 8 representative held-out writes from an
   untrusted channel with no L2 clearance, L1 blocks 1 at write time, the
   trust gate holds 7 at read time, and zero records reach agent context
   (paper §6.5).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "eval"))

from engram.detect import rules
from engram.errors import WriteRejected

from conftest import NS

# Import the paper's held-out corpus from the shipped eval script.
import heldout_eval as he  # noqa: E402  (prints its report on import; harmless in CI)


def _recall(samples):
    return sum(1 for s in samples if rules.scan(s, source_untrusted=True).score >= 0.5)


def test_heldout_recall_matches_paper_table7():
    assert _recall(he.paraphrase) == 0      # 0/10
    assert _recall(he.obfuscated) == 2      # 2/6
    assert _recall(he.multiturn) == 0       # 0/5


def test_heldout_precision_stays_perfect():
    assert _recall(he.benign_shift) == 0    # 0 FP / 8


# ---------------------------------------------------------------------------
# Gate attribution: which control is load-bearing for the guarantee.
# ---------------------------------------------------------------------------

# 8 representative held-out attacks (paper §6.5): the zero-width obfuscation
# (write-blocked by the structural detector) plus seven zero-L1-flag paraphrase
# and multi-turn payloads that only the trust gate can hold.
REPRESENTATIVE = [
    he.obfuscated[5],       # zero-width override -> L1 write-time block
    he.paraphrase[0], he.paraphrase[1], he.paraphrase[5], he.paraphrase[7],
    he.multiturn[1], he.multiturn[3], he.multiturn[4],
]


def test_gate_attribution_zero_admitted(memory):
    blocked_at_write = 0
    written = []
    for payload in REPRESENTATIVE:
        try:
            written.append(memory.write(payload, NS, "web_fetch", "attacker"))
        except WriteRejected:
            blocked_at_write += 1

    assert blocked_at_write == 1                       # L1 blocks 1 of 8

    admitted = []
    for payload in REPRESENTATIVE:
        admitted.extend(memory.retrieve(NS, payload, k=8))
    assert admitted == []                              # zero reach agent context

    # The remaining 7 persist but are held by the trust gate: untrusted
    # provenance without deep-scan clearance is inadmissible regardless of L1.
    held = [e for e in memory.sidecar.audit_entries("acme")
            if e.op == "READ_DROP" and e.detail.get("gate") == "trust_gate"]
    assert len({e.record_id_hash for e in held}) == 7
