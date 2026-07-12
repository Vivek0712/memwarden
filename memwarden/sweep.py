"""Retention sweep: scheduled deletion of expired records (design §9).
Legal-hold rows are skipped and counted."""

from __future__ import annotations

import time
from dataclasses import dataclass

from .metrics import registry


@dataclass
class SweepResult:
    deleted: int
    holds_skipped: int


def sweep_tenant(backend, sidecar, tenant_id: str, now: float | None = None) -> SweepResult:
    now = time.time() if now is None else now
    by_ns: dict[str, list[str]] = {}
    holds = 0
    for rid, env in sidecar.expired_envelopes(tenant_id, now):
        if env.legal_hold:
            holds += 1
            continue
        by_ns.setdefault(env.namespace, []).append(rid)

    deleted = 0
    for ns, rids in by_ns.items():
        for i in range(0, len(rids), 100):
            chunk = rids[i:i + 100]
            n = backend.batch_delete(ns, chunk)
            deleted += n
            sidecar.audit_append(tenant_id, "SWEEP_BATCH",
                                 detail={"namespace": ns, "deleted": n,
                                         "holds_skipped_so_far": holds})
        for rid in rids:
            sidecar.delete_envelope(tenant_id, rid)
            sidecar.delete_verdict(tenant_id, rid)
    registry.incr("memwarden.sweep.deleted", deleted)
    return SweepResult(deleted=deleted, holds_skipped=holds)
