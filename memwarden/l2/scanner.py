"""L2 out-of-band scanner: the record-stream consumer (design §8).

Transport-agnostic handler for record lifecycle events (CREATE/UPDATE/DELETE).
In production it runs as a Lambda on the AgentCore Kinesis record stream; the
same function is invoked directly in tests and in live validation with
simulated stream delivery (notes N5). Guardrails is injected so the CI stub
and the live Bedrock ApplyGuardrail client are interchangeable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional, Protocol

from ..envelope import GovernanceEnvelope, TrustTier, sha256_hex
from ..metrics import registry
from ..policy import Policy
from ..sidecar.base import CLEARED, FAILED, Verdict


class GuardrailClient(Protocol):
    def assess(self, content: str) -> tuple[bool, dict]:
        """Returns (attack_detected, detail)."""


@dataclass
class RecordEvent:
    """Canonical lifecycle-event shape delivered by the record stream."""
    event_type: str          # CREATE | UPDATE | DELETE
    tenant_id: str
    record_id: str
    namespace: str
    content: Optional[str] = None
    actor_id: str = ""
    ts: float = field(default_factory=time.time)


def handle_record_event(event: RecordEvent, sidecar, policy: Policy,
                        guardrail: GuardrailClient, oracle=None) -> Optional[str]:
    """Normative per-record flow (design §8.2). Returns the verdict written, if any.

    Idempotent under at-least-once delivery: verdicts are keyed by record id and
    content digest, so redelivery is a no-op; an update event with a new digest
    overwrites and thereby revokes prior clearance.
    """
    if event.event_type == "DELETE":
        sidecar.delete_envelope(event.tenant_id, event.record_id)
        sidecar.delete_verdict(event.tenant_id, event.record_id)
        return None

    assert event.content is not None, "CREATE/UPDATE events carry content"
    digest = sha256_hex(event.content)

    env = sidecar.get_envelope(event.tenant_id, event.record_id)
    if env is None:
        # Extraction-pipeline write the interceptor never saw: upsert a DERIVED
        # envelope with retention resolved from policy on the namespace.
        rc = policy.resolve_retention("extraction", event.namespace)
        now = event.ts
        env = GovernanceEnvelope.stamp(
            tenant_id=event.tenant_id, actor_id=event.actor_id,
            namespace=event.namespace, channel="extraction", content=event.content,
            retention_class=rc.name,
            expires_at_epoch=now + rc.ttl_days * 86400 if rc.ttl_days else None,
            created_at=now, policy_version=policy.version,
            trust_tier=TrustTier.DERIVED)
        if hasattr(sidecar, "bind_record"):
            sidecar.put_envelope(env)
            sidecar.bind_record(env, event.record_id)
        else:
            sidecar.put_envelope_for(event.record_id, env)
    elif env.content_sha256 != digest:
        # Content changed out from under a prior verdict: refresh the digest so
        # any prior clearance (keyed to the old digest) is revoked.
        env.content_sha256 = digest
        if hasattr(sidecar, "bind_record"):
            sidecar.put_envelope(env)
            sidecar.bind_record(env, event.record_id)
        else:
            sidecar.put_envelope_for(event.record_id, env)

    # Scan scoping: UNTRUSTED and DERIVED by default (design §8.3) — the cost
    # lever. Records the interceptor quarantined (a PENDING verdict) are always
    # scanned regardless of tier, or their quarantine could never resolve.
    existing = sidecar.get_verdict(event.tenant_id, event.record_id)
    pending_here = existing is not None and existing.verdict not in (CLEARED, FAILED)
    if int(env.trust_tier) not in policy.l2_scan_tiers and not pending_here:
        return None

    if existing is not None and existing.verdict_digest == digest \
            and existing.verdict in (CLEARED, FAILED):
        return existing.verdict  # redelivery no-op

    attack, detail = guardrail.assess(event.content)
    verdict = FAILED if attack else CLEARED
    v = Verdict(verdict, digest, l2_detail=detail)
    sidecar.put_verdict(event.tenant_id, event.record_id, v)
    if oracle is not None:
        # Verdict stream feeds the read-path cache (design §8.4).
        oracle.publish(event.record_id, v)
    registry.incr("memwarden.l2.verdicts", verdict=verdict)
    return verdict


class StubGuardrail:
    """CI stand-in for Bedrock Guardrails. Marker-driven so tests control the
    verdict: content containing ##ATTACK## fails, everything else clears —
    including L1 false positives, which is exactly the deep-scan clearance
    scenario the failure-mode suite exercises."""

    def assess(self, content: str) -> tuple[bool, dict]:
        if "##ATTACK##" in content:
            return True, {"source": "stub", "reason": "marker"}
        return False, {"source": "stub"}
