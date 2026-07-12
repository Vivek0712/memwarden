"""GovernedMemory: the inline interceptor (paper §4, design §6–§7, §9).

Write path (normative order): tenant prefix check -> L1 scan -> envelope stamp ->
audit append -> backend write -> post-commit sidecar write.

Read path (normative order, each gate independent): tenant scope check -> backend
retrieval -> Gate 1 quarantine -> Gate 2 TTL -> Gate 3 integrity -> Gate 4 trust
tier -> audit. Fails closed on every ambiguous state.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from . import signing
from .audit import AuditChain
from .backends.base import MemoryBackend, Record
from .detect import rules
from .envelope import GovernanceEnvelope, TrustTier, tier_for_channel
from .errors import SidecarUnavailable, TenantViolation, WriteRejected
from .metrics import registry
from .policy import Policy
from .sidecar.base import CLEARED, FAILED, PENDING, Verdict

REJECT_THRESHOLD = 0.9
QUARANTINE_THRESHOLD = 0.5


@dataclass
class ErasureResult:
    records_deleted: int
    events_deleted: int
    holds_retained: int
    certificate: dict
    conflicts: list[str] = field(default_factory=list)


class GovernedMemory:
    def __init__(self, backend: MemoryBackend, tenant_id: str, policy: Policy,
                 sidecar=None, signer: Optional[signing.Signer] = None,
                 clock=time.time, quarantine_oracle=None):
        from .sidecar.local import LocalSidecar
        self.backend = backend
        self.tenant_id = tenant_id
        self.policy = policy
        self.sidecar = sidecar if sidecar is not None else LocalSidecar()
        self.signer = signer or signing.Signer()
        self.clock = clock
        # Optional verdict-stream cache (design §8.4): serves the common read
        # without a sidecar verdict lookup. Safe because the Bloom filter has no
        # false negatives, so "not present" authoritatively means "no verdict".
        self.oracle = quarantine_oracle
        # Write-through local envelope cache: the degraded-mode admission basis
        # for SYSTEM/FIRST_PARTY when the sidecar is unreachable (design §7).
        self._env_cache: dict[str, GovernanceEnvelope] = {}

    # ------------------------------------------------------------------ write
    def _tenant_prefix(self) -> str:
        return f"tenants/{self.tenant_id}/"

    def _check_tenant(self, namespace: str) -> None:
        if not namespace.startswith(self._tenant_prefix()):
            raise TenantViolation(
                f"namespace {namespace!r} outside tenant scope {self._tenant_prefix()!r}")

    def write(self, content: str, namespace: str, source_channel: str,
              actor_id: str = "") -> str:
        # 1. tenant prefix check (O(1) string compare)
        self._check_tenant(namespace)

        # 2. L1 deterministic scan, amplified for untrusted provenance
        tier = tier_for_channel(source_channel)
        result = rules.scan(content, source_untrusted=(tier == TrustTier.UNTRUSTED))
        if result.score >= REJECT_THRESHOLD:
            self.sidecar.audit_append(
                self.tenant_id, "WRITE_REJECTED", record_id="", actor_id=actor_id,
                detail={"l1_score": round(result.score, 3), "families": result.families,
                        "namespace": namespace})
            registry.incr("memwarden.write.rejected")
            raise WriteRejected(result.score, result.families)
        quarantined = result.score >= QUARANTINE_THRESHOLD

        # 3. envelope stamp
        now = self.clock()
        rc = self.policy.resolve_retention(source_channel, namespace)
        expires = now + rc.ttl_days * 86400 if rc.ttl_days else None
        env = GovernanceEnvelope.stamp(
            tenant_id=self.tenant_id, actor_id=actor_id, namespace=namespace,
            channel=source_channel, content=content, retention_class=rc.name,
            expires_at_epoch=expires, created_at=now,
            policy_version=self.policy.version, quarantined=quarantined)

        # 4. audit append
        self.sidecar.audit_append(
            self.tenant_id, "WRITE", record_id=env.envelope_id, actor_id=actor_id,
            detail={"namespace": namespace, "channel": source_channel,
                    "tier": int(env.trust_tier), "retention_class": rc.name,
                    "quarantined": quarantined, "l1_score": round(result.score, 3)})

        # 5. backend write
        rid = self.backend.put(namespace, content, {"actor_id": actor_id})

        # 6. post-commit sidecar write
        if hasattr(self.sidecar, "bind_record"):
            self.sidecar.put_envelope(env)
            self.sidecar.bind_record(env, rid)
        else:
            self.sidecar.put_envelope_for(rid, env)
        if quarantined:
            v = Verdict(PENDING, env.content_sha256, result.score)
            self.sidecar.put_verdict(self.tenant_id, rid, v)
            if self.oracle is not None:
                self.oracle.publish(rid, v)
            registry.incr("memwarden.write.quarantined")
        self._env_cache[rid] = env
        return rid

    # ------------------------------------------------------------------- read
    def retrieve(self, namespace: str, query: str, k: int = 8) -> list[Record]:
        # Cross-tenant reads fail closed to empty rather than raising: the agent
        # never sees ungoverned data, and the attempt is audited (design §14.2
        # "empty cross-tenant read").
        if not namespace.startswith(self._tenant_prefix()):
            registry.incr("memwarden.read.dropped_by_gate", gate="tenant_scope")
            self.sidecar.audit_append(self.tenant_id, "READ_DROP",
                                      detail={"gate": "tenant_scope", "namespace": namespace})
            return []
        candidates = self.backend.retrieve(namespace, query, k)
        admitted = []
        for rec in candidates:
            if self._admit(rec):
                admitted.append(rec)
        self.sidecar.audit_append(
            self.tenant_id, "READ", record_id="", actor_id="",
            detail={"namespace": namespace, "candidates": len(candidates),
                    "admitted": len(admitted)})
        return admitted

    def _drop(self, rec: Record, gate: str) -> bool:
        registry.incr("memwarden.read.dropped_by_gate", gate=gate)
        self.sidecar.audit_append(self.tenant_id, "READ_DROP", record_id=rec.record_id,
                                  detail={"gate": gate})
        return False

    def _cleared(self, rec: Record, env: GovernanceEnvelope) -> Optional[bool]:
        """True: CLEARED for current digest. False: FAILED (terminal). None: no verdict."""
        v = None
        if self.oracle is not None:
            source, cached = self.oracle.lookup(rec.record_id)
            if source == "bloom_negative":
                return None                      # no verdict, no sidecar hop
            if source == "lru":
                v = cached                       # served from cache, no hop
        if v is None:
            v = self.sidecar.get_verdict(self.tenant_id, rec.record_id)
        if v is None or v.verdict_digest != env.content_sha256:
            return None
        if v.verdict == CLEARED:
            return True
        if v.verdict == FAILED:
            return False
        return None

    def _admit(self, rec: Record) -> bool:
        now = self.clock()
        min_tier = self.policy.min_trust_tier_without_deep_scan

        try:
            env = self.sidecar.get_envelope(self.tenant_id, rec.record_id)
        except SidecarUnavailable:
            # Degraded mode: drop untrusted tiers, admit SYSTEM/FIRST_PARTY whose
            # envelopes are locally cached (design §7).
            registry.incr("memwarden.read.degraded")
            cached = self._env_cache.get(rec.record_id)
            if cached is None or cached.trust_tier < TrustTier.FIRST_PARTY:
                return self._drop(rec, "degraded")
            if cached.expired(now):
                return self._drop(rec, "ttl")
            if self.policy.verify_integrity and not cached.verify_integrity(rec.content):
                return self._drop(rec, "integrity")
            return True

        # Envelope-miss: inadmissible below FIRST_PARTY — covers the
        # stream-reconciliation race. With no envelope the tier is unknown,
        # which is below FIRST_PARTY by definition: fail closed.
        if env is None:
            return self._drop(rec, "envelope_miss")

        try:
            # Gate 1: quarantine lookup. CLEARED overrides an inline quarantine;
            # FAILED is terminal.
            if env.quarantined and self.policy.drop_quarantined:
                if self._cleared(rec, env) is not True:
                    return self._drop(rec, "quarantine")

            # Gate 2: TTL filter.
            if env.expired(now):
                return self._drop(rec, "ttl")

            # Gate 3: integrity re-hash.
            if self.policy.verify_integrity and not env.verify_integrity(rec.content):
                return self._drop(rec, "integrity")

            # Gate 4: trust-tier admission. Below the policy floor requires a
            # CLEARED deep-scan verdict for the current digest.
            if env.trust_tier < min_tier:
                if self._cleared(rec, env) is not True:
                    return self._drop(rec, "trust_gate")
        except SidecarUnavailable:
            registry.incr("memwarden.read.degraded")
            if env.trust_tier >= TrustTier.FIRST_PARTY and not env.expired(now) \
                    and env.verify_integrity(rec.content) and not env.quarantined:
                return True
            return self._drop(rec, "degraded")

        return True

    # ---------------------------------------------------------------- erasure
    def erase_subject(self, actor_id: str) -> ErasureResult:
        """GDPR Article 17 erasure across both tiers (paper Alg. 1, design §9)."""
        held: list[str] = []
        deletable: dict[str, list[str]] = {}
        for rid, env in self.sidecar.envelopes_by_actor(self.tenant_id, actor_id):
            if env.legal_hold:
                held.append(rid)
            else:
                deletable.setdefault(env.namespace, []).append(rid)

        records_deleted = 0
        for ns, rids in deletable.items():
            for i in range(0, len(rids), 100):
                chunk = rids[i:i + 100]
                records_deleted += self.backend.batch_delete(ns, chunk)
            for rid in rids:
                self.sidecar.delete_envelope(self.tenant_id, rid)
                self.sidecar.delete_verdict(self.tenant_id, rid)
                self._env_cache.pop(rid, None)

        events_deleted = 0
        if hasattr(self.backend, "delete_actor_events"):
            events_deleted = self.backend.delete_actor_events(actor_id)

        cert_body = {
            "cert_id": uuid.uuid4().hex,
            "tenant_id": self.tenant_id,
            "actor_hash": signing.actor_hash(actor_id),
            "records_deleted": records_deleted,
            "events_deleted": events_deleted,
            "holds_retained": len(held),
            "ts": self.clock(),
        }
        entry = self.sidecar.audit_append(
            self.tenant_id, "ERASURE_CERT", record_id=cert_body["cert_id"],
            actor_id=actor_id, detail={k: v for k, v in cert_body.items()
                                       if k not in ("tenant_id",)})
        cert_body["chain_seq"] = entry.seq
        cert = dict(cert_body)
        cert["signature"] = self.signer.sign(cert_body)
        self.sidecar.put_certificate(self.tenant_id, cert)
        registry.incr("memwarden.erasure.certificates")
        return ErasureResult(records_deleted, events_deleted, len(held), cert,
                             conflicts=held)

    def verify_certificate(self, cert: dict) -> bool:
        body = {k: v for k, v in cert.items() if k != "signature"}
        return self.signer.verify(body, cert["signature"])
