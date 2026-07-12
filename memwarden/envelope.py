"""Governance envelope: the unit of governance metadata (paper Listing 1, design §4.1)."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Optional


class TrustTier(IntEnum):
    UNTRUSTED = 0    # web, tool output, inbound email, third-party doc, A2A
    DERIVED = 1      # LLM-extracted long-term records (hallucination risk)
    FIRST_PARTY = 2  # verbatim user / agent turns
    SYSTEM = 3       # operator-seeded policies and canonical facts


# Trust tiers are assigned from the source channel (paper §5.1).
CHANNEL_TIERS: dict[str, TrustTier] = {
    "web_fetch": TrustTier.UNTRUSTED,
    "tool_output": TrustTier.UNTRUSTED,
    "inbound_email": TrustTier.UNTRUSTED,
    "third_party_doc": TrustTier.UNTRUSTED,
    "a2a": TrustTier.UNTRUSTED,
    "extraction": TrustTier.DERIVED,
    "llm_extraction": TrustTier.DERIVED,
    "user_turn": TrustTier.FIRST_PARTY,
    "agent_turn": TrustTier.FIRST_PARTY,
    "operator": TrustTier.SYSTEM,
    "system_seed": TrustTier.SYSTEM,
}


def tier_for_channel(channel: str) -> TrustTier:
    # Unknown channels are untrusted by default: fail-closed provenance.
    return CHANNEL_TIERS.get(channel, TrustTier.UNTRUSTED)


def sha256_hex(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass
class GovernanceEnvelope:
    envelope_id: str
    tenant_id: str
    actor_id: str
    namespace: str
    source_channel: str
    trust_tier: TrustTier
    content_sha256: str
    retention_class: str
    expires_at_epoch: Optional[float]
    created_at: float
    policy_version: str
    legal_hold: bool = False
    quarantined: bool = False

    @classmethod
    def stamp(cls, *, tenant_id: str, actor_id: str, namespace: str, channel: str,
              content: str, retention_class: str, expires_at_epoch: Optional[float],
              created_at: float, policy_version: str, quarantined: bool = False,
              trust_tier: Optional[TrustTier] = None) -> "GovernanceEnvelope":
        return cls(
            envelope_id=uuid.uuid4().hex,
            tenant_id=tenant_id,
            actor_id=actor_id,
            namespace=namespace,
            source_channel=channel,
            trust_tier=tier_for_channel(channel) if trust_tier is None else trust_tier,
            content_sha256=sha256_hex(content),
            retention_class=retention_class,
            expires_at_epoch=expires_at_epoch,
            created_at=created_at,
            policy_version=policy_version,
            quarantined=quarantined,
        )

    def verify_integrity(self, content: str) -> bool:
        return sha256_hex(content) == self.content_sha256

    def expired(self, now: float) -> bool:
        return self.expires_at_epoch is not None and now >= self.expires_at_epoch

    def to_item(self) -> dict:
        d = asdict(self)
        d["trust_tier"] = int(self.trust_tier)
        return d

    @classmethod
    def from_item(cls, d: dict) -> "GovernanceEnvelope":
        d = dict(d)
        d["trust_tier"] = TrustTier(int(d["trust_tier"]))
        return cls(**d)
