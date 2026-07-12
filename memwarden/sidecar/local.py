"""Dict-backed sidecar: the library-topology default and the CI reference."""

from __future__ import annotations

from typing import Iterable, Optional

from ..audit import AuditChain, AuditEntry
from ..envelope import GovernanceEnvelope
from .base import Verdict


class LocalSidecar:
    def __init__(self):
        self._envelopes: dict[tuple[str, str], GovernanceEnvelope] = {}
        self._verdicts: dict[tuple[str, str], Verdict] = {}
        self._chains: dict[str, AuditChain] = {}
        self._certs: dict[str, list[dict]] = {}

    # -- envelopes ------------------------------------------------------------
    def put_envelope(self, env: GovernanceEnvelope) -> None:
        self._envelopes[(env.tenant_id, env.envelope_id)] = env

    def bind_record(self, env: GovernanceEnvelope, record_id: str) -> None:
        """Key the envelope by the backend record id once the write commits."""
        self._envelopes.pop((env.tenant_id, env.envelope_id), None)
        self._envelopes[(env.tenant_id, record_id)] = env

    def get_envelope(self, tenant_id: str, record_id: str) -> Optional[GovernanceEnvelope]:
        return self._envelopes.get((tenant_id, record_id))

    def delete_envelope(self, tenant_id: str, record_id: str) -> None:
        self._envelopes.pop((tenant_id, record_id), None)

    def envelopes_by_actor(self, tenant_id: str, actor_id: str) -> Iterable[tuple[str, GovernanceEnvelope]]:
        for (tid, rid), env in list(self._envelopes.items()):
            if tid == tenant_id and env.actor_id == actor_id:
                yield rid, env

    def expired_envelopes(self, tenant_id: str, now: float) -> Iterable[tuple[str, GovernanceEnvelope]]:
        for (tid, rid), env in list(self._envelopes.items()):
            if tid == tenant_id and env.expired(now):
                yield rid, env

    def set_legal_hold(self, tenant_id: str, record_id: str, hold: bool) -> None:
        env = self._envelopes[(tenant_id, record_id)]
        env.legal_hold = hold

    # -- verdicts ---------------------------------------------------------------
    def put_verdict(self, tenant_id: str, record_id: str, verdict: Verdict) -> None:
        self._verdicts[(tenant_id, record_id)] = verdict

    def get_verdict(self, tenant_id: str, record_id: str) -> Optional[Verdict]:
        return self._verdicts.get((tenant_id, record_id))

    def delete_verdict(self, tenant_id: str, record_id: str) -> None:
        self._verdicts.pop((tenant_id, record_id), None)

    # -- audit ---------------------------------------------------------------
    def _chain(self, tenant_id: str) -> AuditChain:
        if tenant_id not in self._chains:
            self._chains[tenant_id] = AuditChain(tenant_id)
        return self._chains[tenant_id]

    def audit_append(self, tenant_id: str, op: str, record_id: str = "",
                     actor_id: str = "", detail: Optional[dict] = None) -> AuditEntry:
        return self._chain(tenant_id).append(op, record_id, actor_id, detail)

    def audit_entries(self, tenant_id: str) -> list[AuditEntry]:
        return self._chain(tenant_id).entries()

    def chain_head(self, tenant_id: str) -> str:
        return self._chain(tenant_id).head()

    def tenants(self) -> list[str]:
        return list(self._chains)

    # -- certificates ----------------------------------------------------------
    def put_certificate(self, tenant_id: str, cert: dict) -> None:
        self._certs.setdefault(tenant_id, []).append(cert)

    def certificates(self, tenant_id: str) -> list[dict]:
        return list(self._certs.get(tenant_id, []))
