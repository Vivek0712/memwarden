"""Memwarden: a governance layer for agentic memory.

Reference implementation accompanying the paper and the technical design.
"""

from .envelope import GovernanceEnvelope, TrustTier
from .errors import (BackendUnavailable, MemwardenError, PolicyError,
                     SidecarUnavailable, TenantViolation, WriteRejected)
from .governed import ErasureResult, GovernedMemory
from .policy import Policy

__all__ = [
    "GovernedMemory", "ErasureResult", "Policy", "GovernanceEnvelope", "TrustTier",
    "WriteRejected", "TenantViolation", "PolicyError", "BackendUnavailable",
    "SidecarUnavailable", "MemwardenError",
]
__version__ = "0.1.0"
