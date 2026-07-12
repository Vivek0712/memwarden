"""Memwarden error taxonomy (design doc §5.2)."""


class MemwardenError(Exception):
    pass


class WriteRejected(MemwardenError):
    """L1 score >= reject threshold; nothing persisted."""

    def __init__(self, l1_score: float, families: list[str]):
        self.l1_score = l1_score
        self.families = families
        super().__init__(f"write rejected: l1_score={l1_score:.2f} families={families}")


class TenantViolation(MemwardenError):
    pass


class PolicyError(MemwardenError):
    pass


class BackendUnavailable(MemwardenError):
    """Fails closed on read; fails the write on write."""


class SidecarUnavailable(MemwardenError):
    """Fails closed on read; fails the write on write."""
