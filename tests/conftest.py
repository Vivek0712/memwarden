import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engram.backends.inmemory import InMemoryBackend
from engram.governed import GovernedMemory
from engram.policy import Policy
from engram.sidecar.local import LocalSidecar

POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "policies", "policy.yaml")


class FakeClock:
    def __init__(self, t0: float = 1_800_000_000.0):
        self.t = t0

    def __call__(self) -> float:
        return self.t

    def advance_days(self, days: float) -> None:
        self.t += days * 86400


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def policy():
    return Policy.load(POLICY_PATH)


@pytest.fixture
def backend():
    return InMemoryBackend()


@pytest.fixture
def sidecar():
    return LocalSidecar()


@pytest.fixture
def memory(backend, sidecar, policy, clock):
    return GovernedMemory(backend=backend, tenant_id="acme", policy=policy,
                          sidecar=sidecar, clock=clock)


NS = "tenants/acme/notes/alice"
