# Contributing to Memwarden

Thanks for helping govern agent memory. This repo is the **open-source Memwarden SDK**
(Apache-2.0). The managed control plane (Memwarden Cloud) is developed separately.

## Scope of this repo

In scope: the seven-operation backend protocol, the `GovernedMemory` interceptor,
the L1 detector, the policy engine, envelopes, the audit chain and `memwarden-verify`,
the verdict-stream cache, backend adapters, and the self-host sidecar. Out of
scope here: the hosted multi-tenant control plane, dashboards, and IaC.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,all]"
pytest -q                 # must stay green
python eval/heldout_eval.py
```

## The two hard rules

1. **Adapters own transport only.** No policy, detection, audit, or erasure logic
   goes in a backend adapter. A backend passes `tests/test_conformance.py` or it
   does not ship.
2. **Detection changes must not regress the held-out gate.** `tests/test_heldout_gate.py`
   and `tests/test_detection.py` are regression gates: in-distribution precision
   and recall stay 1.00, benign near-misses never flag, and held-out recall stays
   within the paper's measured envelope. L1 is a precision instrument for
   documented classes — do not broaden patterns to chase held-out recall; that is
   the L2/trust-gate's job.

## Adding a backend adapter

Implement `memwarden.backends.base.MemoryBackend` (seven methods), add it to the
conformance suite parametrization, and document its batch limits and consistency
model. Open a PR with the conformance run in the description.

## PRs

- One logical change per PR; keep the diff readable.
- New behavior needs a test keyed to the failure mode or protocol op it affects.
- Sign your commits off (`git commit -s`); contributions are under Apache-2.0.
