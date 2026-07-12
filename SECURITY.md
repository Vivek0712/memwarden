# Security Policy

Memwarden is a security component. We take vulnerabilities seriously.

## Reporting

Email **vivekrajaps.offl@gmail.com** with a description, reproduction, and impact.
Do not open public issues for vulnerabilities. We acknowledge within 3 business
days and aim to ship a fix or mitigation within 30 days, coordinating disclosure
with you.

## Scope

In scope: bypasses of the tenant check, read-gate, trust-gate, or erasure logic;
audit-chain forgery; L1 false-negative classes that reach agent context without
being caught by the trust gate; policy-engine parsing issues.

Out of scope: L1 recall on novel out-of-distribution attacks (by design, L1 is a
precision instrument; the trust gate carries the guarantee — see the paper §6.5).
Report a *bypass of the trust gate*, not a missed detection.

## Supported versions

The latest minor release receives security fixes. Pin `memwarden>=x.y,<x.(y+1)`.
