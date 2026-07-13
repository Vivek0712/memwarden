# Changelog

All notable changes to the Memwarden SDK are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] — unreleased (first public release)

### Added
- Seven-operation `MemoryBackend` protocol and the `GovernedMemory` interceptor
  (normative write/read paths, GDPR Article 17 `erase_subject`).
- L1 deterministic detector (7 pattern families + invisible-Unicode and
  high-entropy-base64 structural detectors) with provenance amplification.
- Policy engine (YAML + JSON Schema), per-category retention classes.
- Governance envelope, trust tiers, SHA-256 integrity, HMAC-signed certificates.
- Per-tenant hash-chained audit log, Merkle anchoring, and the `memwarden-verify` CLI.
- Verdict-stream cache (Bloom filter + LRU) that removes the sidecar hop on the
  common read.
- Backends: in-memory (reference), Amazon Bedrock AgentCore Memory, Redis (beta),
  pgvector (beta stub). Local + DynamoDB self-host sidecars.
- L2 scanner handler and Bedrock Guardrails client for self-hosted out-of-band scan.
- Failure-mode, conformance, detection, held-out-gate, and cache test suites;
  benchmark harness; the paper's held-out adversarial evaluation.
- `memwarden-lab`: a randomized scenario runner (simple → complex) that exercises
  the full governance flow and prints a metrics report card, with opt-in,
  content-free telemetry.
