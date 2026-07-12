"""Policy engine: YAML, versioned, schema-validated at load (design §13).

First matching glob on `channel:namespace` wins. A policy that fails validation
never loads; the previous version stays active (caller keeps the old object).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Optional

import jsonschema
import yaml

from .errors import PolicyError

_SCHEMA = {
    "type": "object",
    "required": ["version", "retention_classes", "retention_rules", "read_admission"],
    "properties": {
        "version": {"type": "string"},
        "retention_classes": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "required": ["ttl_days"],
                "properties": {
                    "ttl_days": {"type": "number", "minimum": 0},
                    "legal_hold_eligible": {"type": "boolean"},
                },
            },
        },
        "retention_rules": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["match", "class"],
                "properties": {"match": {"type": "string"}, "class": {"type": "string"}},
            },
        },
        "read_admission": {
            "type": "object",
            "properties": {
                "min_trust_tier_without_deep_scan": {"type": "integer", "minimum": 0, "maximum": 3},
                "drop_quarantined": {"type": "boolean"},
                "verify_integrity": {"type": "boolean"},
            },
        },
        "l2": {
            "type": "object",
            "properties": {
                "scan_tiers": {"type": "array", "items": {"type": "integer"}},
                "guardrail_id": {"type": "string"},
                "guardrail_version": {"type": "string"},
                "strength": {"type": "string"},
            },
        },
    },
}


@dataclass(frozen=True)
class RetentionClass:
    name: str
    ttl_days: float
    legal_hold_eligible: bool = False


class Policy:
    def __init__(self, doc: dict):
        try:
            jsonschema.validate(doc, _SCHEMA)
        except jsonschema.ValidationError as e:
            raise PolicyError(f"policy failed schema validation: {e.message}") from e
        self.version: str = doc["version"]
        self.retention_classes: dict[str, RetentionClass] = {
            name: RetentionClass(name=name, ttl_days=spec["ttl_days"],
                                 legal_hold_eligible=spec.get("legal_hold_eligible", False))
            for name, spec in doc["retention_classes"].items()
        }
        self.retention_rules: list[tuple[str, str]] = [
            (r["match"], r["class"]) for r in doc["retention_rules"]
        ]
        for _, cls in self.retention_rules:
            if cls not in self.retention_classes:
                raise PolicyError(f"retention rule references unknown class {cls!r}")
        ra = doc["read_admission"]
        self.min_trust_tier_without_deep_scan: int = ra.get("min_trust_tier_without_deep_scan", 2)
        self.drop_quarantined: bool = ra.get("drop_quarantined", True)
        self.verify_integrity: bool = ra.get("verify_integrity", True)
        l2 = doc.get("l2", {})
        self.l2_scan_tiers: list[int] = l2.get("scan_tiers", [0, 1])
        self.l2_guardrail_id: Optional[str] = l2.get("guardrail_id")
        self.l2_guardrail_version: str = l2.get("guardrail_version", "DRAFT")

    @classmethod
    def load(cls, path: str) -> "Policy":
        with open(path, "r", encoding="utf-8") as f:
            return cls(yaml.safe_load(f))

    def resolve_retention(self, channel: str, namespace: str) -> RetentionClass:
        """First matching glob on channel:namespace wins."""
        key = f"{channel}:{namespace}"
        for pattern, cls in self.retention_rules:
            if fnmatch.fnmatchcase(key, pattern):
                return self.retention_classes[cls]
        raise PolicyError(f"no retention rule matches {key!r}")
