"""L1 deterministic poisoning detection (paper §5.2, design §6).

Seven pattern families derived from the documented attack classes, plus two
structural detectors (invisible/bidirectional Unicode; high-entropy base64 runs).
All patterns compile once at import; scan() is a single pass. L1 is a precision
instrument for the documented classes, not a general classifier: novel phrasings
are expected to pass and are covered by the trust gate + out-of-band L2.

Score semantics (design §6): >= 0.9 rejects the write outright; [0.5, 0.9)
persists quarantined and invisible to agents until L2 clears it. Untrusted
provenance amplifies any suspicious score, so the same sentence is treated more
harshly from a web fetch than from a direct user turn.
"""

from __future__ import annotations

import base64
import math
import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Pattern families. Each entry: (family, compiled_pattern, base_score)
# --------------------------------------------------------------------------

_F = re.IGNORECASE

_FAMILIES: list[tuple[str, re.Pattern, float]] = [
    # 1. Instruction override: the classic "ignore all previous instructions".
    ("instruction_override",
     re.compile(r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|earlier|above|all)\b[^.\n]{0,30}\b(instructions?|rules?|directives?|context|polic(?:y|ies)|prompts?)\b", _F),
     0.80),
    # 2. Memory imperatives: the recommendation-poisoning class,
    #    "remember that X is the best choice".
    ("memory_imperative",
     re.compile(r"\b(remember|recall|note|store|save)\b[^.\n]{0,80}\b(best|top|preferred|default|first|only)\b[^.\n]{0,40}\b(choice|option|pick|vendor|tool|provider|product|recommendation|answer|solution)\b", _F),
     0.60),
    # 3. Role hijack, including template-token smuggling.
    ("role_hijack",
     re.compile(r"(\byou\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|jailbroken|uncensored|dan\b|operating\s+as|acting\s+as)|\bact\s+as\s+(?:a\s+)?(?:new\s+)?(?:system|admin|root|developer)\b|\bnew\s+persona\b|<\|im_start\|>|\[/?INST\]|<<SYS>>|###\s*(?:system|instruction)\b)", _F),
     0.80),
    # 4. Exfiltration directives: move conversation data to an external sink.
    ("exfiltration",
     re.compile(r"\b(forward|send|copy|relay|upload|transmit)\b[^.\n]{0,60}\b(conversations?|transcripts?|chat|history|messages?|logs?)\b[^.\n]{0,60}(https?://|\burl\b|@|\.com\b|\bcollector\b|\bexternal\s+(?:server|endpoint|address)\b)", _F),
     0.85),
    # 5. Financial rerouting: the invoice scenario.
    ("financial_reroute",
     re.compile(r"\b(reroute|redirect|wire|transfer|route|send)\b[^.\n]{0,60}\b(payments?|invoices?|funds|payouts?|remittances?)\b[^.\n]{0,60}\b(account|wallet|iban)\b", _F),
     0.85),
    # 6. Promotional bias: standing directives to favor a product.
    ("promotional_bias",
     re.compile(r"(\balways\s+(?:recommend|suggest|mention|surface|prefer)\b|\b(?:is|as)\s+the\s+(?:best|number\s+one)\s+(?:choice|option|pick|product|vendor|tool)\b)", _F),
     0.55),
    # 7. Secret leakage: directives to reveal protected configuration.
    ("secret_leakage",
     re.compile(r"\b(reveal|show|print|display|leak|expose|output)\b[^.\n]{0,40}\b(system\s+prompt|developer\s+message|api\s+keys?|passwords?|credentials|secret\s+keys?)\b", _F),
     0.80),
]

# Structural detector 1: invisible and bidirectional Unicode. No legitimate
# reason to appear in memory content; blocks outright (paper §5.2).
_INVISIBLE = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff\u00ad\u200e\u200f"  # zero-width, BOM, soft hyphen, LRM/RLM
    "\u202a-\u202e\u2066-\u2069"                             # bidi embedding/isolate controls
    "\U000e0000-\U000e007f]"                                   # Unicode tag block (tag smuggling)
)

# C-speed substring prefilters: a family's regex runs only when one of its
# trigger keywords is present (keyword presence is implied by every regex
# match, so semantics are unchanged; this keeps the 128-token scan linear
# and under the paper's per-scan budget).
_PREFILTERS: dict[str, tuple[str, ...]] = {
    "instruction_override": ("ignore", "disregard", "forget", "override"),
    "memory_imperative": ("remember", "recall", "note", "store", "save"),
    "role_hijack": ("you are now", "act as", "new persona", "<|im_start|>",
                    "[inst]", "<<sys>>", "###"),
    "exfiltration": ("forward", "send", "copy", "relay", "upload", "transmit"),
    "financial_reroute": ("reroute", "redirect", "wire", "transfer", "route", "send"),
    "promotional_bias": ("always", "the best", "the number one"),
    "secret_leakage": ("reveal", "show", "print", "display", "leak", "expose", "output"),
}

# Structural detector 2: high-entropy base64 runs (hidden payloads).
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{48,}={0,2}")

_UNTRUSTED_AMPLIFICATION = 0.15


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class ScanResult:
    score: float
    families: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return self.score >= 0.5


def scan(content: str, source_untrusted: bool = False) -> ScanResult:
    """Single pass over precompiled patterns. ~tens of microseconds."""
    families: list[str] = []
    score = 0.0

    # Every invisible/bidi codepoint is non-ASCII, so ASCII content skips the
    # class scan entirely (isascii is a C-speed single pass).
    if not content.isascii() and _INVISIBLE.search(content):
        # Blocks outright regardless of provenance.
        return ScanResult(score=1.0, families=["invisible_unicode"])

    lowered = content.lower()
    for family, pattern, base in _FAMILIES:
        keywords = _PREFILTERS[family]
        if not any(k in lowered for k in keywords):
            continue
        if pattern.search(content):
            families.append(family)
            score = max(score, base)

    # A 48-char base64 run implies a whitespace-free token of at least 48
    # chars, so the token-length check soundly gates the regex.
    b64_candidates = (_B64_RUN.findall(content)
                      if len(content) >= 48 and any(len(t) >= 48 for t in content.split())
                      else ())
    for run in b64_candidates:
        if _shannon_entropy(run) >= 4.5:
            try:
                base64.b64decode(run + "=" * (-len(run) % 4))
            except Exception:
                continue
            families.append("high_entropy_base64")
            score = max(score, 0.55)
            break

    if score > 0.0:
        if len(families) > 1:
            score = min(1.0, score + 0.05 * (len(families) - 1))
        if source_untrusted:
            score = min(1.0, score + _UNTRUSTED_AMPLIFICATION)

    return ScanResult(score=score, families=families)
