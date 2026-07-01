"""
quality.py
==========
Implements automated quality gating for generated requirements:
  * exact duplicate rejection (hash-based)
  * near-duplicate rejection (token Jaccard similarity above threshold)
  * minimum/maximum length checks
  * "must mention a protocol/service/security action" checks
  * basic grammar sanity checks (no leftover template artifacts such as
    unresolved "{" placeholders, doubled spaces, doubled punctuation)
  * repetitive-wording checks (rejects a candidate if its template_id has
    already been used too many times relative to the rest of the corpus,
    encouraging template diversity across the full run)

This module is deliberately separated from grammar.py so the quality
bar can be tuned/extended (e.g. swapped for a perplexity-based filter)
without touching the generation logic itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from config import GeneratorConfig
from metadata import FirewallRequirement


_ACTION_WORD_PATTERN = re.compile(
    r"\b(allow|permit|enable|grant|authorize|whitelist|deny|block|restrict|"
    r"prohibit|disable|revoke|prevent|quarantine|drop|isolate|segment)\w*\b",
    re.IGNORECASE,
)
_PROTOCOL_PATTERN = re.compile(
    r"\b(TCP|UDP|ICMP|GRE|ESP|AH|SCTP|HTTP|HTTPS|SSH|FTP|SFTP|SMTP|DNS|"
    r"RDP|VNC|SMB|NFS|MQTT|Modbus|OPC|BACnet|DICOM|HL7|LDAP|VPN|IPsec)\w*\b",
    re.IGNORECASE,
)


@dataclass
class ValidationResult:
    accepted: bool
    reason: Optional[str] = None


def _tokenize(text: str) -> set:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union else 0.0


class QualityGate:
    """
    Stateful validator: holds the running set of accepted exact-text
    hashes, token sets (for near-duplicate detection), and per-template
    usage counters so it can reject overrepresented template structures
    as the corpus grows.
    """

    def __init__(self, config: GeneratorConfig, target_count: int):
        self.config = config
        self.target_count = target_count
        self._seen_text: set = set()
        self._seen_token_sets: list = []
        self._template_counts: dict = {}
        # Soft cap: no single template should account for more than this
        # fraction of the final corpus, to guarantee structural variety.
        self._max_template_share = 0.012  # 1.2% per template skeleton

    def _max_per_template(self) -> int:
        return max(3, int(self.target_count * self._max_template_share))

    def validate(self, requirement: FirewallRequirement) -> ValidationResult:
        text = requirement.generated_requirement

        # 1. Unresolved placeholder artifacts ("{something}" left in text)
        if "{" in text or "}" in text:
            return ValidationResult(False, "unresolved_placeholder")

        # 2. Length checks
        if len(text) < self.config.min_sentence_length:
            return ValidationResult(False, "too_short")
        if len(text) > self.config.max_sentence_length:
            return ValidationResult(False, "too_long")

        # 3. Exact duplicate
        normalized = re.sub(r"\s+", " ", text.strip().lower())
        if normalized in self._seen_text:
            return ValidationResult(False, "exact_duplicate")

        # 4. Near-duplicate via Jaccard similarity over token sets
        tokens = _tokenize(text)
        for other in self._seen_token_sets[-400:]:  # bounded sliding window
            if _jaccard(tokens, other) >= self.config.near_duplicate_jaccard_threshold:
                return ValidationResult(False, "near_duplicate")

        # 5. Must reference a protocol/service indicator somewhere
        if not _PROTOCOL_PATTERN.search(text) and requirement.protocol is None:
            return ValidationResult(False, "missing_protocol_or_service")

        # 6. Must contain a recognizable security action verb
        if not _ACTION_WORD_PATTERN.search(text):
            return ValidationResult(False, "missing_security_action")

        # 7. Doubled punctuation / spacing artifacts (grammar sanity)
        if re.search(r"([.,])\1", text) or "  " in text:
            return ValidationResult(False, "punctuation_artifact")

        # 8. Template overrepresentation guard
        count = self._template_counts.get(requirement.template_id, 0)
        if count >= self._max_per_template():
            return ValidationResult(False, "template_overrepresented")

        return ValidationResult(True, None)

    def commit(self, requirement: FirewallRequirement) -> None:
        """Registers an accepted requirement so future candidates are
        checked against it for duplication/overrepresentation."""
        text = requirement.generated_requirement
        normalized = re.sub(r"\s+", " ", text.strip().lower())
        self._seen_text.add(normalized)
        self._seen_token_sets.append(_tokenize(text))
        self._template_counts[requirement.template_id] = (
            self._template_counts.get(requirement.template_id, 0) + 1
        )

    def uniqueness_ratio(self, total_accepted: int, total_attempts: int) -> float:
        if total_attempts == 0:
            return 0.0
        return round(total_accepted / total_attempts, 6)
