"""
difficulty.py
==============
Implements the difficulty / ambiguity / complexity scoring engine used to
label every generated requirement as Easy, Medium, Hard, or Expert.

The scoring model is intentionally simple and explainable (a weighted
linear combination of structural signals) because TrustGuard's research
goal is to correlate *requirement* difficulty with downstream *LLM
hallucination rate* -- an opaque scoring function would undermine that
analysis. Each signal below is something a human firewall engineer would
also recognize as making a change request harder to implement correctly.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DifficultySignals:
    num_conditions: int
    num_exceptions: int
    has_nested_logic: bool
    has_contradiction: bool
    has_ambiguity: bool
    is_compliance_scoped: bool
    is_security_sensitive_zone: bool  # OT/PCI/healthcare/tier-0 AD/etc.
    requires_multi_hop: bool
    category_baseline: float = 0.0


# Weights are calibrated so that:
#   0.0 - 0.25  -> Easy
#   0.25 - 0.50 -> Medium
#   0.50 - 0.75 -> Hard
#   0.75 - 1.00 -> Expert
_WEIGHTS = {
    "condition": 0.12,
    "exception": 0.11,
    "nested_logic": 0.22,
    "contradiction": 0.30,
    "ambiguity": 0.24,
    "compliance": 0.10,
    "sensitive_zone": 0.13,
    "multi_hop": 0.13,
}


def compute_complexity_score(signals: DifficultySignals) -> float:
    """Pure, deterministic complexity score in [0, 1] (clamped)."""
    score = 0.0
    score += signals.category_baseline
    score += min(signals.num_conditions, 4) * _WEIGHTS["condition"]
    score += min(signals.num_exceptions, 3) * _WEIGHTS["exception"]
    score += _WEIGHTS["nested_logic"] if signals.has_nested_logic else 0.0
    score += _WEIGHTS["contradiction"] if signals.has_contradiction else 0.0
    score += _WEIGHTS["ambiguity"] if signals.has_ambiguity else 0.0
    score += _WEIGHTS["compliance"] if signals.is_compliance_scoped else 0.0
    score += _WEIGHTS["sensitive_zone"] if signals.is_security_sensitive_zone else 0.0
    score += _WEIGHTS["multi_hop"] if signals.requires_multi_hop else 0.0
    return max(0.0, min(1.0, round(score, 4)))


def compute_ambiguity_score(signals: DifficultySignals) -> float:
    """
    A narrower score focused specifically on linguistic/requirement
    ambiguity (as opposed to overall structural complexity), used by
    TrustGuard's hallucination correlation analysis as an independent
    variable.
    """
    score = 0.0
    if signals.has_ambiguity:
        score += 0.55
    if signals.has_contradiction:
        score += 0.30
    score += min(signals.num_conditions, 3) * 0.04
    return max(0.0, min(1.0, round(score, 4)))


def classify_difficulty(complexity_score: float) -> str:
    if complexity_score < 0.25:
        return "Easy"
    if complexity_score < 0.50:
        return "Medium"
    if complexity_score < 0.75:
        return "Hard"
    return "Expert"
