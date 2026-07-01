"""
metadata.py
===========
Defines the FirewallRequirement dataclass: the canonical internal record
produced for every generated item. Only the `generated_requirement`
field is exported to requirements.json for Ollama consumption; the full
record (with id, category, difficulty, scores, entities, etc.) is
exported separately to requirements_metadata.json for downstream
TrustGuard validation, SHAP/LIME explainability correlation, and result
analysis in the IEEE paper.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class FirewallRequirement:
    id: str
    category: str
    subcategory: str
    difficulty: str
    template_id: str

    generated_requirement: str

    service: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None

    source_zone: Optional[str] = None
    destination_zone: Optional[str] = None
    source_host: Optional[str] = None
    destination_host: Optional[str] = None
    source_cidr: Optional[str] = None
    destination_cidr: Optional[str] = None

    department: Optional[str] = None
    application: Optional[str] = None
    vendor: Optional[str] = None
    compliance: Optional[str] = None
    authentication: Optional[str] = None

    action: Optional[str] = None  # "allow" or "deny"
    internet_exposed: bool = False

    num_conditions: int = 0
    num_exceptions: int = 0
    has_nested_logic: bool = False
    has_contradiction: bool = False
    has_ambiguity: bool = False

    ambiguity_score: float = 0.0
    complexity_score: float = 0.0

    entities: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
