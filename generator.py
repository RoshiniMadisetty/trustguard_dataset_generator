"""
generator.py
============
Orchestrates the end-to-end generation pipeline: draws candidate
requirements across categories (weighted to respect the configured
difficulty distribution), runs them through the QualityGate, and keeps
generating replacements until exactly `target_count` validated, unique
requirements have been produced -- or `max_generation_attempts` is
exceeded, in which case a diagnostic RuntimeError is raised.

This module contains no I/O (file writing); see exporter.py for that.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

from config import GeneratorConfig
from entities import EntityLibrary, load_entity_library
from grammar import generate_requirement, available_categories
from quality import QualityGate
from metadata import FirewallRequirement


@dataclass
class GenerationStatistics:
    target_count: int
    total_attempts: int = 0
    accepted_count: int = 0
    rejected_count: int = 0
    rejection_reasons: dict = field(default_factory=dict)
    difficulty_counts: dict = field(default_factory=dict)
    category_counts: dict = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    uniqueness_ratio: float = 0.0
    total_entities_loaded: int = 0
    total_base_templates: int = 0

    def to_dict(self) -> dict:
        return {
            "target_count": self.target_count,
            "total_attempts": self.total_attempts,
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
            "rejection_reasons": self.rejection_reasons,
            "difficulty_distribution": self.difficulty_counts,
            "category_distribution": self.category_counts,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "uniqueness_ratio": self.uniqueness_ratio,
            "total_entities_loaded": self.total_entities_loaded,
            "total_base_templates": self.total_base_templates,
        }


def _weighted_category_cycle(lib: EntityLibrary, rng: random.Random):
    """
    Yields an endless, shuffled-per-cycle sequence of category names so
    that every category gets roughly equal representation over the full
    run (while still being randomized within each cycle to avoid
    positional patterns in the corpus).
    """
    categories = available_categories(lib)
    while True:
        shuffled = categories[:]
        rng.shuffle(shuffled)
        for cat in shuffled:
            yield cat


def generate_dataset(
    config: GeneratorConfig,
    target_count: int | None = None,
) -> tuple[list[FirewallRequirement], GenerationStatistics]:
    """
    Main entry point. Returns (requirements, statistics).
    """
    target_count = target_count or config.target_count
    rng = random.Random(config.random_seed)
    lib = load_entity_library()
    gate = QualityGate(config, target_count)

    stats = GenerationStatistics(
        target_count=target_count,
        total_entities_loaded=lib.total_entity_count(),
        total_base_templates=lib.total_template_count(),
    )

    accepted: list[FirewallRequirement] = []
    category_cycle = _weighted_category_cycle(lib, rng)

    start = time.time()
    attempts = 0
    next_id = 1

    while len(accepted) < target_count:
        if attempts >= config.max_generation_attempts:
            raise RuntimeError(
                f"Exceeded max_generation_attempts ({config.max_generation_attempts}) "
                f"while only producing {len(accepted)}/{target_count} unique requirements. "
                f"Consider expanding entity/template diversity or relaxing the near-duplicate "
                f"threshold."
            )
        attempts += 1
        category = next(category_cycle)
        req_id = f"TG-{next_id:06d}"

        try:
            candidate = generate_requirement(req_id, category, lib, rng)
        except Exception:
            stats.rejected_count += 1
            stats.rejection_reasons["generation_exception"] = (
                stats.rejection_reasons.get("generation_exception", 0) + 1
            )
            continue

        result = gate.validate(candidate)
        if not result.accepted:
            stats.rejected_count += 1
            stats.rejection_reasons[result.reason] = (
                stats.rejection_reasons.get(result.reason, 0) + 1
            )
            continue

        gate.commit(candidate)
        accepted.append(candidate)
        next_id += 1

        stats.difficulty_counts[candidate.difficulty] = (
            stats.difficulty_counts.get(candidate.difficulty, 0) + 1
        )
        stats.category_counts[candidate.category] = (
            stats.category_counts.get(candidate.category, 0) + 1
        )

    stats.total_attempts = attempts
    stats.accepted_count = len(accepted)
    stats.elapsed_seconds = time.time() - start
    stats.uniqueness_ratio = gate.uniqueness_ratio(len(accepted), attempts)

    return accepted, stats
