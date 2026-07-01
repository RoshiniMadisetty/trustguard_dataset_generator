"""
config.py
=========
Central configuration for the TrustGuard Synthetic Enterprise Firewall
Policy Requirement Generator.

All tunable parameters (target dataset size, quality thresholds, random
seed, output paths) live here so the rest of the codebase never hardcodes
magic numbers. This keeps the generator reproducible (fixed seed) and
trivially scalable from 10,000 to 100,000 requirements by changing a
single CLI parameter, which overrides TARGET_COUNT at runtime.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Path configuration
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")


@dataclass(frozen=True)
class GeneratorConfig:
    """
    Immutable configuration object passed through the generation pipeline.

    Attributes:
        target_count: Number of unique, validated requirements to produce.
        random_seed: Seed for the global RNG, guaranteeing reproducibility
            of a given run (same seed + same target_count => same dataset).
        min_sentence_length: Minimum character length for an accepted
            requirement (rejects degenerate/too-short outputs).
        max_sentence_length: Soft cap to avoid runaway nested-condition
            sentences that would read as unnatural.
        max_generation_attempts: Hard ceiling on total generation attempts
            before the generator aborts with a diagnostic error (guards
            against infinite loops if entity/template space is exhausted).
        difficulty_distribution: Target proportion of Easy/Medium/Hard/
            Expert items in the final corpus. Values must sum to 1.0.
        oversampling_factor: Internal candidate pool is generated at
            target_count * oversampling_factor before quality filtering,
            since a portion of raw candidates will be rejected or be
            duplicates.
    """

    target_count: int = 10_000
    random_seed: int = 42
    min_sentence_length: int = 45
    max_sentence_length: int = 420
    max_generation_attempts: int = 2_000_000
    difficulty_distribution: dict = field(
        default_factory=lambda: {
            "Easy": 0.25,
            "Medium": 0.35,
            "Hard": 0.25,
            "Expert": 0.15,
        }
    )
    oversampling_factor: float = 1.35

    # Near-duplicate detection: two requirements whose normalized token
    # Jaccard similarity exceeds this threshold are treated as duplicates
    # even if not byte-identical (catches template-echo repetition).
    near_duplicate_jaccard_threshold: float = 0.92

    def output_paths(self) -> dict:
        return {
            "requirements_json": os.path.join(OUTPUT_DIR, "requirements.json"),
            "requirements_csv": os.path.join(OUTPUT_DIR, "requirements.csv"),
            "requirements_xlsx": os.path.join(OUTPUT_DIR, "requirements.xlsx"),
            "metadata_json": os.path.join(OUTPUT_DIR, "requirements_metadata.json"),
            "statistics_json": os.path.join(OUTPUT_DIR, "generation_statistics.json"),
        }


DEFAULT_CONFIG = GeneratorConfig()
