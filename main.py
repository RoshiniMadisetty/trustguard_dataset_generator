"""
main.py
=======
Command-line entry point for the TrustGuard synthetic enterprise
firewall requirement corpus generator.

Usage:
    python3 main.py --count 10000
    python3 main.py --count 100000 --seed 7

The generator is capable of producing anywhere from 10,000 to 100,000+
unique requirements by changing only --count; everything else
(entity libraries, templates, quality thresholds) scales automatically.
"""

from __future__ import annotations

import argparse
import sys
import time

from config import GeneratorConfig, DEFAULT_CONFIG
from generator import generate_dataset
from exporter import export_all


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the TrustGuard synthetic enterprise firewall "
                    "requirement corpus."
    )
    parser.add_argument(
        "--count", type=int, default=DEFAULT_CONFIG.target_count,
        help="Number of unique, validated requirements to generate "
             "(default: 10000). Tested range: 10,000 - 100,000.",
    )
    parser.add_argument(
        "--seed", type=int, default=DEFAULT_CONFIG.random_seed,
        help="Random seed for full reproducibility (default: 42).",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    config = GeneratorConfig(
        target_count=args.count,
        random_seed=args.seed,
    )

    print(f"[TrustGuard] Generating {config.target_count:,} unique enterprise "
          f"firewall requirements (seed={config.random_seed})...")
    t0 = time.time()

    try:
        requirements, stats = generate_dataset(config, target_count=config.target_count)
    except RuntimeError as exc:
        print(f"[TrustGuard] FATAL: {exc}", file=sys.stderr)
        return 1

    print(f"[TrustGuard] Generated {len(requirements):,} requirements in "
          f"{time.time() - t0:.1f}s ({stats.total_attempts:,} attempts, "
          f"uniqueness ratio={stats.uniqueness_ratio:.4f}).")

    paths = export_all(requirements, stats, config)
    print("[TrustGuard] Exported files:")
    for name, path in paths.items():
        print(f"  - {name}: {path}")

    print("[TrustGuard] Difficulty distribution:")
    for level in ("Easy", "Medium", "Hard", "Expert"):
        n = stats.difficulty_counts.get(level, 0)
        pct = (n / len(requirements) * 100) if requirements else 0
        print(f"    {level:8s}: {n:6,d}  ({pct:5.1f}%)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
