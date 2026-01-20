#!/usr/bin/env python3
"""
generate_scorecard.py

Creates a structured investor/compliance scorecard JSON for QSE vs System.

Usage:
  python3 generate_scorecard.py \
    --qse sts-results/qse/report.json \
    --system sts-results/system/report.json \
    --comparison sts-results/comparison.json \
    --out sts-results/scorecard.json
"""

import argparse
import json
import os
from datetime import datetime
from typing import Dict, Any


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def headline_verdict(qse: Dict[str, Any], sys: Dict[str, Any], comparison: Dict[str, Any]) -> str:
    if qse["summary"]["overall_pass"] and sys["summary"]["overall_pass"]:
        if comparison["overall"]["winner"] == "qse":
            return "Both sources pass NIST STS; QSE shows slightly stronger margins across tests."
        elif comparison["overall"]["winner"] == "system":
            return "Both sources pass NIST STS; system entropy shows slightly stronger margins across tests."
        return "Both sources pass NIST STS; performance is broadly comparable."
    if qse["summary"]["overall_pass"]:
        return "QSE entropy passes NIST STS while system entropy did not meet all thresholds."
    if sys["summary"]["overall_pass"]:
        return "System entropy passes NIST STS while QSE entropy did not meet all thresholds."
    return "Neither source met all NIST STS thresholds under this run configuration."


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate investor/compliance scorecard JSON.")
    parser.add_argument("--qse", required=True, help="QSE report.json")
    parser.add_argument("--system", required=True, help="System report.json")
    parser.add_argument("--comparison", required=True, help="comparison.json")
    parser.add_argument("--out", required=True, help="Output scorecard.json path")
    args = parser.parse_args()

    qse = load_json(args.qse)
    sys = load_json(args.system)
    comp = load_json(args.comparison)

    scorecard = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "config": {
            "alpha": 0.01,
            "sequences": 100,
            "sequence_length_bits": 1_000_000,
            "input_mode": "binary",
        },
        "headline_verdict": headline_verdict(qse, sys, comp),
        "overall": comp["overall"],
        "qse_summary": qse["summary"],
        "system_summary": sys["summary"],
        "qse_weakest_test": qse["weakest_test"],
        "system_weakest_test": sys["weakest_test"],
        "qse_lowest_uniformity_test": qse["lowest_uniformity_test"],
        "system_lowest_uniformity_test": sys["lowest_uniformity_test"],
        "qse_borderline_tests": qse["borderline_tests"],
        "system_borderline_tests": sys["borderline_tests"],
        "wins_by_test": comp["overall"]["win_counts"],
        "comparisons": comp["comparisons"],
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(scorecard, f, indent=2)

    print("✅ Scorecard generated.")
    print(f"Saved: {args.out}")
    print(f"Headline: {scorecard['headline_verdict']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())