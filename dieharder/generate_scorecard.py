#!/usr/bin/env python3
"""
generate_scorecard.py

Creates a structured investor/compliance scorecard JSON for QSE vs System (Dieharder).

Usage:
  python3 generate_scorecard.py \
    --qse dieharder-results/qse/report.json \
    --system dieharder-results/system/report.json \
    --comparison dieharder-results/comparison.json \
    --out dieharder-results/scorecard.json
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
    """
    Generate headline verdict based on Dieharder assessment.
    Note: Dieharder is a strength assessment tool, not a binary pass/fail.
    It evaluates randomness strength through p-value distribution analysis.
    Some WEAK results are statistically expected with many tests.
    """
    qse_pass = qse["summary"]["overall_pass"]
    sys_pass = sys["summary"]["overall_pass"]
    qse_failed = qse["summary"]["failed_tests"]
    sys_failed = sys["summary"]["failed_tests"]
    qse_weak = qse["summary"]["weak_tests"]
    sys_weak = sys["summary"]["weak_tests"]
    
    if qse_pass and sys_pass:
        if comparison["overall"]["winner"] == "qse":
            return "Both sources demonstrate strong randomness in Dieharder tests; QSE shows slightly stronger performance across tests."
        elif comparison["overall"]["winner"] == "system":
            return "Both sources demonstrate strong randomness in Dieharder tests; system entropy shows slightly stronger performance across tests."
        return "Both sources demonstrate strong randomness in Dieharder tests; performance is broadly comparable."
    
    if qse_pass:
        if sys_failed > 0:
            return f"QSE entropy demonstrates strong randomness in Dieharder tests. System entropy shows {sys_failed} failed test(s), indicating potential weaknesses."
        else:
            return f"QSE entropy demonstrates strong randomness in Dieharder tests. System entropy shows {sys_weak} weak test(s), which may indicate statistical variation or minor concerns."
    
    if sys_pass:
        if qse_failed > 0:
            return f"System entropy demonstrates strong randomness in Dieharder tests. QSE entropy shows {qse_failed} failed test(s), indicating potential weaknesses."
        else:
            return f"System entropy demonstrates strong randomness in Dieharder tests. QSE entropy shows {qse_weak} weak test(s), which may indicate statistical variation or minor concerns."
    
    # Both have issues - determine winner based on failure counts
    winner = comparison["overall"]["winner"]
    if qse_failed > 0 or sys_failed > 0:
        if winner == "qse":
            return f"Both sources show concerns in Dieharder tests. QSE demonstrates stronger performance with {qse_failed} failed and {qse_weak} weak tests, compared to System's {sys_failed} failed and {sys_weak} weak tests. Failed tests (p < 0.0001 or p > 0.9999) indicate potential randomness weaknesses."
        elif winner == "system":
            return f"Both sources show concerns in Dieharder tests. System demonstrates stronger performance with {sys_failed} failed and {sys_weak} weak tests, compared to QSE's {qse_failed} failed and {qse_weak} weak tests. Failed tests (p < 0.0001 or p > 0.9999) indicate potential randomness weaknesses."
        else:
            return f"Both sources show similar concerns in Dieharder tests. QSE: {qse_failed} failed, {qse_weak} weak. System: {sys_failed} failed, {sys_weak} weak. Failed tests indicate potential randomness weaknesses."
    else:
        if winner == "qse":
            return f"Both sources show elevated weak test counts. QSE demonstrates stronger performance with {qse_weak} weak tests compared to System's {sys_weak} weak tests. This may indicate statistical variation or require further investigation."
        elif winner == "system":
            return f"Both sources show elevated weak test counts. System demonstrates stronger performance with {sys_weak} weak tests compared to QSE's {qse_weak} weak tests. This may indicate statistical variation or require further investigation."
        else:
            return f"Both sources show elevated weak test counts. QSE: {qse_weak} weak tests. System: {sys_weak} weak tests. This may indicate statistical variation or require further investigation with additional test runs."


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate investor/compliance scorecard JSON (Dieharder).")
    parser.add_argument("--qse", required=True, help="QSE report.json")
    parser.add_argument("--system", required=True, help="System report.json")
    parser.add_argument("--comparison", required=True, help="comparison.json")
    parser.add_argument("--out", required=True, help="Output scorecard.json path")
    parser.add_argument("--sequences", type=int, help="Number of sequences tested (default: 100)")
    parser.add_argument("--seq-length", type=int, help="Sequence length in bits (default: 1000000)")
    args = parser.parse_args()

    qse = load_json(args.qse)
    sys = load_json(args.system)
    comp = load_json(args.comparison)

    # Use provided values or defaults
    num_sequences = args.sequences if args.sequences is not None else 100
    seq_length = args.seq_length if args.seq_length is not None else 1_000_000

    scorecard = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "config": {
            "sequences": num_sequences,
            "sequence_length_bits": seq_length,
            "input_mode": "binary",
        },
        "headline_verdict": headline_verdict(qse, sys, comp),
        "overall": comp["overall"],
        "qse_summary": qse["summary"],
        "system_summary": sys["summary"],
        "qse_weakest_test": qse["weakest_test"],
        "system_weakest_test": sys["weakest_test"],
        "qse_lowest_p_value_test": qse["lowest_p_value_test"],
        "system_lowest_p_value_test": sys["lowest_p_value_test"],
        "qse_borderline_tests": qse["borderline_tests"],
        "system_borderline_tests": sys["borderline_tests"],
        "qse_suspect_tests": qse.get("suspect_tests", []),
        "system_suspect_tests": sys.get("suspect_tests", []),
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
