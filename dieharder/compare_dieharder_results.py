#!/usr/bin/env python3
"""
compare_dieharder_results.py

Compare QSE and System dieharder parsed results (report.json) and output comparison.json

Usage:
  python3 compare_dieharder_results.py \
    --qse dieharder-results/qse/report.json \
    --system dieharder-results/system/report.json \
    --out dieharder-results/comparison.json
"""

import argparse
import json
import os
from typing import Dict, Any


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def assessment_score(assessment: str) -> int:
    """Convert assessment to numeric score for comparison."""
    return {"PASSED": 2, "WEAK": 1, "FAILED": 0}.get(assessment, 0)


def score_test(qse_test: Dict[str, Any], sys_test: Dict[str, Any]) -> Dict[str, Any]:
    """
    Scoring philosophy:
    - Primary: assessment (PASSED > WEAK > FAILED)
    - Secondary: p-value (closer to 0.5 is better for randomness)
    """
    qse_assessment = qse_test["assessment"]
    sys_assessment = sys_test["assessment"]
    
    qse_p = qse_test["p_value"]
    sys_p = sys_test["p_value"]
    
    # Score based on assessment first
    qse_score = assessment_score(qse_assessment)
    sys_score = assessment_score(sys_assessment)
    
    winner = "tie"
    if qse_score > sys_score:
        winner = "qse"
    elif sys_score > qse_score:
        winner = "system"
    else:
        # Same assessment - compare p-values
        # For randomness, p-values closer to 0.5 are better (more uniform)
        qse_dist_from_05 = abs(qse_p - 0.5)
        sys_dist_from_05 = abs(sys_p - 0.5)
        
        if qse_dist_from_05 < sys_dist_from_05:
            winner = "qse"
        elif sys_dist_from_05 < qse_dist_from_05:
            winner = "system"
        # else: tie
    
    return {
        "test_name": qse_test["test_name"],
        "qse": {
            "p_value": qse_p,
            "assessment": qse_assessment,
            "ntuple": qse_test.get("ntuple", 0),
            "tsamples": qse_test.get("tsamples", 0),
            "psamples": qse_test.get("psamples", 0),
        },
        "system": {
            "p_value": sys_p,
            "assessment": sys_assessment,
            "ntuple": sys_test.get("ntuple", 0),
            "tsamples": sys_test.get("tsamples", 0),
            "psamples": sys_test.get("psamples", 0),
        },
        "winner": winner,
        "delta": {
            "p_value": round(qse_p - sys_p, 6),
            "assessment_score": qse_score - sys_score,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare QSE vs System dieharder report.json outputs."
    )
    parser.add_argument("--qse", required=True, help="Path to QSE report.json")
    parser.add_argument("--system", required=True, help="Path to system report.json")
    parser.add_argument("--out", required=True, help="Output comparison.json path")
    args = parser.parse_args()

    qse = load_json(args.qse)
    sys = load_json(args.system)

    qse_tests = {t["test_name"]: t for t in qse["tests"]}
    sys_tests = {t["test_name"]: t for t in sys["tests"]}

    all_test_names = sorted(set(qse_tests.keys()) | set(sys_tests.keys()))

    comparisons = []
    win_counts = {"qse": 0, "system": 0, "tie": 0}

    for name in all_test_names:
        if name not in qse_tests or name not in sys_tests:
            continue
        row = score_test(qse_tests[name], sys_tests[name])
        comparisons.append(row)
        win_counts[row["winner"]] += 1

    # Overall verdict
    # Priority 1: If one passes and the other fails, the one that passes wins
    # Priority 2: If both pass or both fail, compare by individual test wins
    # Priority 3: If still tied, it's a tie
    qse_overall_pass = qse["summary"]["overall_pass"]
    sys_overall_pass = sys["summary"]["overall_pass"]
    
    overall_winner = "tie"
    
    if qse_overall_pass and not sys_overall_pass:
        # QSE passes, System fails -> QSE wins
        overall_winner = "qse"
    elif sys_overall_pass and not qse_overall_pass:
        # System passes, QSE fails -> System wins
        overall_winner = "system"
    elif qse_overall_pass and sys_overall_pass:
        # Both pass - compare by individual test wins
        if win_counts["qse"] > win_counts["system"]:
            overall_winner = "qse"
        elif win_counts["system"] > win_counts["qse"]:
            overall_winner = "system"
        # else: tie (both pass and equal wins)
    else:
        # Both fail - compare by individual test wins
        if win_counts["qse"] > win_counts["system"]:
            overall_winner = "qse"
        elif win_counts["system"] > win_counts["qse"]:
            overall_winner = "system"
        # else: tie (both fail and equal wins)

    output = {
        "overall": {
            "qse_overall_pass": qse["summary"]["overall_pass"],
            "system_overall_pass": sys["summary"]["overall_pass"],
            "winner": overall_winner,
            "win_counts": win_counts,
        },
        "comparisons": comparisons,
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print("✅ Comparison generated.")
    print(f"Winner: {overall_winner}")
    print(f"QSE: {qse['summary']['passed_tests']}/{qse['summary']['total_tests']} passed")
    print(f"System: {sys['summary']['passed_tests']}/{sys['summary']['total_tests']} passed")
    print(f"Saved: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
