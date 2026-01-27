#!/usr/bin/env python3
"""
compare_dieharder_results.py

Compare QSE and System dieharder parsed results (report.json) and output comparison.json

Comparison Methodology (based on Dieharder documentation):
1. FAILED tests (p < 0.0001 or p > 0.9999) are the PRIMARY indicator of randomness weaknesses
2. WEAK tests (p < 0.005 or p > 0.995) are SECONDARY concerns - some are statistically expected
3. Overall winner is determined by:
   - Priority 1: Fewer FAILED tests = stronger
   - Priority 2: Fewer WEAK tests (if same failed count) = stronger
   - Priority 3: More PASSED tests (if same failed/weak counts) = stronger
   - Priority 4: P-value distribution quality (closer to uniform = better)
4. Individual test-by-test comparisons are for detailed analysis but don't override overall failure counts

Note: P-values closer to 0.5 indicate better randomness (more uniform distribution).
However, the absence of extreme p-values (FAILED) is more important than p-value proximity to 0.5.

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

    # Overall verdict based on Dieharder strength assessment principles:
    # Priority 1: Fewer FAILED tests (p < 0.0001 or p > 0.9999) = stronger
    # Priority 2: Fewer WEAK tests (if same failed count) = stronger
    # Priority 3: More PASSED tests (if same failed/weak counts) = stronger
    # Priority 4: P-value distribution quality (closer to uniform = better)
    #   When both sources pass (0 failed), p-value distribution becomes more important
    # Individual test-by-test wins are less important than overall failure counts
    
    qse_failed = qse["summary"]["failed_tests"]
    sys_failed = sys["summary"]["failed_tests"]
    qse_weak = qse["summary"]["weak_tests"]
    sys_weak = sys["summary"]["weak_tests"]
    qse_passed = qse["summary"]["passed_tests"]
    sys_passed = sys["summary"]["passed_tests"]
    
    # Calculate p-value distribution quality (closer to 0.5 = better uniform distribution)
    qse_p_values = [t["p_value"] for t in qse["tests"]]
    sys_p_values = [t["p_value"] for t in sys["tests"]]
    
    qse_avg_dist = sum(abs(p - 0.5) for p in qse_p_values) / len(qse_p_values) if qse_p_values else 0.5
    sys_avg_dist = sum(abs(p - 0.5) for p in sys_p_values) / len(sys_p_values) if sys_p_values else 0.5
    
    overall_winner = "tie"
    
    # Priority 1: Compare FAILED tests (most critical - indicates real problems)
    if qse_failed < sys_failed:
        overall_winner = "qse"
    elif sys_failed < qse_failed:
        overall_winner = "system"
    else:
        # Same number of failed tests - compare WEAK tests
        if qse_weak < sys_weak:
            overall_winner = "qse"
        elif sys_weak < qse_weak:
            overall_winner = "system"
        else:
            # Same failed and weak - compare PASSED tests
            if qse_passed > sys_passed:
                overall_winner = "qse"
            elif sys_passed > qse_passed:
                overall_winner = "system"
            else:
                # Same counts - compare p-value distribution quality
                # For truly random sources, p-values should be uniformly distributed
                # Average distance from 0.5 indicates how uniform the distribution is
                # Smaller distance = more uniform = stronger randomness
                if qse_avg_dist < sys_avg_dist:
                    overall_winner = "qse"
                elif sys_avg_dist < qse_avg_dist:
                    overall_winner = "system"
                # else: tie (identical performance)

    output = {
        "overall": {
            "qse_overall_pass": qse["summary"]["overall_pass"],
            "system_overall_pass": sys["summary"]["overall_pass"],
            "winner": overall_winner,
            "win_counts": win_counts,
            "qse_failed": qse_failed,
            "sys_failed": sys_failed,
            "qse_weak": qse_weak,
            "sys_weak": sys_weak,
            "qse_passed": qse_passed,
            "sys_passed": sys_passed,
            "qse_pvalue_avg_dist_from_05": round(qse_avg_dist, 6),
            "sys_pvalue_avg_dist_from_05": round(sys_avg_dist, 6),
        },
        "comparisons": comparisons,
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print("✅ Comparison generated.")
    print(f"Winner: {overall_winner}")
    print(f"QSE: {qse_passed} passed, {qse_weak} weak, {qse_failed} failed")
    print(f"System: {sys_passed} passed, {sys_weak} weak, {sys_failed} failed")
    print(f"P-value distribution (avg distance from 0.5): QSE={qse_avg_dist:.6f}, System={sys_avg_dist:.6f} (lower = better)")
    print(f"Individual test wins: QSE={win_counts['qse']}, System={win_counts['system']}, Ties={win_counts['tie']}")
    print(f"Saved: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
