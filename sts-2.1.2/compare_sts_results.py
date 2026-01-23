#!/usr/bin/env python3
"""
compare_sts_results.py

Compare QSE and System STS parsed results (report.json) and output comparison.json

Usage:
  python3 compare_sts_results.py \
    --qse sts-results/qse/report.json \
    --system sts-results/system/report.json \
    --out sts-results/comparison.json
"""

import argparse
import json
import os
from typing import Dict, Any


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def score_test(qse_test: Dict[str, Any], sys_test: Dict[str, Any]) -> Dict[str, Any]:
    """
    Scoring philosophy:
    - Primary: pass_rate difference
    - Secondary: p_value_uniformity difference
    - Also track threshold margin.
    """
    qse_rate = qse_test["pass_rate"]
    sys_rate = sys_test["pass_rate"]

    qse_p = qse_test["p_value_uniformity"]
    sys_p = sys_test["p_value_uniformity"]

    qse_margin = qse_test["passed"] - qse_test["min_required"]
    sys_margin = sys_test["passed"] - sys_test["min_required"]

    winner = "tie"
    if qse_rate > sys_rate:
        winner = "qse"
    elif sys_rate > qse_rate:
        winner = "system"
    else:
        # if pass rate equal, compare p-value uniformity
        if qse_p > sys_p:
            winner = "qse"
        elif sys_p > qse_p:
            winner = "system"

    return {
        "test_name": qse_test["test_name"],
        "qse": {
            "pass_rate": qse_rate,
            "p_value_uniformity": qse_p,
            "passed": qse_test["passed"],
            "total": qse_test["total"],
            "margin": qse_margin,
            "meets_threshold": qse_test["meets_threshold"],
        },
        "system": {
            "pass_rate": sys_rate,
            "p_value_uniformity": sys_p,
            "passed": sys_test["passed"],
            "total": sys_test["total"],
            "margin": sys_margin,
            "meets_threshold": sys_test["meets_threshold"],
        },
        "winner": winner,
        "delta": {
            "pass_rate": round(qse_rate - sys_rate, 4),
            "p_value_uniformity": round(qse_p - sys_p, 6),
            "margin": qse_margin - sys_margin,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare QSE vs System STS report.json outputs.")
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
    print(f"Saved: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())