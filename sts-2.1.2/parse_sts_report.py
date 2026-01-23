#!/usr/bin/env python3
"""
parse_sts_report.py (robust)

Parses NIST STS finalAnalysisReport.txt and extracts the summary table:
Uniformity of P-values + Proportion of Passing Sequences.

Outputs:
- report.json
- report.csv

Usage:
  python3 parse_sts_report.py --report sts-results/qse/finalAnalysisReport.txt --out sts-results/qse/report.json
"""

import argparse
import csv
import json
import os
import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Tuple


@dataclass
class TestResult:
    test_name: str
    p_value_uniformity: float
    passed: int
    total: int
    pass_rate: float
    min_required: int
    meets_threshold: bool


# Matches: "generator is <data/qse_all.bin>"
GENERATOR_REGEX = re.compile(r"generator is <(.+?)>")

# Matches summary rows:
#  11  11 ...  0.834308     99/100     Frequency
ROW_REGEX = re.compile(
    r"""
    ^\s*\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+
    \s+([0-9.]+)
    \s+(\d+)\/(\d+)
    \s+(.+?)\s*$
    """,
    re.VERBOSE,
)

DEFAULT_MIN_REQUIRED = 96
RANDOM_EXCURSION_MIN_REQUIRED = 57


def detect_min_required(test_name: str, total: int) -> int:
    name = test_name.lower()
    if "randomexcursions" in name:
        if total == 60:
            return RANDOM_EXCURSION_MIN_REQUIRED
        return int(0.95 * total)

    if total == 100:
        return DEFAULT_MIN_REQUIRED

    return int(0.95 * total)


def find_summary_table_start(lines: List[str]) -> int:
    """
    Finds the line index where the summary table begins.
    It looks for:
      - a line containing 'RESULTS FOR THE UNIFORMITY'
      - OR the table header containing 'P-VALUE' and 'PROPORTION'
    """
    for i, line in enumerate(lines):
        if "RESULTS FOR THE UNIFORMITY" in line.upper():
            return i
        if "P-VALUE" in line and "PROPORTION" in line:
            return max(i - 3, 0)
    return -1


def parse_summary_block(text: str) -> Tuple[str, List[TestResult]]:
    lines = text.splitlines()

    start_idx = find_summary_table_start(lines)
    if start_idx == -1:
        raise ValueError(
            "❌ Could not locate STS summary table. "
            "Make sure this is finalAnalysisReport.txt from STS."
        )

    # generator name
    generator_match = GENERATOR_REGEX.search(text)
    generator = generator_match.group(1).strip() if generator_match else "unknown"

    results: List[TestResult] = []
    in_table = False

    for line in lines[start_idx:]:
        if "P-VALUE" in line and "PROPORTION" in line:
            in_table = True
            continue

        if not in_table:
            continue

        if line.strip().startswith("- - - - -") or "minimum pass rate" in line.lower():
            break

        m = ROW_REGEX.match(line)
        if not m:
            continue

        p_val = float(m.group(1))
        passed = int(m.group(2))
        total = int(m.group(3))
        test_name = m.group(4).strip()

        min_req = detect_min_required(test_name, total)
        meets = passed >= min_req
        pass_rate = (passed / total) * 100 if total else 0.0

        results.append(
            TestResult(
                test_name=test_name,
                p_value_uniformity=p_val,
                passed=passed,
                total=total,
                pass_rate=pass_rate,
                min_required=min_req,
                meets_threshold=meets,
            )
        )

    if not results:
        raise ValueError("❌ No test results parsed from summary table. Format may differ.")

    return generator, results


def build_report(generator: str, results: List[TestResult]) -> Dict[str, Any]:
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r.meets_threshold)

    weakest = min(results, key=lambda r: (r.passed - r.min_required, r.p_value_uniformity))
    lowest_uniformity = min(results, key=lambda r: r.p_value_uniformity)

    borderline = [r for r in results if (r.passed - r.min_required) <= 2]

    return {
        "generator": generator,
        "summary": {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": total_tests - passed_tests,
            "overall_pass": passed_tests == total_tests,
        },
        "weakest_test": asdict(weakest),
        "lowest_uniformity_test": asdict(lowest_uniformity),
        "borderline_tests": [asdict(r) for r in borderline],
        "tests": [asdict(r) for r in results],
    }


def write_csv(results: List[TestResult], csv_path: str) -> None:
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "test_name",
                "p_value_uniformity",
                "passed",
                "total",
                "pass_rate",
                "min_required",
                "meets_threshold",
            ],
        )
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse NIST STS finalAnalysisReport.txt into JSON + CSV")
    parser.add_argument("--report", required=True, help="Path to finalAnalysisReport.txt")
    parser.add_argument("--out", required=True, help="Output JSON path")
    args = parser.parse_args()

    if not os.path.exists(args.report):
        raise FileNotFoundError(f"❌ Report not found: {args.report}")

    with open(args.report, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    generator, results = parse_summary_block(text)
    report_obj = build_report(generator, results)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report_obj, f, indent=2)

    csv_path = os.path.splitext(args.out)[0] + ".csv"
    write_csv(results, csv_path)

    print("✅ Parsed STS report successfully.")
    print(f"Generator: {generator}")
    print(f"JSON: {args.out}")
    print(f"CSV:  {csv_path}")
    print(f"Overall pass: {report_obj['summary']['overall_pass']} "
          f"({report_obj['summary']['passed_tests']}/{report_obj['summary']['total_tests']})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())