#!/usr/bin/env python3
"""
parse_dieharder_report.py

Parses dieharder output and extracts test results into structured JSON.

Dieharder output format (with -c ',' -D default -D pvalues):
   diehard_birthdays|   0|       100|     100|0.54821141|  PASSED
   diehard_operm5|   0|   1000000|     100|0.12345678|  PASSED

Key fields:
- Test name
- ntuple value
- tsamples
- psamples
- p-value
- Assessment (PASSED/WEAK/FAILED)

Usage:
  python3 parse_dieharder_report.py --report dieharder-results/qse/report.txt --out dieharder-results/qse/report.json
"""

import argparse
import csv
import json
import os
import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Any


@dataclass
class TestResult:
    test_name: str
    ntuple: int
    tsamples: int
    psamples: int
    p_value: float
    assessment: str  # PASSED, WEAK, FAILED


# Matches dieharder output lines with -D test_name -D pvalues:
#   diehard_birthdays,0.88508587
# Format: test_name,pvalue
SIMPLE_ROW_REGEX = re.compile(
    r"""
    ^\s*([^,]+),        # test_name
    \s*([0-9.]+)\s*$    # p_value
    """,
    re.VERBOSE,
)

# Matches dieharder output lines with pipe delimiter (old format):
#   diehard_birthdays|   0|       100|     100|0.54821141|  PASSED
# Format: test_name|ntuple|tsamples|psamples|p_value|assessment
PIPE_ROW_REGEX = re.compile(
    r"""
    ^\s*([^\|]+)\|      # test_name
    \s*(\d+)\|          # ntuple
    \s*(\d+)\|          # tsamples
    \s*(\d+)\|          # psamples
    \s*([0-9.]+)\|      # p_value
    \s*(PASSED|WEAK|FAILED)\s*$  # assessment
    """,
    re.VERBOSE,
)


def determine_assessment(p_value: float) -> str:
    """
    Determine assessment (PASSED/WEAK/FAILED) based on p-value.
    Based on dieharder's thresholds:
    - FAILED: p < 0.0001 or p > 0.9999 (very extreme)
    - WEAK: p < 0.005 or p > 0.995 (close to boundaries)
    - PASSED: otherwise (acceptable range)
    """
    if p_value < 0.0001 or p_value > 0.9999:
        return "FAILED"
    elif p_value < 0.005 or p_value > 0.995:
        return "WEAK"
    else:
        return "PASSED"


def parse_dieharder_output(text: str) -> List[TestResult]:
    """
    Parse dieharder output text and extract test results.
    Supports two formats:
    1. Simple format: test_name,pvalue (from -D test_name -D pvalues)
    2. Full format: test_name|ntuple|tsamples|psamples|p_value|assessment
    """
    results: List[TestResult] = []
    lines = text.splitlines()
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Try simple format first: test_name,pvalue
        m = SIMPLE_ROW_REGEX.match(line)
        if m:
            test_name = m.group(1).strip()
            p_value = float(m.group(2))
            assessment = determine_assessment(p_value)
            
            results.append(
                TestResult(
                    test_name=test_name,
                    ntuple=0,  # Not available in simple format
                    tsamples=0,  # Not available in simple format
                    psamples=0,  # Not available in simple format
                    p_value=p_value,
                    assessment=assessment,
                )
            )
            continue
        
        # Try pipe-delimited format (old format)
        m = PIPE_ROW_REGEX.match(line)
        if m:
            test_name = m.group(1).strip()
            ntuple = int(m.group(2))
            tsamples = int(m.group(3))
            psamples = int(m.group(4))
            p_value = float(m.group(5))
            assessment = m.group(6).strip()
            
            results.append(
                TestResult(
                    test_name=test_name,
                    ntuple=ntuple,
                    tsamples=tsamples,
                    psamples=psamples,
                    p_value=p_value,
                    assessment=assessment,
                )
            )
            continue
        
        # Try old format: 2,test_name,ntuple,tsamples,psamples (no p-value)
        # This format doesn't have p-values, so we skip it
        if ',' in line and '|' not in line:
            parts = [p.strip() for p in line.split(',')]
            # Skip header lines and lines that start with 0 or 1
            if len(parts) >= 2 and parts[0] not in ['0', '1', '2']:
                # This might be a different format, try to parse
                try:
                    # Check if it's the 6-field format with p-value
                    if len(parts) >= 6:
                        test_name = parts[0]
                        ntuple = int(parts[1])
                        tsamples = int(parts[2])
                        psamples = int(parts[3])
                        p_value = float(parts[4])
                        assessment = parts[5].strip()
                        
                        if assessment in ['PASSED', 'WEAK', 'FAILED']:
                            results.append(
                                TestResult(
                                    test_name=test_name,
                                    ntuple=ntuple,
                                    tsamples=tsamples,
                                    psamples=psamples,
                                    p_value=p_value,
                                    assessment=assessment,
                                )
                            )
                except (ValueError, IndexError):
                    # Old format without p-value - skip
                    pass
    
    return results


def build_report(results: List[TestResult]) -> Dict[str, Any]:
    """
    Build structured report from test results.
    """
    if not results:
        raise ValueError("❌ No test results found in dieharder output.")
    
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r.assessment == "PASSED")
    weak_tests = sum(1 for r in results if r.assessment == "WEAK")
    failed_tests = sum(1 for r in results if r.assessment == "FAILED")
    
    # Overall pass: all tests must be PASSED (no WEAK or FAILED)
    overall_pass = failed_tests == 0 and weak_tests == 0
    
    # Find weakest test (lowest p-value among failed/weak, or lowest overall)
    weakest = min(results, key=lambda r: (0 if r.assessment == "PASSED" else 1, r.p_value))
    
    # Find tests with lowest p-values (potential concerns)
    lowest_p_value = min(results, key=lambda r: r.p_value)
    
    # Borderline tests (WEAK or p-value close to thresholds)
    borderline = [r for r in results if r.assessment == "WEAK" or (r.p_value < 0.01 or r.p_value > 0.99)]
    
    return {
        "summary": {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "weak_tests": weak_tests,
            "failed_tests": failed_tests,
            "overall_pass": overall_pass,
        },
        "weakest_test": asdict(weakest),
        "lowest_p_value_test": asdict(lowest_p_value),
        "borderline_tests": [asdict(r) for r in borderline],
        "tests": [asdict(r) for r in results],
    }


def write_csv(results: List[TestResult], csv_path: str) -> None:
    """Write results to CSV file."""
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "test_name",
                "ntuple",
                "tsamples",
                "psamples",
                "p_value",
                "assessment",
            ],
        )
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse dieharder output into JSON + CSV"
    )
    parser.add_argument("--report", required=True, help="Path to dieharder output file (stdout captured)")
    parser.add_argument("--out", required=True, help="Output JSON path")
    args = parser.parse_args()

    if not os.path.exists(args.report):
        raise FileNotFoundError(f"❌ Report not found: {args.report}")

    with open(args.report, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    results = parse_dieharder_output(text)
    report_obj = build_report(results)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report_obj, f, indent=2)

    csv_path = os.path.splitext(args.out)[0] + ".csv"
    write_csv(results, csv_path)

    print("✅ Parsed dieharder report successfully.")
    print(f"JSON: {args.out}")
    print(f"CSV:  {csv_path}")
    print(f"Overall pass: {report_obj['summary']['overall_pass']} "
          f"({report_obj['summary']['passed_tests']}/{report_obj['summary']['total_tests']} passed, "
          f"{report_obj['summary']['weak_tests']} weak, {report_obj['summary']['failed_tests']} failed)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
