#!/usr/bin/env python3
"""
render_scorecard_html.py

Render scorecard.json into a professional PDF-style HTML report (Dieharder).

Usage:
  python3 render_scorecard_html.py \
    --scorecard dieharder-results/scorecard.json \
    --out dieharder-results/scorecard.html
"""

import argparse
import json
import os
from datetime import datetime
from typing import Dict, Any


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def badge(text: str, kind: str) -> str:
    color = {
        "pass": "#0f766e",
        "fail": "#b91c1c",
        "info": "#1d4ed8",
        "warn": "#b45309",
        "neutral": "#334155",
    }.get(kind, "#334155")
    return f"""<span class="badge" style="background:{color};">{text}</span>"""


def fmt_pct(x: float) -> str:
    return f"{x:.2f}%"


def main() -> int:
    parser = argparse.ArgumentParser(description="Render investor-style HTML scorecard (Dieharder)")
    parser.add_argument("--scorecard", required=True, help="scorecard.json path")
    parser.add_argument("--out", required=True, help="Output HTML path")
    args = parser.parse_args()

    sc = load_json(args.scorecard)

    qse_pass = sc["qse_summary"]["overall_pass"]
    sys_pass = sc["system_summary"]["overall_pass"]

    overall_badge = badge("PASS", "pass") if (qse_pass and sys_pass) else badge("CHECK", "warn")

    winner = sc["overall"]["winner"]
    winner_text = "Tie" if winner == "tie" else ("QSE" if winner == "qse" else "System")
    
    # Get config values from scorecard (with fallbacks for older scorecards)
    config = sc.get("config", {})
    num_sequences = config.get("sequences", 100)
    seq_length = config.get("sequence_length_bits", 1_000_000)
    input_mode = config.get("input_mode", "binary")
    
    # Format sequence length with commas
    seq_length_formatted = f"{seq_length:,}"
    
    # Get generated timestamp from scorecard or use current time
    generated_at = sc.get("generated_at", datetime.utcnow().isoformat() + "Z")
    try:
        # Parse ISO format timestamp and format for display
        dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        generated_str = dt.strftime("%Y-%m-%d %H:%M UTC")
    except:
        generated_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Dieharder Entropy Scorecard</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      background: #f8fafc;
      color: #0f172a;
      margin: 0;
      padding: 0;
    }}
    .page {{
      max-width: 980px;
      margin: 40px auto;
      padding: 40px;
      background: white;
      box-shadow: 0 10px 30px rgba(2, 6, 23, 0.10);
      border-radius: 16px;
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 18px;
      margin-bottom: 18px;
    }}
    .title {{
      font-size: 24px;
      font-weight: 800;
      margin: 0;
    }}
    .subtitle {{
      margin: 6px 0 0;
      color: #475569;
      font-size: 13px;
    }}
    .badge {{
      color: white;
      padding: 8px 12px;
      border-radius: 999px;
      font-weight: 700;
      font-size: 12px;
      letter-spacing: 0.2px;
      white-space: nowrap;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 14px;
      margin-top: 14px;
    }}
    .card {{
      border: 1px solid #e2e8f0;
      border-radius: 14px;
      padding: 14px;
      background: #ffffff;
    }}
    .card h3 {{
      margin: 0 0 6px;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #475569;
    }}
    .card .value {{
      font-size: 22px;
      font-weight: 800;
      margin: 0;
    }}
    .muted {{
      color: #64748b;
      font-size: 13px;
      line-height: 1.4;
    }}
    .section {{
      margin-top: 26px;
    }}
    .section h2 {{
      font-size: 16px;
      margin: 0 0 10px;
      font-weight: 800;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      overflow: hidden;
      font-size: 13px;
    }}
    th, td {{
      padding: 10px 10px;
      border-bottom: 1px solid #e2e8f0;
      text-align: left;
    }}
    th {{
      background: #f1f5f9;
      font-weight: 800;
      color: #334155;
    }}
    tr:last-child td {{
      border-bottom: none;
    }}
    .winner-qse {{
      color: #0f766e;
      font-weight: 800;
    }}
    .winner-system {{
      color: #1d4ed8;
      font-weight: 800;
    }}
    .winner-tie {{
      color: #334155;
      font-weight: 800;
    }}
    .callout {{
      border-left: 4px solid #1d4ed8;
      background: #eff6ff;
      padding: 12px 14px;
      border-radius: 10px;
      margin-top: 10px;
      font-size: 13px;
    }}
    .small {{
      font-size: 12px;
      color: #64748b;
    }}
    @media print {{
      body {{
        background: white;
      }}
      .page {{
        margin: 0;
        box-shadow: none;
        border-radius: 0;
      }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <div class="header">
      <div>
        <h1 class="title">Dieharder Entropy Scorecard</h1>
        <div class="subtitle">
          Dieharder Test Suite • {num_sequences} sequences × {seq_length_formatted} bits • {input_mode.capitalize()} mode<br/>
          Generated: {generated_str}
        </div>
      </div>
      <div style="text-align:right">
        {overall_badge}<br/>
        <div class="small">Winner: <b>{winner_text}</b></div>
      </div>
    </div>

    <div class="callout">
      <b>Headline Verdict:</b> {sc["headline_verdict"]}
    </div>

    <div class="grid">
      <div class="card">
        <h3>QSE Overall</h3>
        <p class="value">{badge("PASS", "pass") if qse_pass else badge("FAIL", "fail")}</p>
        <div class="muted">Passed: {sc["qse_summary"]["passed_tests"]}/{sc["qse_summary"]["total_tests"]}<br/>
        Weak: {sc["qse_summary"]["weak_tests"]}, Failed: {sc["qse_summary"]["failed_tests"]}</div>
      </div>

      <div class="card">
        <h3>System Overall</h3>
        <p class="value">{badge("PASS", "pass") if sys_pass else badge("FAIL", "fail")}</p>
        <div class="muted">Passed: {sc["system_summary"]["passed_tests"]}/{sc["system_summary"]["total_tests"]}<br/>
        Weak: {sc["system_summary"]["weak_tests"]}, Failed: {sc["system_summary"]["failed_tests"]}</div>
      </div>

      <div class="card">
        <h3>Wins by Test</h3>
        <p class="value">{sc["wins_by_test"]["qse"]} QSE • {sc["wins_by_test"]["system"]} System</p>
        <div class="muted">{sc["wins_by_test"]["tie"]} ties</div>
      </div>
    </div>

    <div class="section">
      <h2>Key Risk / Weakest Tests</h2>
      <table>
        <tr>
          <th>Source</th>
          <th>Weakest Test</th>
          <th>P-value</th>
          <th>Assessment</th>
        </tr>
        <tr>
          <td><b>QSE</b></td>
          <td>{sc["qse_weakest_test"]["test_name"]}</td>
          <td>{sc["qse_weakest_test"]["p_value"]}</td>
          <td>{badge(sc["qse_weakest_test"]["assessment"], "pass" if sc["qse_weakest_test"]["assessment"] == "PASSED" else "warn" if sc["qse_weakest_test"]["assessment"] == "WEAK" else "fail")}</td>
        </tr>
        <tr>
          <td><b>System</b></td>
          <td>{sc["system_weakest_test"]["test_name"]}</td>
          <td>{sc["system_weakest_test"]["p_value"]}</td>
          <td>{badge(sc["system_weakest_test"]["assessment"], "pass" if sc["system_weakest_test"]["assessment"] == "PASSED" else "warn" if sc["system_weakest_test"]["assessment"] == "WEAK" else "fail")}</td>
        </tr>
      </table>
      <div class="small" style="margin-top:8px;">
        Note: Dieharder evaluates statistical randomness. It does not alone certify cryptographic strength or "quantum resilience."
      </div>
    </div>

    <div class="section">
      <h2>Per-Test Comparison (All Tests)</h2>
      <table>
        <tr>
          <th>Test</th>
          <th>QSE P-value</th>
          <th>QSE Assessment</th>
          <th>System P-value</th>
          <th>System Assessment</th>
          <th>Winner</th>
        </tr>
"""

    for row in sc["comparisons"]:
        w = row["winner"]
        w_class = "winner-tie"
        w_label = "Tie"
        if w == "qse":
            w_class = "winner-qse"
            w_label = "QSE"
        elif w == "system":
            w_class = "winner-system"
            w_label = "System"
        
        qse_assessment = row["qse"]["assessment"]
        sys_assessment = row["system"]["assessment"]
        qse_badge = badge(qse_assessment, "pass" if qse_assessment == "PASSED" else "warn" if qse_assessment == "WEAK" else "fail")
        sys_badge = badge(sys_assessment, "pass" if sys_assessment == "PASSED" else "warn" if sys_assessment == "WEAK" else "fail")

        html += f"""
        <tr>
          <td>{row["test_name"]}</td>
          <td>{row["qse"]["p_value"]}</td>
          <td>{qse_badge}</td>
          <td>{row["system"]["p_value"]}</td>
          <td>{sys_badge}</td>
          <td class="{w_class}">{w_label}</td>
        </tr>
"""

    html += """
      </table>
    </div>

    <div class="section">
      <h2>Recommended Next Steps</h2>
      <div class="muted">
        • Run multiple independent batches (e.g., 5 runs) with newly generated data for both sources.<br/>
        • Increase sequences to 200–300 per run for stronger statistical confidence.<br/>
        • Track stability: count how often any test hits WEAK or FAILED across runs.<br/>
        • Archive all Dieharder reports and parameters for auditability.
      </div>
    </div>

    <div class="section" style="margin-top:28px;text-align:center;">
      <div class="small">— End of Report —</div>
    </div>
  </div>
</body>
</html>
"""

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)

    print("✅ HTML scorecard generated.")
    print(f"Saved: {args.out}")
    print("Open it with: open", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
