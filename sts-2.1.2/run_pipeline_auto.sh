#!/usr/bin/env bash
#
# Automated NIST STS Pipeline for Web UI
# This is a non-interactive version of run_pipeline.sh
# Used by the web demo to run the full pipeline automatically
#
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./run_pipeline_auto.sh --seq-length 1000000 --sequences 100

Environment:
  ENTROPY_ENDPOINT - Required. Example: http://scopesvr.fractalarmor.com:8888/entropy/get

What it does (fully automated, no user input needed):
  1) Generate QSE entropy streams (.bin)
  2) Generate System entropy streams (.bin)
  3) Concatenate into data/qse_all.bin
  4) Concatenate into data/system_all.bin
  5) Run ./assess for QSE (automated)
  6) Run ./assess for System (automated)
  7) Parse both reports -> report.json + report.csv
  8) Compare + generate scorecard + render HTML
EOF
}

SEQ_LENGTH="1000000"
SEQUENCES="100"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --seq-length) SEQ_LENGTH="$2"; shift 2 ;;
    --sequences)  SEQUENCES="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "============================================"
echo " NIST STS Pipeline (Automated Mode)"
echo "============================================"
echo " ROOT       : $ROOT_DIR"
echo " SEQ_LENGTH : $SEQ_LENGTH bits"
echo " SEQUENCES  : $SEQUENCES"
echo " ENDPOINT   : ${ENTROPY_ENDPOINT:-NOT SET}"
echo "============================================"
echo

# --- sanity checks
if [[ ! -x "./assess" ]]; then
  echo "❌ ./assess not found or not executable."
  echo "   Run: make"
  exit 1
fi

if [[ ! -f "generate_entropy.py" ]]; then
  echo "❌ generate_entropy.py not found in this directory."
  exit 1
fi

if [[ -z "${ENTROPY_ENDPOINT:-}" ]]; then
  echo "❌ ENTROPY_ENDPOINT is not set."
  echo '   Example: export ENTROPY_ENDPOINT="http://scopesvr.fractalarmor.com:8888/entropy/get"'
  exit 1
fi

# Create directories
mkdir -p entropy-streams/qse entropy-streams/system data sts-results/qse sts-results/system

# ============================================
# Step 1: Generate QSE entropy streams
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📥 Step 1/8: Generate QSE entropy streams"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Using endpoint: ${ENTROPY_ENDPOINT}"
echo
python3 generate_entropy.py --use qse --seq-length "$SEQ_LENGTH" --sequences "$SEQUENCES"
echo "✅ Step 1 complete: QSE entropy generated"

# ============================================
# Step 2: Generate SYSTEM entropy streams
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🖥️  Step 2/8: Generate SYSTEM entropy streams"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
python3 generate_entropy.py --use local --seq-length "$SEQ_LENGTH" --sequences "$SEQUENCES"
echo "✅ Step 2 complete: System entropy generated"

# ============================================
# Step 3: Concatenate QSE streams
# ============================================
QSE_ALL="data/qse_all.bin"
SYSTEM_ALL="data/system_all.bin"

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔗 Step 3/8: Concatenate QSE streams"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat entropy-streams/qse/*.bin > "$QSE_ALL"
QSE_SIZE=$(du -h "$QSE_ALL" | cut -f1)
echo "✅ Created: $QSE_ALL ($QSE_SIZE)"

# ============================================
# Step 4: Concatenate SYSTEM streams
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔗 Step 4/8: Concatenate SYSTEM streams"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat entropy-streams/system/*.bin > "$SYSTEM_ALL"
SYS_SIZE=$(du -h "$SYSTEM_ALL" | cut -f1)
echo "✅ Created: $SYSTEM_ALL ($SYS_SIZE)"

# ============================================
# Helper: Run assess with automated input
# ============================================
run_assess_auto() {
  local SOURCE="$1"     # qse | system (lowercase)
  local INPUT_FILE="$2"

  local REPORT_SRC="experiments/AlgorithmTesting/finalAnalysisReport.txt"
  local OUT_DIR="sts-results/${SOURCE}"
  local OUT_REPORT="${OUT_DIR}/finalAnalysisReport.txt"

  mkdir -p "${OUT_DIR}"

  echo
  echo "🔬 Running NIST STS for: ${SOURCE}"
  echo "   Input file: ${INPUT_FILE}"
  echo "   Bitstreams: ${SEQUENCES}"
  echo "   Bit length: ${SEQ_LENGTH}"
  echo

  # Automated input sequence for ./assess:
  # 0           - Select "Input File" generator
  # INPUT_FILE  - Path to combined binary file
  # 1           - Apply all tests
  # 0           - No parameter adjustments (continue)
  # SEQUENCES   - Number of bitstreams
  # 1           - Binary input format

  # ./assess can return non-zero even if it completes successfully
  set +e
  printf '%s\n' "0" "${INPUT_FILE}" "1" "0" "${SEQUENCES}" "1" | ./assess "${SEQ_LENGTH}" 2>&1
  local ASSESS_RC=$?
  set -e

  echo
  echo "ℹ️  ./assess exit code: ${ASSESS_RC} (non-zero can still be success)"

  # Check if report was generated (the real success indicator)
  if [[ ! -f "${REPORT_SRC}" ]]; then
    echo "❌ STS did not produce: ${REPORT_SRC}"
    echo "   This usually means the run didn't complete."
    exit 1
  fi

  cp "${REPORT_SRC}" "${OUT_REPORT}"
  echo "✅ Saved report: ${OUT_REPORT}"
}

# ============================================
# Step 5: Run STS for QSE
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⚙️  Step 5/8: Run NIST STS (QSE)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⏳ This may take 5-15 minutes..."
run_assess_auto "qse" "${QSE_ALL}"
echo "✅ Step 5 complete: QSE STS tests done"

# ============================================
# Step 6: Run STS for SYSTEM
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⚙️  Step 6/8: Run NIST STS (SYSTEM)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⏳ This may take 5-15 minutes..."
run_assess_auto "system" "${SYSTEM_ALL}"
echo "✅ Step 6 complete: System STS tests done"

# ============================================
# Step 7: Parse reports
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Step 7/8: Parse STS reports"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "Parsing QSE report..."
python3 parse_sts_report.py \
  --report "sts-results/qse/finalAnalysisReport.txt" \
  --out "sts-results/qse/report.json"
echo "✅ Created: sts-results/qse/report.json"

echo "Parsing System report..."
python3 parse_sts_report.py \
  --report "sts-results/system/finalAnalysisReport.txt" \
  --out "sts-results/system/report.json"
echo "✅ Created: sts-results/system/report.json"

# ============================================
# Step 8: Compare + Scorecard + HTML
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📈 Step 8/8: Generate comparison & scorecard"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "Comparing results..."
python3 compare_sts_results.py \
  --qse "sts-results/qse/report.json" \
  --system "sts-results/system/report.json" \
  --out "sts-results/compare.json"
echo "✅ Created: sts-results/compare.json"

echo "Generating scorecard..."
python3 generate_scorecard.py \
  --qse "sts-results/qse/report.json" \
  --system "sts-results/system/report.json" \
  --comparison "sts-results/compare.json" \
  --out "sts-results/scorecard.json"
echo "✅ Created: sts-results/scorecard.json"

echo "Rendering HTML report..."
python3 render_scorecard_html.py \
  --scorecard "sts-results/scorecard.json" \
  --out "sts-results/scorecard.html"
echo "✅ Created: sts-results/scorecard.html"

# ============================================
# Done!
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎉 PIPELINE COMPLETE!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "Results:"
echo "  📄 QSE Report:     sts-results/qse/report.json"
echo "  📄 System Report:  sts-results/system/report.json"
echo "  📊 Comparison:     sts-results/compare.json"
echo "  📊 Scorecard:      sts-results/scorecard.json"
echo "  🌐 HTML Report:    sts-results/scorecard.html"
echo
echo "To view: open sts-results/scorecard.html"
