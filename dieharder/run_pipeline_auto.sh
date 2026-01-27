#!/usr/bin/env bash
#
# Automated Dieharder Pipeline for Web UI
# This is a non-interactive version for running the full pipeline automatically
#
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./run_pipeline_auto.sh --seq-length 1000000 --sequences 100

Environment:
  ENTROPY_ENDPOINT - Required. Example: http://api.example.com:8888/entropy/get

What it does (fully automated, no user input needed):
  1) Generate QSE entropy streams (.bin)
  2) Generate System entropy streams (.bin)
  3) Concatenate into data/qse_all.bin
  4) Concatenate into data/system_all.bin
  5) Run dieharder for QSE (automated)
  6) Run dieharder for System (automated)
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
echo " Dieharder Pipeline (Automated Mode)"
echo "============================================"
echo " ROOT       : $ROOT_DIR"
echo " SEQ_LENGTH : $SEQ_LENGTH bits"
echo " SEQUENCES  : $SEQUENCES"
echo " ENDPOINT   : ${ENTROPY_ENDPOINT:-NOT SET}"
echo "============================================"
echo

# --- sanity checks
DIEHARDER_BIN=""
if [[ -x "dieharder/dieharder" ]]; then
  DIEHARDER_BIN="dieharder/dieharder"
elif [[ -x "../dieharder/dieharder/dieharder" ]]; then
  DIEHARDER_BIN="../dieharder/dieharder/dieharder"
elif command -v dieharder &> /dev/null; then
  DIEHARDER_BIN="dieharder"
else
  echo "❌ dieharder binary not found."
  echo "   Expected: dieharder/dieharder"
  echo "   Or install dieharder system-wide and ensure it's in PATH"
  exit 1
fi

# Use generate_entropy.py from STS (shared utility)
GEN_ENTROPY_SCRIPT="../sts-2.1.2/generate_entropy.py"
if [[ ! -f "$GEN_ENTROPY_SCRIPT" ]]; then
  echo "❌ generate_entropy.py not found at: $GEN_ENTROPY_SCRIPT"
  exit 1
fi

if [[ -z "${ENTROPY_ENDPOINT:-}" ]]; then
  echo "❌ ENTROPY_ENDPOINT is not set."
  echo '   Example: export ENTROPY_ENDPOINT="http://api.example.com:8888/entropy/get"'
  exit 1
fi

# Create directories
mkdir -p entropy-streams/qse entropy-streams/system data dieharder-results/qse dieharder-results/system

# Remove ALL previous entropy sequences (any seq-length)
rm -f entropy-streams/qse/seq_*.bin
rm -f entropy-streams/system/seq_*.bin

# Remove previously concatenated files
rm -f data/qse_all.bin
rm -f data/system_all.bin

echo "✅ Cleanup complete"

# ============================================
# Step 1: Generate QSE entropy streams
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📥 Step 1/8: Generate QSE entropy streams"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
python3 "$GEN_ENTROPY_SCRIPT" --use qse --seq-length "$SEQ_LENGTH" --sequences "$SEQUENCES" --sleep-ms 50
echo "✅ Step 1 complete: QSE entropy generated"

# ============================================
# Step 2: Generate SYSTEM entropy streams
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🖥️  Step 2/8: Generate SYSTEM entropy streams"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
python3 "$GEN_ENTROPY_SCRIPT" --use local --seq-length "$SEQ_LENGTH" --sequences "$SEQUENCES"
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
# Helper: Run dieharder with file input
# ============================================
run_dieharder_auto() {
  local SOURCE="$1"     # qse | system (lowercase)
  local INPUT_FILE="$2"

  local OUT_DIR="dieharder-results/${SOURCE}"
  local OUT_REPORT="${OUT_DIR}/report.txt"

  mkdir -p "${OUT_DIR}"

  echo
  echo "🔬 Running Dieharder for: ${SOURCE}"
  echo "   Input file: ${INPUT_FILE}"
  echo "   Binary: ${DIEHARDER_BIN}"
  echo

  # Run dieharder with:
  # -g 201: raw binary file input
  # -f filename: input file path
  # -a: run all tests
  # -c ',': comma-separated output for easier parsing
  # -D test_name -D pvalues: output format control (test name and p-values only)
  set +e
  "$DIEHARDER_BIN" -g 201 -f "$INPUT_FILE" -a -c ',' -D test_name -D pvalues > "$OUT_REPORT" 2>&1
  local DIEHARDER_RC=$?
  set -e

  echo
  echo "ℹ️  dieharder exit code: ${DIEHARDER_RC}"

  # Check if report was generated (the real success indicator)
  if [[ ! -f "${OUT_REPORT}" ]] || [[ ! -s "${OUT_REPORT}" ]]; then
    echo "❌ Dieharder did not produce output: ${OUT_REPORT}"
    echo "   This usually means the run didn't complete."
    exit 1
  fi

  echo "✅ Saved report: ${OUT_REPORT}"
}

# ============================================
# Step 5: Run Dieharder for QSE
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⚙️  Step 5/8: Run Dieharder (QSE)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⏳ This may take 10-30 minutes..."
run_dieharder_auto "qse" "${QSE_ALL}"
echo "✅ Step 5 complete: QSE Dieharder tests done"

# ============================================
# Step 6: Run Dieharder for SYSTEM
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⚙️  Step 6/8: Run Dieharder (SYSTEM)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⏳ This may take 10-30 minutes..."
run_dieharder_auto "system" "${SYSTEM_ALL}"
echo "✅ Step 6 complete: System Dieharder tests done"

# ============================================
# Step 7: Parse reports
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Step 7/8: Parse Dieharder reports"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "Parsing QSE report..."
python3 parse_dieharder_report.py \
  --report "dieharder-results/qse/report.txt" \
  --out "dieharder-results/qse/report.json"
echo "✅ Created: dieharder-results/qse/report.json"

echo "Parsing System report..."
python3 parse_dieharder_report.py \
  --report "dieharder-results/system/report.txt" \
  --out "dieharder-results/system/report.json"
echo "✅ Created: dieharder-results/system/report.json"

# ============================================
# Step 8: Compare + Scorecard + HTML
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📈 Step 8/8: Generate comparison & scorecard"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "Comparing results..."
python3 compare_dieharder_results.py \
  --qse "dieharder-results/qse/report.json" \
  --system "dieharder-results/system/report.json" \
  --out "dieharder-results/compare.json"
echo "✅ Created: dieharder-results/compare.json"

echo "Generating scorecard..."
python3 generate_scorecard.py \
  --qse "dieharder-results/qse/report.json" \
  --system "dieharder-results/system/report.json" \
  --comparison "dieharder-results/compare.json" \
  --out "dieharder-results/scorecard.json" \
  --sequences "${SEQUENCES}" \
  --seq-length "${SEQ_LENGTH}"
echo "✅ Created: dieharder-results/scorecard.json"

echo "Rendering HTML report..."
python3 render_scorecard_html.py \
  --scorecard "dieharder-results/scorecard.json" \
  --out "dieharder-results/scorecard.html"
echo "✅ Created: dieharder-results/scorecard.html"

# ============================================
# Archive scorecard to past reports
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 Archiving scorecard to past reports"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Create past-reports directory if it doesn't exist
mkdir -p "dieharder-results/past-reports"

# Generate filename with date
DATE=$(date +"%Y%m%d_%H%M%S")
ARCHIVE_NAME="scorecard_${SEQUENCES}_seqs_${SEQ_LENGTH}_bits_${DATE}.html"
ARCHIVE_PATH="dieharder-results/past-reports/${ARCHIVE_NAME}"

# Copy scorecard.html to past-reports
cp "dieharder-results/scorecard.html" "$ARCHIVE_PATH"
echo "✅ Archived: $ARCHIVE_PATH"

# ============================================
# Done!
# ============================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎉 PIPELINE COMPLETE!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "Results:"
echo "  📄 QSE Report:     dieharder-results/qse/report.json"
echo "  📄 System Report:  dieharder-results/system/report.json"
echo "  📊 Comparison:     dieharder-results/compare.json"
echo "  📊 Scorecard:      dieharder-results/scorecard.json"
echo "  🌐 HTML Report:    dieharder-results/scorecard.html"
echo
echo "To view: open dieharder-results/scorecard.html"
