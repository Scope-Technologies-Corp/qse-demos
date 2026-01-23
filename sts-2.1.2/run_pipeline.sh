#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./run_pipeline.sh --seq-length 1000000 --sequences 100


What it does:
  1) Generate QSE + System entropy streams (.bin)
  2) Concatenate into data/qse_all.bin and data/system_all.bin
  3) Launch ./assess interactively for QSE (you enter choices)
  4) Copies experiments/AlgorithmTesting/finalAnalysisReport.txt -> sts-results/qse/finalAnalysisReport.txt
  5) Launch ./assess interactively for System (you enter choices)
  6) Copies experiments/AlgorithmTesting/finalAnalysisReport.txt -> sts-results/system/finalAnalysisReport.txt
  7) Parses both -> report.json + report.csv
  8) Compares + generates scorecard + renders HTML
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
echo " NIST STS Pipeline (manual assess step)"
echo " ROOT      : $ROOT_DIR"
echo " SEQ_LENGTH : $SEQ_LENGTH"
echo " SEQUENCES  : $SEQUENCES"
echo "============================================"

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

mkdir -p entropy-streams/qse entropy-streams/system data sts-results/qse sts-results/system

# --- Step 1: generate QSE streams
if [[ -z "${ENTROPY_ENDPOINT:-}" ]]; then
  echo "❌ ENTROPY_ENDPOINT is not set."
  echo '   Example: export ENTROPY_ENDPOINT="http://scopesvr.fractalarmor.com:8888/entropy/get"'
  exit 1
fi

echo
echo "== Step 1/8: Generate QSE entropy streams =="
python3 generate_entropy.py --use qse --seq-length "$SEQ_LENGTH" --sequences "$SEQUENCES"

# --- Step 2: generate SYSTEM streams
echo
echo "== Step 2/8: Generate SYSTEM entropy streams =="
python3 generate_entropy.py --use local --seq-length "$SEQ_LENGTH" --sequences "$SEQUENCES"

# --- Step 3/4: concatenate into single files for STS
QSE_ALL="data/qse_all.bin"
SYSTEM_ALL="data/system_all.bin"

echo
echo "== Step 3/8: Concatenate QSE streams -> $ROOT_DIR/$QSE_ALL =="
cat entropy-streams/qse/*.bin > "$QSE_ALL"

echo
echo "== Step 4/8: Concatenate SYSTEM streams -> $ROOT_DIR/$SYSTEM_ALL =="
cat entropy-streams/system/*.bin > "$SYSTEM_ALL"

# --- helper: run assess interactively + save report
run_assess_interactive() {
  local SOURCE="$1"     # qse | system (lowercase)
  local INPUT_FILE="$2"

  local REPORT_SRC="experiments/AlgorithmTesting/finalAnalysisReport.txt"
  local OUT_DIR="sts-results/${SOURCE}"
  local OUT_REPORT="${OUT_DIR}/finalAnalysisReport.txt"

  echo
  echo "============================================"
  echo "✅ Running ./assess for: ${SOURCE}"
  echo "Input file: ${INPUT_FILE}"
  echo
  echo "When prompted, use these choices:"
  echo "  Enter Choice (Generator): 0"
  echo "  User Prescribed Input File: ${INPUT_FILE}"
  echo "  Apply all tests?: 1"
  echo "  Select Test (0 to continue): 0"
  echo "  How many bitstreams?: ${SEQUENCES}"
  echo "  Input File Format: 1 (Binary)"
  echo "============================================"
  echo

  mkdir -p "${OUT_DIR}"

  # ./assess can return non-zero even if it completes.
  set +e
  ./assess "${SEQ_LENGTH}"
  local ASSESS_RC=$?
  set -e

  echo
  echo "ℹ️ ./assess exit code: ${ASSESS_RC} (can be non-zero even on success)"

  # STS writes the final report here (authoritative)
  if [[ ! -f "${REPORT_SRC}" ]]; then
    echo "❌ STS did not produce: ${REPORT_SRC}"
    echo "   This usually means the run didn't complete, or STS couldn't write outputs."
    exit 1
  fi

  cp "${REPORT_SRC}" "${OUT_REPORT}"
  echo "✅ Saved: ${OUT_REPORT}"
}

# --- Step 5: run assess for QSE (manual)
echo
echo "== Step 5/8: Run STS manually (QSE) =="
run_assess_interactive "qse" "${QSE_ALL}"

# --- Step 6: run assess for SYSTEM (manual)
echo
echo "== Step 6/8: Run STS manually (SYSTEM) =="
run_assess_interactive "system" "${SYSTEM_ALL}"

# --- Step 7: parse reports
echo
echo "== Step 7/8: Parse STS reports -> report.json/report.csv =="

python3 parse_sts_report.py \
  --report "sts-results/qse/finalAnalysisReport.txt" \
  --out "sts-results/qse/report.json"

python3 parse_sts_report.py \
  --report "sts-results/system/finalAnalysisReport.txt" \
  --out "sts-results/system/report.json"

# --- Step 8: compare + scorecard + html
echo
echo "== Step 8/8: Compare + Scorecard + HTML =="

python3 compare_sts_results.py \
  --qse "sts-results/qse/report.json" \
  --system "sts-results/system/report.json" \
  --out "sts-results/compare.json"

python3 generate_scorecard.py \
  --qse "sts-results/qse/report.json" \
  --system "sts-results/system/report.json" \
  --comparison "sts-results/compare.json" \
  --out "sts-results/scorecard.json"

python3 render_scorecard_html.py \
  --scorecard "sts-results/scorecard.json" \
  --out "sts-results/scorecard.html"

echo
echo "✅ Done."
echo "Open report:"
echo "  open sts-results/scorecard.html"
echo "Export PDF: Chrome -> Print -> Save as PDF"