#!/usr/bin/env bash
#!/usr/bin/env bash
set -euo pipefail

# Auto-detect STS_DIR whether you run from root or inside sts-2.1.2
if [[ -f "./assess" ]]; then
  STS_DIR="."
elif [[ -f "./sts-2.1.2/assess" ]]; then
  STS_DIR="./sts-2.1.2"
else
  echo "❌ Could not find STS assess binary. Run 'make' in sts-2.1.2 first."
  exit 1
fi

INPUT_BASE="./entropy-streams"
OUT_BASE="./sts-results"
SEQ_LENGTH_BITS=1000000
ALPHA=0.01
# ------------------------------
# HELPERS
# ------------------------------
run_sts_for_source () {
  local source="$1"   # qse or system
  local input_dir="${INPUT_BASE}/${source}"
  local out_dir="${OUT_BASE}/${source}"
  local data_dir="${STS_DIR}/data"
  local experiments_dir="${STS_DIR}/experiments"

  if [[ ! -d "$STS_DIR" ]]; then
    echo "❌ STS directory not found: $STS_DIR"
    echo "Make sure sts-2.1.2 exists and is compiled (make)."
    exit 1
  fi

  if [[ ! -d "$input_dir" ]]; then
    echo "❌ Input directory not found: $input_dir"
    exit 1
  fi

  mkdir -p "$out_dir"
  mkdir -p "$data_dir"

  echo ""
  echo "========================================"
  echo " Running NIST STS for source: $source"
  echo " Input:  $input_dir"
  echo " Output: $out_dir"
  echo "========================================"

  # Clean STS data folder
  rm -f "${data_dir}/"*

  # Copy .bin sequences into STS data folder
  cp "$input_dir"/*.bin "$data_dir"/

  # Clean previous experiments
  rm -rf "$experiments_dir"
  mkdir -p "$experiments_dir"

  # ---- Build STS interactive config in one shot ----
  # Explanation:
  # 0  => input file format = binary file
  # 0  => read from files in data/ directory
  # 1  => include all tests
  # 0  => do not ask for individual test selection
  # 0  => default parameters
  # ALPHA => significance level
  # 1  => run tests
  #
  # assess expects "n" (length bits) as argument.
  #
  echo "▶ Starting STS batch run..."
  (
    cd "$STS_DIR"
    printf "0\n0\n1\n0\n0\n${ALPHA}\n1\n" | ./assess "$SEQ_LENGTH_BITS"
  )

  echo "✅ STS completed."

  # Copy final report + experiments output
  if [[ -f "${STS_DIR}/experiments/AlgorithmTesting/finalAnalysisReport.txt" ]]; then
    cp "${STS_DIR}/experiments/AlgorithmTesting/finalAnalysisReport.txt" "$out_dir"/finalAnalysisReport.txt
  fi

  # Copy everything else for debugging/tracking
  cp -r "${STS_DIR}/experiments" "$out_dir"/

  echo "📄 Report copied to: $out_dir/finalAnalysisReport.txt"
  echo "📁 Full output copied to: $out_dir/experiments"
}

# ------------------------------
# MAIN
# ------------------------------
echo "🚀 Running STS on QSE entropy..."
run_sts_for_source "qse"

echo "🚀 Running STS on System entropy..."
run_sts_for_source "system"

echo ""
echo "✅ All done."
echo "Results are in: $OUT_BASE"