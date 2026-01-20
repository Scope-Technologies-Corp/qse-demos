# NIST STS (SP 800-22) Entropy Evaluation Pipeline — QSE vs System

This workflow generates entropy streams (**QSE entropy** + **system/local entropy**), runs the **NIST Statistical Test Suite (STS 2.1.2)**, parses `finalAnalysisReport.txt`, compares results, and produces a **professional investor/compliance scorecard HTML report**.

✅ You are using the **manual `./assess` workflow**, because STS is interactive and automation via `run_sts.sh` often breaks.

---

## ✅ What You Already Have Working

- `generate_entropy.py` ✅ generates `.bin` sequences for QSE and system
- `./assess` ✅ runs NIST STS successfully
- You have:
  - `finalAnalysisReport.txt`
  - `report.json`
  - `report.csv`

So the remaining steps are:

1) Compare QSE vs system (`compare_sts_results.py`)  
2) Generate scorecard (`generate_scorecard.py`)  
3) Render investor report (`render_scorecard_html.py`)  
4) Export PDF (Chrome print)

---

# 1) Folder Structure (Expected)

```text
sts-2.1.2/
├─ assess                          # compiled STS binary
├─ data/                           # STS input data files (combined .bin)
│  ├─ qse_all.bin
│  └─ system_all.bin
├─ entropy-streams/                # generated entropy sequences (.bin)
│  ├─ qse/
│  │  ├─ seq_0001_1000000bits.bin
│  │  ├─ ...
│  └─ system/
│     ├─ seq_0001_1000000bits.bin
│     ├─ ...
├─ sts-results/
│  ├─ qse/
│  │  ├─ finalAnalysisReport.txt
│  │  ├─ report.json
│  │  └─ report.csv
│  ├─ system/
│  │  ├─ finalAnalysisReport.txt
│  │  ├─ report.json
│  │  └─ report.csv
│  ├─ compare.json
│  ├─ scorecard.json
│  └─ scorecard.html
├─ templates/
│  └─ scorecard_template.html
├─ generate_entropy.py
├─ parse_sts_report.py
├─ compare_sts_results.py
├─ generate_scorecard.py
├─ render_scorecard_html.py
└─ README.md
```

---

# 2) What Each Script Does

## ✅ `generate_entropy.py`
Generates entropy sequences in **binary `.bin` format** suitable for STS.

### What it does
- Calls entropy API endpoint OR uses system RNG (`secrets.token_bytes()`)
- Generates **N sequences**, each of **seq-length bits**
- Writes one `.bin` file per sequence

### Why `.bin` is preferred over ASCII `0/1`
- Smaller file size (8x smaller than ASCII bits)
- Faster read/write
- Avoids newline/format issues
- STS supports binary mode directly

### Outputs
- `entropy-streams/qse/*.bin`
- `entropy-streams/system/*.bin`

---

## ✅ `parse_sts_report.py`
Parses **STS output report** `finalAnalysisReport.txt`.

### What it extracts
- Table: `P-VALUE`, `PROPORTION`, and test name for each test

### Output files
- `report.json` → structured parsed data (used for comparisons & scorecard)
- `report.csv` → spreadsheet version for auditors/investors

---

## ✅ `compare_sts_results.py`
Compares QSE vs System results using both JSON reports.

### Output
- `sts-results/compare.json`

### Includes
- Overall pass count
- Borderline tests (close to minimum pass threshold)
- Uniformity p-value warnings
- Per-test delta (QSE vs System)

---

## ✅ `generate_scorecard.py`
Builds an investor/compliance scorecard JSON.

### Inputs
- `sts-results/qse/report.json`
- `sts-results/system/report.json`
- `sts-results/compare.json`

### Output
- `sts-results/scorecard.json`

### Contents
- Overall verdict
- Score out of 100
- Risk flags (uniformity outliers, borderline tests)
- Executive summary bullets
- Evidence table

---

## ✅ `render_scorecard_html.py`
Renders `scorecard.json` into a **PDF-ready HTML report**.

### Inputs
- `scorecard.json`
- `templates/scorecard_template.html`

### Output
- `sts-results/scorecard.html`

✅ Export to PDF:
- Open in Chrome → Print → Save as PDF

---

# 3) Setup / Install

## Build STS
Inside STS folder:

```bash
make
```

Confirm:
```bash
./assess
```

---

## Python env
```bash
python3 -m venv .env
source .env/bin/activate
pip install requests
```

---

# 4) Full Workflow (Step-by-Step)

---

## Step 1 — Generate entropy streams

Generate 100 sequences, each 1M bits:

```bash
python3 generate_entropy.py --use qse --seq-length 1000000 --sequences 100
python3 generate_entropy.py --use local --seq-length 1000000 --sequences 100
```

✅ Expected file size:
- 1,000,000 bits = 125,000 bytes ≈ 122 KB

---

## Step 2 — Combine into STS input files

STS expects one file containing multiple sequences back-to-back.

QSE:
```bash
cat entropy-streams/qse/*.bin > data/qse_all.bin
```

System:
```bash
cat entropy-streams/system/*.bin > data/system_all.bin
```

✅ Each should be about:
- 100 × 125 KB = ~12.5 MB

---

## Step 3 — Run STS manually (QSE)

```bash
./assess 1000000
```

Then enter:

| Prompt | Value |
|--------|-------|
| Enter Choice | `0` |
| User Prescribed Input File | `data/qse_all.bin` |
| Apply all tests? | `1` |
| Parameter adjustments | `0` |
| How many bitstreams? | `100` |
| Input mode | `1` (Binary) |

After completion:

```bash
mkdir -p sts-results/qse
cp finalAnalysisReport.txt sts-results/qse/finalAnalysisReport.txt
```

---

## Step 4 — Run STS manually (System)

Repeat with:
- `data/system_all.bin`

Then:

```bash
mkdir -p sts-results/system
cp finalAnalysisReport.txt sts-results/system/finalAnalysisReport.txt
```

---

## Step 5 — Parse the reports

QSE:
```bash
python3 parse_sts_report.py --report sts-results/qse/finalAnalysisReport.txt --out sts-results/qse/report.json
```

System:
```bash
python3 parse_sts_report.py --report sts-results/system/finalAnalysisReport.txt --out sts-results/system/report.json
```

This generates:
- `report.json`
- `report.csv`

---

## Step 6 — Compare results

```bash
python3 compare_sts_results.py \
  --qse sts-results/qse/report.json \
  --system sts-results/system/report.json \
  --out sts-results/compare.json
```

---

## Step 7 — Generate scorecard

```bash
python3 generate_scorecard.py \
  --qse sts-results/qse/report.json \
  --system sts-results/system/report.json \
  --compare sts-results/compare.json \
  --out sts-results/scorecard.json
```

---

## Step 8 — Render HTML report

```bash
python3 render_scorecard_html.py \
  --scorecard sts-results/scorecard.json \
  --template templates/scorecard_template.html \
  --out sts-results/scorecard.html
```

Open:
```bash
open sts-results/scorecard.html
```

Export to PDF:
Chrome → Print → Save as PDF

---

# 5) Interpreting Results (Important)

### ✅ Passing proportion requirement:
Minimum pass rate for tests (for 100 sequences) is around:

- **96/100** for most tests
- **57/60** for Random Excursions tests

If any test falls below minimum pass → **entropy generator is suspect**.

---

### ✅ Uniformity p-value:
Should usually be:

- `>= 0.0001`

If very low (like `0.000375`), it may indicate non-uniform distribution and should be flagged for investigation, especially if repeated across runs.

---

# 6) Troubleshooting

### Error: `file 0 could not be opened`
You typed `0` as filename — STS literally tries to open `0`.

Use:
```bash
data/qse_all.bin
```

---

### Error: `LOG FILES COULD NOT BE OPENED`
Usually means missing directories or permission issues.

Fix:
```bash
mkdir -p experiments/AlgorithmTesting results
chmod -R 777 experiments results
```

---

# 7) Deliverables for Investors / Compliance

After running everything, you can share:

✅ `sts-results/scorecard.html`  
✅ `sts-results/scorecard.json`  
✅ `sts-results/qse/report.csv`  
✅ `sts-results/system/report.csv`  
✅ `compare.json`  
✅ `verdict.docx`

---

# 8) Recommended Next Improvements

To improve credibility:

1. Repeat the entire test on different days (reproducibility)
2. Increase sequences:
   - 200 sequences
   - 2,000,000 bits each
3. Add additional randomness batteries:
   - PractRand
   - Dieharder
4. Store run metadata:
   - timestamp
   - endpoint used
   - environment info
   - machine hardware ID

---

# Disclaimer

Passing NIST STS does **not guarantee cryptographic security** — it proves strong statistical randomness properties.

To claim cryptographic-quality entropy, also ensure:
- entropy source reliability and tamper resistance
- no deterministic compression or bias
- continuous runtime monitoring
- secure key generation architecture
