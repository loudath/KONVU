#!/usr/bin/env bash
set -e

# 1️⃣ Download and unzip OSV data
echo "[*] Downloading OSV npm data..."
wget -c https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
mkdir -p all_json
echo "[*] Unzipping data into ./all_json..."
unzip -o all.zip -d all_json

# 2️⃣ Create virtual environment
echo "[*] Setting up Python virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

# 3️⃣ Install required Python packages
echo "[*] Installing required Python packages..."
pip install --upgrade pip
pip install pandas requests tqdm numpy matplotlib seaborn scikit-learn

# 4️⃣ Run extraction script
echo "[*] Extracting OSV data..."
python extract_osv.py

# 5️⃣ Run priority scoring / report script
echo "[*] Generating priority scores and report..."
python konvu_part1_priority.py

# 6️⃣ Move all outputs to /outputs
mkdir -p outputs
mv osv_summary.csv konvu_ranked.csv priority_score.png osv_analysis_report.txt outputs/

echo "[*] Pipeline finished! Outputs:"
echo " - Summary CSV: osv_summary.csv"
echo " - Ranked CSV: konvu_ranked.csv"
echo " - Priority chart: priority_score.png"
echo " - Report: osv_analysis_report.txt"
