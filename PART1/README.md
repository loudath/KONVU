# Part 1 – JavaScript-Ecosystem Snapshot

## Overview

This analysis focuses on JavaScript-related vulnerabilities disclosed in the last 12 months, providing **Konvu’s application-security engineers** actionable insight for prioritization and triage. 
The pipeline produces a ranked list of GHSA vulnerabilities and highlights risky malicious (MAL) packages.

---

### TO RUN THE PIPELINE

chmod +x run_pipeline.sh
./run_pipeline.sh


## Pipeline Overview

1. **Load Filtered Data**  
   - Reads `osv_summary.csv`, containing OSV vulnerabilities from the last 12 months.
   - Separates **GHSA advisories** from **MAL packages**.

2. **Summarize GHSA Vulnerabilities**  
   - Counts top CWEs.
   - Computes severity distribution.
   - Identifies top affected packages.

3. **Summarize MAL Packages**  
   - Counts affected packages.
   - Flags MAL packages associated with account takeover or compromise.

4. **Score & Rank GHSA Packages**  
   - **Numeric severity:** LOW→3.9, MODERATE→5.5, HIGH→7.5, CRITICAL→9.0.
   - **Weaponization keywords:** `xss`, `prototype pollution`, `path traversal`, `ssrf`, `rce`, `code injection` → 1 if present, 0 if not.
   - **Downloads:** Last-month NPM downloads per package (optional but included if online).
   - **Score formula:**  
     ```
     score = 0.5 * normalized_severity + 0.3 * weapon_keyword + 0.2 * normalized_downloads
     ```
   - Top 20 GHSA packages are sorted by this **priority score**.

5. **Visualization & Reporting in /reports**  
   - Barplot of top 10 packages (`priority_score.png`).
   - Ranked CSV (`konvu_ranked.csv`).
   - Full report with counts, distributions, and recommendations (`osv_analysis_report.txt`).

---


## Vulnerability Prioritization – Reasoning

### Recommended Themes / Issues

Based on the analysis, Konvu should prioritize:

1. **High-severity CWEs:**
   - **XSS (CWE-79)** – common in web apps, easily exploitable.
   - **Prototype Pollution (CWE-1321)** – can lead to unexpected behavior and remote code execution.
   - **Path Traversal (CWE-22)** – allows attackers to read sensitive files.
   - **SSRF (CWE-918)** – can access internal services or bypass network restrictions.
   - **RCE / Code Injection** – enables full system compromise.

2. **Popular packages with high downloads**  
   Packages like `next`, `vite`, `lodash`, `jsonwebtoken` have wide usage, so vulnerabilities here have high impact.

3. **Malicious packages (MAL)**  
   Focus on packages flagged for **account takeover** or **maintainer compromise**, which represent supply-chain risk.

---

### Why This Prioritization

We use a **scoring system** that combines:

- **Severity** (numeric mapping: LOW→3.9, MODERATE→5.5, HIGH→7.5, CRITICAL→9.0)  
  Reflects the potential impact of a vulnerability.

- **Weaponization keywords** (`xss`, `prototype pollution`, `path traversal`, `ssrf`, `rce`, `code injection`)  
  Indicates how easily a vulnerability could be exploited in practice.

- **NPM downloads**  
  Captures the real-world exposure of the affected package.

The **priority score formula** is:  score = 0.5 * normalized_severity + 0.3 * weapon_keyword + 0.2 * normalized_downloads 


- Severity carries the most weight (50%) to focus on **critical impact**.  
- Weaponization keywords add 30% weight to highlight vulnerabilities that are **practical to exploit**.  
- Downloads add 20% weight to account for **reach and exposure**.

This combined score ensures Konvu engineers focus on **high-risk, actionable vulnerabilities first**, balancing severity, exploitability, and exposure.

---

### Customization

The scoring system is **editable directly in the Python script :konvu_part1_priority.py** at the top of the `score_and_rank` function.  
- You can adjust severity mapping, weights, or the list of weaponization keywords to match **Konvu’s risk posture** (conservative vs exposure-centric).





