#!/usr/bin/env python3
"""
konvu_part1_priority.py

Reads a filtered osv_summary.csv (last 12 months) and produces:
  - outputs/konvu_ranked.csv
  - outputs/priority_score.png
  - outputs/osv_analysis_report.txt

Configurable at top of file:
  - scoring weights (W_SEV, W_EXPLOIT, W_EXPOSURE)
  - whether to fetch npm downloads (FETCH_DOWNLOADS)
  - cache file for downloads (DOWNLOADS_CACHE)
  - limits for download lookups to avoid long runs (DOWNLOAD_LOOKUP_LIMIT)
"""

import csv
import json
import math
import os
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import requests
from sklearn.preprocessing import MinMaxScaler
import matplotlib.pyplot as plt

# ---------------- CONFIG (edit here to change scoring policy) ----------------
CSV_FILE = "osv_summary.csv"                  # input (produced by extract script)
OUT_DIR = "outputs"                           # outputs folder (will be created)
RANKED_FILE = f"{OUT_DIR}/konvu_ranked.csv"
REPORT_FILE = f"{OUT_DIR}/osv_analysis_report.txt"
PNG_FILE = f"{OUT_DIR}/priority_score.png"
DOWNLOADS_CACHE = "analysis/downloads_cache.json"  # cache location (kept in repo)

# Scoring weights (must sum to 1; they will be normalized if not)
W_SEV = 0.60
W_EXPLOIT = 0.30
W_EXPOSURE = 0.10

TOP_N = 20
FETCH_DOWNLOADS = True        # set False for fastest run (no network calls)
THREADS = 8                  # parallel fetch workers
DOWNLOAD_TIMEOUT = 3.0       # seconds per request
MAX_RETRIES = 2
BACKOFF_BASE = 1.5
DOWNLOAD_LOOKUP_LIMIT = 200  # limit how many distinct packages to query downloads for

# Weapon keyword weights (substring matching; higher => more weaponizable)
WEAP_KEYWORDS = {
    "rce": 1.00,
    "remote code execution": 1.00,
    "command injection": 0.98,
    "sql injection": 0.95,
    "sqli": 0.95,
    "code injection": 0.95,
    "prototype pollution": 0.90,
    "privilege escalation": 0.90,
    "ssrf": 0.85,
    "server side request forgery": 0.85,
    "path traversal": 0.80,
    "local file inclusion": 0.80,
    "lfi": 0.80,
    "xss": 0.60,
    "cross-site scripting": 0.60,
    "dom-based xss": 0.60,
    "authentication bypass": 0.70,
    "denial of service": 0.35,
    "dos": 0.35,
    "information disclosure": 0.30,
}

# severity textual -> CVSS approximations (0-10)
SEV_TO_CVSS = {
    "LOW": 2.5,
    "MODERATE": 5.5,
    "MEDIUM": 5.5,
    "HIGH": 8.0,
    "CRITICAL": 9.5
}

# ---------------- helper I/O ----------------
def read_csv_rows(path):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"{path} not found. Run extract_osv.py first.")
    rows = []
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows

# ---------------- severity parsing ----------------
def parse_severity_to_cvss(sev_field):
    if not sev_field:
        return None
    s = str(sev_field).strip()
    try:
        v = float(s)
        if 0 <= v <= 10:
            return v
    except Exception:
        pass
    s_up = s.upper()
    for k, vv in SEV_TO_CVSS.items():
        if k in s_up:
            return vv
    return None

# ---------------- weaponization scoring ----------------
def compute_weapon_score(text):
    if not text:
        return 0.0
    t = text.lower()
    matched = []
    for kw, w in WEAP_KEYWORDS.items():
        if kw in t:
            matched.append(w)
    if not matched:
        return 0.0
    return min(1.0, max(matched))

# ---------------- downloads cache + fetching ----------------
def load_downloads_cache():
    p = Path(DOWNLOADS_CACHE)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_downloads_cache(cache):
    p = Path(DOWNLOADS_CACHE)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cache, indent=2), encoding="utf-8")

def fetch_download_count_once(pkg):
    url = f"https://api.npmjs.org/downloads/point/last-month/{pkg}"
    attempt = 0
    while attempt <= MAX_RETRIES:
        try:
            r = requests.get(url, timeout=DOWNLOAD_TIMEOUT)
            if r.status_code == 200:
                return int(r.json().get("downloads", 0))
            if r.status_code == 429:
                time.sleep((BACKOFF_BASE ** attempt) * 0.5)
            else:
                return 0
        except Exception:
            time.sleep((BACKOFF_BASE ** attempt) * 0.3)
        attempt += 1
    return 0

def fetch_downloads_parallel(pkgs, threads=THREADS, limit=DOWNLOAD_LOOKUP_LIMIT):
    cache = load_downloads_cache()
    # reduce pkgs to first 'limit' most frequent
    if len(pkgs) > limit:
        pkgs = pkgs[:limit]
    to_fetch = [p for p in pkgs if p not in cache]
    if not to_fetch:
        return {p: cache.get(p, 0) for p in pkgs}
    print(f"[INFO] Fetching downloads for {len(to_fetch)} packages (parallel {threads}) — first run may take some time")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(fetch_download_count_once, p): p for p in to_fetch}
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                val = fut.result()
            except Exception:
                val = 0
            cache[p] = val
    save_downloads_cache(cache)
    return {p: cache.get(p, 0) for p in pkgs}

# ---------------- core scoring pipeline ----------------
def score_rows(rows, w_sev, w_exploit, w_exposure, fetch_downloads):
    ghsa_rows = [r for r in rows if r.get("type","").upper() == "GHSA"]
    if not ghsa_rows:
        return pd.DataFrame()
    df = pd.DataFrame(ghsa_rows)
    df["summary"] = df.get("summary","").fillna("")

    # severity -> numeric CVSS
    df["cvss_raw"] = df["severity"].apply(parse_severity_to_cvss)
    median_cvss = np.nanmedian(df["cvss_raw"].astype(float)) if not df["cvss_raw"].isnull().all() else 5.5
    df["cvss"] = df["cvss_raw"].fillna(median_cvss)

    # weaponization score
    df["weap_score"] = df["summary"].apply(compute_weapon_score)

    # downloads/exposure (limit to top packages by frequency to keep time bounded)
    pkgs = list(df["package"].value_counts().index)  # ordered by frequency
    downloads_map = {p: 0 for p in pkgs}
    if fetch_downloads and pkgs:
        downloads_map = fetch_downloads_parallel(pkgs)

    df["downloads"] = df["package"].map(downloads_map).fillna(0)
    df["downloads_log"] = df["downloads"].apply(lambda x: math.log1p(x))

    # normalize axes
    scaler = MinMaxScaler()
    norm_cols = df[["cvss", "weap_score", "downloads_log"]].astype(float).fillna(0)
    scaled = scaler.fit_transform(norm_cols)
    df[["sev_norm", "weap_norm", "exp_norm"]] = scaled

    # combined score
    df["score"] = w_sev * df["sev_norm"] + w_exploit * df["weap_norm"] + w_exposure * df["exp_norm"]

    # aggregate per package (take highest scoring advisory per package)
    agg = df.sort_values("score", ascending=False).groupby("package", as_index=False).first()
    agg = agg.sort_values("score", ascending=False)
    return agg

# ---------------- outputs ----------------
def generate_outputs(rows, w_sev, w_exploit, w_exposure, top_n, fetch_downloads, ranked_file, report_file, png_file):
    Path(OUT_DIR).mkdir(parents=True, exist_ok=True)
    agg = score_rows(rows, w_sev, w_exploit, w_exposure, fetch_downloads)
    if agg.empty:
        print("[WARN] No GHSA entries found in CSV")
        return
    top = agg.head(top_n)
    top.to_csv(ranked_file, index=False)

    plt.figure(figsize=(10, max(4, top_n//2)))
    plt.barh(top["package"].iloc[::-1], top["score"].iloc[::-1])
    plt.xlabel("Priority score (0-1)")
    plt.title(f"Konvu priority short-list (top {top_n})")
    plt.tight_layout()
    plt.savefig(png_file, dpi=300)
    plt.close()

    ghsa = [r for r in rows if r.get("type","").upper() == "GHSA"]
    mal = [r for r in rows if r.get("type","").upper() == "MAL"]
    cwe_counter = Counter()
    for r in ghsa:
        for c in (r.get("cwe") or "").split(","):
            c = c.strip()
            if c:
                cwe_counter[c] += 1
    severity_counter = Counter([r.get("severity") or "UNKNOWN" for r in ghsa])
    mal_counter = Counter([r.get("package") for r in mal])

    with open(report_file, "w", encoding="utf-8") as f:
        f.write("JavaScript OSV snapshot — automated analysis (last 12 months)\n\n")
        f.write(f"Total GHSA entries: {len(ghsa)}\n")
        f.write(f"Total MAL entries: {len(mal)}\n\n")
        f.write("Top CWEs (GHSA):\n")
        for k, v in cwe_counter.most_common(12):
            f.write(f"  {k}: {v}\n")
        f.write("\nSeverity distribution (GHSA):\n")
        for k, v in severity_counter.most_common():
            f.write(f"  {k}: {v}\n")
        f.write("\nTop MAL packages (sample):\n")
        for k, v in mal_counter.most_common(10):
            f.write(f"  {k}: {v}\n")
        f.write("\nTop Konvu ranked short-list (package, score, severity, downloads):\n")
        for _, r in top.iterrows():
            f.write(f"{r['package']:<30} {r['score']:.3f}  sev={r.get('severity','')!s:8} downloads={int(r.get('downloads',0)):,}\n")
        f.write("\nRecommendations:\n")
        f.write(" - Treat packages scoring in top 5 or score >= 0.80 as P0 — immediate triage and hotfix.\n")
        f.write(" - Focus on RCE/SQLi/Prototype Pollution/SSRF variants first; they have highest exploitability.\n")
        f.write(" - Track MAL packages with downloads closely; if maintainer changes or sudden publish spikes occur, block.\n")
        f.write(" - Automate this pipeline and re-run monthly; keep downloads_cache.json alongside repo.\n")

    print(f"[OK] Wrote: {ranked_file}, {png_file}, {report_file}")

# ---------------- main ----------------
def main():
    # normalize weights to sum=1
    total = W_SEV + W_EXPLOIT + W_EXPOSURE
    if not math.isclose(total, 1.0):
        w_sev = W_SEV / total
        w_exploit = W_EXPLOIT / total
        w_exposure = W_EXPOSURE / total
    else:
        w_sev, w_exploit, w_exposure = W_SEV, W_EXPLOIT, W_EXPOSURE

    rows = read_csv_rows(CSV_FILE)
    generate_outputs(rows, w_sev, w_exploit, w_exposure, TOP_N, FETCH_DOWNLOADS, RANKED_FILE, REPORT_FILE, PNG_FILE)

if __name__ == "__main__":
    main()
