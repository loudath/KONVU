#!/usr/bin/env python3
import os
import json
from datetime import datetime, timedelta
from collections import Counter
import csv

def load_osv_jsons(folder, months=12):
    cutoff_date = datetime.now() - timedelta(days=months*30)
    ghsa_list, mal_list = [], []
    for file in os.listdir(folder):
        if not file.endswith(".json"):
            continue
        path = os.path.join(folder, file)
        with open(path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print(f"Skipping invalid JSON: {file}")
                continue
        pub_date = data.get("published")
        if not pub_date:
            continue
        pub_dt = datetime.fromisoformat(pub_date.replace("Z",""))
        if pub_dt < cutoff_date:
            continue
        if file.startswith("GHSA"):
            ghsa_list.append(data)
        elif file.startswith("MAL"):
            mal_list.append(data)
    return ghsa_list, mal_list

def extract_ghsa_info(ghsa_list):
    extracted = []
    for g in ghsa_list:
        pkg = g['affected'][0]['package']['name']
        severity = g['database_specific'].get('severity')
        cwe = ", ".join(g['database_specific'].get('cwe_ids', []))
        published = g.get('published')
        summary = g.get('summary')
        extracted.append({
            "package": pkg,
            "type": "GHSA",
            "cwe": cwe,
            "severity": severity,
            "published": published,
            "summary": summary
        })
    return extracted

def extract_mal_info(mal_list):
    extracted = []
    for m in mal_list:
        pkg = m['affected'][0]['package']['name']
        published = m.get('published')
        details = m.get('details')
        extracted.append({
            "package": pkg,
            "type": "MAL",
            "cwe": "",
            "severity": "",
            "published": published,
            "summary": details
        })
    return extracted

def summarize_and_save(data, output_csv="osv_summary.csv"):
    keys = ["package", "type", "cwe", "severity", "published", "summary"]
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    print(f"Saved summary to {output_csv}")

def main():
    folder = os.path.join(os.getcwd(), "all_json")
    ghsa_list, mal_list = load_osv_jsons(folder, months=12)
    ghsa_data = extract_ghsa_info(ghsa_list)
    mal_data = extract_mal_info(mal_list)
    all_data = ghsa_data + mal_data
    summarize_and_save(all_data)

    # quick analysis
    cwe_counter = Counter([d["cwe"] for d in ghsa_data if d["cwe"]])
    severity_counter = Counter([d["severity"] for d in ghsa_data if d["severity"]])
    print("Top CWEs:", cwe_counter.most_common(10))
    print("Severity distribution:", severity_counter)
    print("Total GHSA:", len(ghsa_data))
    print("Total MAL:", len(mal_data))

if __name__ == "__main__":
    main()
