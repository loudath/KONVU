# JavaScript Vulnerability Analysis & Verification Assignment

This repository contains the deliverables for the assignment, covering two main parts:

1. **Part 1 – JavaScript-Ecosystem Snapshot**  
2. **Part 2 – Verification Blueprint**

Each part has its own folder with scripts and reports, while this README provides an overview, explains the rationale, and describes AI usage.

---

## Assignment Overview

The goal of this project was to explore recent JavaScript vulnerabilities, identify actionable patterns, and design a reproducible verification procedure for a specific advisory affecting the OWASP Juice Shop.

---

## Part 1 – JavaScript-Ecosystem Snapshot

**Objective:** Pull every JavaScript-related vulnerability disclosed in the last 12 months from OSV, analyze patterns, and recommend which issues Konvu should prioritize.

**Approach:**

- Used automated scripts to fetch and parse OSV data.  
- Performed quick analysis to detect recurring themes (e.g., dependency chains, regex-related vulnerabilities, input validation issues).  
- Highlighted vulnerabilities that are most likely to impact real-world projects based on frequency, severity, and exploitability.  

**Deliverables:**  

- Scripts/notebooks used to fetch and analyze vulnerabilities.  
- A brief report summarizing findings and recommendations.  

**Key Thoughts:**  

- Regular expressions and serialization issues appear frequently and have high impact.  
- Dependency updates and patching cadence are critical for mitigating common JavaScript vulnerabilities.  
- Prioritization should focus on patterns that are reproducible, high-risk, and relevant to Konvu’s ecosystem.

---

## Part 2 – Verification Blueprint

**Objective:** Draft a reproducible plan to verify if the OWASP Juice Shop codebase is affected by advisory GHSA-87vv-r9j6-g5qv.

**Approach:**

- Designed step-by-step procedures, including setup of test scripts and timing analysis.  
- Scripts are self-contained and log outputs for easy validation.  
- Verified performance and vulnerability patterns systematically.  

**Deliverables:**  


- Step-by-step procedure documented in Markdown, suitable for another engineer to follow.

---

## AI Tools Usage

AI tools were leveraged throughout the project to:

- Suggest payloads and test patterns for Part 1 and Part 2.  
- Generate scripts and correct syntax for timing-sensitive tests.  
- Assist in interpreting results, spotting potential edge cases, and documenting the procedure clearly.  

**Note:** AI was used as an assistant to accelerate development and ensure correctness, but all analysis and final decisions were manually validated.

---

## Rationale & Thought Process

- **Clarity:** Designed scripts and procedures to be reproducible by another engineer.  
- **Automation:** Reduced repetitive steps with scripts and logging.  
- **Modularity:** Each part is independent but can be combined for full analysis.  
- **AI-assisted but human-verified:** AI accelerated work without replacing reasoning or validation.  

---


