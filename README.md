# 🔍 GitHub Health Scanner

**Point it at any GitHub repo and get a complete health report — dead code, stale branches, missing docs, security risks — grounded in evidence, not guesses.**

An AI-powered GitHub Risk & Readiness Advisor that scans public GitHub repositories across 5 health dimensions and produces an actionable report with file-level citations, cross-signal reasoning, and priority fixes. Every finding traces back to a retrieved source — not the LLM's opinion.

---

## 🎯 What Makes This Different?

Most tools scan in silos. Dependabot checks dependencies. CodeClimate checks style. SonarQube runs static analysis. **None of them reason across dimensions.**

This tool does. When it finds a critical CVE in Flask 1.0.2 AND the repo has no CI/CD pipeline AND no tests, it doesn't list three separate issues — it reasons:

> *"This repo has a critical vulnerability in Flask 1.0.2 AND no CI/CD pipeline, making upgrades riskier since there are no automated tests to catch regressions."*

| Existing Tool | What It Misses | Our Advantage |
|---|---|---|
| Dependabot | No code quality, no hygiene, no reasoning | Cross-signal reasoning across all dimensions |
| CodeClimate | No security, no RAG grounding, no citations | RAG-grounded evidence for every finding |
| SonarQube | No LLM reasoning, no deprecation detection | Agent reasons about findings, not just flags |
| GitHub Insights | No security, no code quality analysis | All 5 dimensions in one pass |

---

## 📊 5 Health Dimensions

| Dimension | Weight | What It Checks |
|---|---|---|
| 🛡️ **Security** | 40% | Hardcoded secrets, committed .env files, CVE vulnerabilities |
| 💻 **Code Quality** | 20% | Unused imports, dead functions, cyclomatic complexity, nesting depth |
| 📄 **Documentation** | 10% | README, LICENSE, PEP 257 docstrings |
| 🧹 **Repo Hygiene** | 15% | CI/CD config, test directory, .gitignore, stale branches |
| 📦 **Deprecations** | 15% | Outdated packages, unmaintained dependencies |

Each dimension scored 0–100. Final health score = weighted sum.

---

## 🏗️ Architecture

```
User Input: GitHub repo URL
    ↓
┌─────────────────────────────────────────┐
│           ReAct Agent (LLM)             │
│   Decides which tools to call based     │
│   on what it discovers at runtime       │
└────────────┬────────────────────────────┘
             ↓
    scan_structure()        → GitHub API: repo metadata, secrets
             ↓
    scan_code_quality()     → Python AST: imports, functions, complexity
             ↓
    check_vulnerabilities() → ChromaDB RAG: CVE + PyPI advisory matching
             ↓
    check_deprecations()    → PyPI API: version gaps, maintenance status
             ↓
    generate_health_report() → LLM synthesis with RAG context + scoring
             ↓
    Streamlit UI            → Color-coded report with PDF download
```

### Why This Is Truly Agentic

The tools called depend on what the agent discovers at runtime:

- **No Python files found** → skips `scan_code_quality`
- **No requirements.txt** → skips `check_vulnerabilities` and `check_deprecations`
- **Skipped checks** are reported honestly as "not tested" with score of 50/100

This is dynamic tool selection — not a fixed pipeline with a different name.

---

## 🖥️ Demo

### Scanning Our Own Repo (75.45/100 — Moderate)

| Dimension | Score | Status |
|---|---|---|
| 🛡️ Security | 85/100 | Healthy |
| 💻 Code Quality | 77/100 | Moderate |
| 📄 Documentation | 43/100 | At Risk |
| 🧹 Repo Hygiene | 50/100 | At Risk |
| 📦 Deprecations | 95/100 | Healthy |

**Key Findings:**
- 🟠 [HIGH] Vulnerable `requests` package — CVE-2014-1830 allows sensitive info leak via Proxy-Authorization header
- 🟡 [MEDIUM] Missing LICENSE file — code under exclusive copyright by default
- 🟡 [MEDIUM] No CI/CD configuration — no automated verification of code changes
- 🟡 [MEDIUM] Unused imports across 7 files with specific line numbers cited
- 🟡 [MEDIUM] Missing docstrings in 18 functions across 8 files

**Cross-Signal Insight:** *"The repository has vulnerabilities in the requests package and lacks CI/CD configuration, increasing the risk of deploying insecure code without automated checks."*

### Scanning an Intentionally Unhealthy Repo (35.2/100 — Unhealthy)

| Dimension | Score | Status |
|---|---|---|
| 🛡️ Security | 0/100 | Unhealthy |
| 💻 Code Quality | 92/100 | Healthy |
| 📄 Documentation | 3/100 | Unhealthy |
| 🧹 Repo Hygiene | 25/100 | Unhealthy |
| 📦 Deprecations | 85/100 | Healthy |

**Deployment Risk:** *"HIGH RISK: Critical security vulnerabilities including hardcoded API keys and passwords, outdated dependencies with known CVEs (Flask 1.0.2, PyYAML 5.1), and no CI/CD or tests."*

---

## 📈 Evaluation Results

### Precision@K — A/B Test: K=3 vs K=5

| Metric | K=3 | K=5 |
|---|---|---|
| Precision | 0.93 | 0.92 |
| Recall | 0.40 | 0.66 |
| F1 Score | 0.56 | 0.76 |

**Conclusion:** K=5 selected. Precision remains nearly identical (1% drop) 
while recall improves by 65%. F1 jumps from 0.56 to 0.76, confirming K=5 
as the better retrieval setting.


**Why not K=10?** Diminishing returns — more results mean more tokens sent to the LLM with marginal relevance gain, increasing cost and latency.

### Failure Cases

1. **CVE data noise:** The NVD keyword search for "python requests" returns CVEs mentioning both words anywhere in the description (e.g., PyDNS CVEs tagged under "requests"). Mitigated by filtering entries where package name doesn't appear in the CVE description during ingestion.

2. **flaskcode vs flask:** CVE-2023-52288 about the `flaskcode` package gets matched under `flask` because the package metadata from scraping filed it under "flask". This is a data quality issue from the NVD keyword search, not a retrieval failure.

3. **CVSS vector parsing:** Some PyPI advisories return raw CVSS vectors (`CVSS:3.1/AV:N/AC:L/...`) instead of human-readable severity labels. Normalized using the `cvss` Python library to convert vectors to standard severity levels.

---

## 🔧 Tech Stack

| Component | Technology |
|---|---|
| Agent Framework | LangChain ReAct Agent |
| Vector Store | ChromaDB (3 collections: security, pep, github) |
| Embeddings | OpenAI text-embedding-3-small |
| LLM | OpenAI GPT-4 |
| Code Analysis | Python `ast` module |
| APIs | GitHub REST API, PyPI JSON API |
| Frontend | Streamlit |

---

## 📚 RAG Knowledge Base

| Source | Collection | Used By | Documents |
|---|---|---|---|
| CVE/NVD Database | security | `check_vulnerabilities` | Top 50 Python packages |
| PyPI Security Advisories (OSV.dev) | security | `check_vulnerabilities` | Package-specific advisories |
| PEP Standards (8, 257, 20) | pep | `scan_code_quality` | Style, docstring, Zen of Python |
| GitHub Best Practices | github | `generate_health_report` | Repo structure, CI/CD, security |
| PyPI Changelogs | — | `check_deprecations` | Fetched on-the-fly per package |

**Chunking:** RecursiveCharacterTextSplitter, chunk size 512, overlap 50.

**RAG query strategy:** Conditional queries — only query for issues that were actually found. One query per issue type, not per individual finding.

---

## 📁 Project Structure

```
GithubScanner/
├── .env                          # API keys (not committed)
├── .gitignore
├── config.py                     # Model name, chunk size, embedding config
├── chromaStore/                   # ChromaDB persistent storage
├── app.py                        # Streamlit UI
├── agent.py                      # LangChain ReAct agent + tool wiring
├── ingest.py                     # Parse, chunk, embed, store in ChromaDB
├── generate_health.py            # RAG context + LLM synthesis + scoring
├── evaluation.py                 # Precision@K, Recall, F1 evaluation
├── utils.py                      # Shared GitHub API helpers
├── raw_docs/                     # Pre-scraped source files
│   ├── cve.txt
│   ├── pypi_advisories.txt
│   ├── pep_standards.txt
│   └── github_best_practices.txt
├── scrapers/                     # One-time data collection scripts
│   ├── scrape_all.py
│   ├── scrape_cve.py
│   ├── scrape_pypi_advisories.py
│   ├── scrape_pep.py
│   └── scrape_github_practices.py
├── scan_structure.py             # GitHub API: tree, branches, commits, secrets
├── scan_code_quality.py          # Python AST: imports, functions, complexity
├── check_vulnerabilities.py      # ChromaDB RAG: CVE + PyPI matching
├── README.md
└── requirements.txt
```

---

## 🚀 Setup

### Prerequisites
- Python 3.9+
- OpenAI API key
- GitHub personal access token

### Installation

```bash
# Clone the repo
git clone https://github.com/agentbharath/github-scanner.git
cd GithubScanner

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Add your OPENAI_API_KEY and GITHUB_TOKEN to .env
```

### First Run

```bash
# Step 1: Scrape data sources (one-time, ~10 minutes)
cd scrapers
python scrape_all.py
cd ..

# Step 2: Ingest into ChromaDB (one-time)
python ingest.py

# Step 3: Run the scanner
streamlit run app.py
```

### Run Evaluation

```bash
python evaluation.py
```

---

## ⚖️ Health Score Calculation

**Formula:** `Score = Σ (weight × dimension_score)`

### Scoring Rules

**Security (0-100):**
- Secrets found: -30
- .env committed: -20
- Each critical vulnerability: -15
- Each high vulnerability: -10
- Each medium: -5, each low: -2

**Code Quality (0-100):**
- Unused imports: max -16 (1 per import)
- Dead functions: max -16 (1 per function)
- Missing docstrings: max -4 (1 per docstring)
- High complexity (>10): max -16
- Deep nesting (>4): max -16
- Too many params (>5): max -16
- Long functions (>50 lines): max -16

**Documentation (0-100):**
- No README: -40
- No LICENSE: -40
- Missing docstrings: max -20 (1 per docstring)

**Repo Hygiene (0-100):**
- No .gitignore: -25
- No CI/CD: -25
- No test directory: -25
- Stale branches: -12.5
- Inactive commits (>365 days): -12.5

**Deprecations (0-100):**
- Outdated packages: max -50 (5 per package)
- Unmaintained packages: max -50 (5 per package)

Python calculates all scores deterministically. The LLM generates findings, evidence, and recommendations — never the numbers.

---

## 🔮 Roadmap

- **Currently supports Python.** Adding JavaScript is a 1-day effort — the architecture is language-agnostic. Only `scan_code_quality` needs a per-language implementation.
- **PDF report download** — export full report as downloadable PDF
- **Dangerous function detection** — flag `eval()`, `exec()`, `os.system()` calls
- **Multi-language support** — JavaScript (ESLint/tree-sitter), Go, Java
- **Shares RAG infrastructure** with PromptAutopsy and PR Reviewer

---


**Why build this?**
> "GitHub has Dependabot and CodeClimate, but nothing that reasons holistically across security, code quality, docs, and hygiene in one pass and grounds every finding in evidence. I built the RAG + ReAct layer those tools are missing."

**Why is this agentic and not just a pipeline?**
> "The tools called depend on what the agent discovers. A repo without Python files skips code quality. A repo without requirements.txt skips vulnerability checks. The agent reasons about which tools are relevant at runtime."

**What did you measure?**
> "I ran an A/B test comparing K=3 vs K=5 retrieval on vulnerability detection. K=5 achieved 0.67 F1 vs 0.46 for K=3, with perfect precision for both. I documented failure cases — like CVE data noise from NVD keyword search producing false matches."

**How does RAG add value over just calling an LLM?**
> "Without RAG, the LLM would guess about vulnerabilities. With RAG, every finding cites a real CVE ID with affected versions and fix versions. The LLM synthesizes — it doesn't fabricate."

---

*GitHub Health Scanner — Agentic RAG Portfolio Project*