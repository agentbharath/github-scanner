# 🔍 GitHub Health Scanner

**Point it at any GitHub repo and get a complete health report — dead code, stale branches, missing docs, security risks — grounded in evidence, not guesses.**

An agentic RAG system that scans public GitHub repositories across 5 health dimensions and produces an actionable report with file-level citations and priority fixes. Every finding traces back to a retrieved source — not the LLM's opinion.

---

## What Makes This Different?

| Existing Tool | What It Misses | Our Advantage |
|---|---|---|
| Dependabot | No code quality, no hygiene, no reasoning | Holistic reasoning across all dimensions |
| CodeClimate | No security, no RAG grounding, no citations | RAG-grounded evidence for every finding |
| SonarQube | No LLM reasoning, no deprecation detection | Agent reasons about findings, not just flags |
| GitHub Insights | No security, no code quality analysis | All 5 dimensions in one pass |

**Key differentiator:** Cross-signal reasoning. When we find a critical CVE in a package AND the repo has no tests AND no CI/CD, we don't just list three separate issues — we reason about the combined risk and explain why the combination is dangerous.

---

## 5 Health Dimensions

| Dimension | What It Checks | Severity |
|---|---|---|
| 🔴 Security | Hardcoded secrets, vulnerable dependencies, exposed API keys, committed .env files | Critical |
| 🔵 Deprecations | Outdated dependencies, deprecated APIs, migration paths needed | High |
| 🟡 Code Quality | Unused imports, dead functions, missing docstrings, PEP 8 violations | Medium |
| 🟠 Documentation | Missing README, LICENSE, undocumented functions | Medium |
| 🟢 Repo Hygiene | Stale branches, no CI/CD, no .gitignore, no test directory | Low |

---

## Architecture

```
User Input: GitHub repo URL
    ↓
scan_structure()        → repo metadata, README, CI, branches, secrets
    ↓
scan_code_quality()     → unused imports, dead functions (Python repos)
    ↓
check_vulnerabilities() → CVE matches from RAG index
    ↓
check_deprecations()    → deprecated deps from changelog index
    ↓
generate_health_report() → prioritized report with citations + health score
```

**This is a true ReAct agent**, not a fixed pipeline. The tools called depend on what the agent discovers at runtime:
- No `requirements.txt` found → skip vulnerability and deprecation checks
- No Python files found → skip code quality scan
- Repo last committed 3 years ago → escalate hygiene severity

---

## Health Score

Each dimension is scored 0-100, then weighted:

| Dimension | Weight |
|---|---|
| Security | 0.40 |
| Code Quality | 0.20 |
| Repo Hygiene | 0.15 |
| Deprecations | 0.15 |
| Documentation | 0.10 |

**Final Score = Σ (weight × dimension score)**

---

## Tech Stack

- **Agent Framework:** LangChain ReAct Agent
- **Vector Store:** ChromaDB (3 collections: security, pep, github)
- **Embeddings:** OpenAI text-embedding-3-small
- **LLM:** OpenAI GPT-4
- **Frontend:** Streamlit
- **APIs:** GitHub REST API

---

## RAG Knowledge Base

| Source | What It Covers | Used By |
|---|---|---|
| CVE/NVD Database | Known vulnerabilities for top 50 Python packages | `check_vulnerabilities` |
| PyPI Security Advisories | Package-specific vulnerability data with fix versions | `check_vulnerabilities` |
| PEP Standards (8, 257, 20) | Python coding standards and conventions | `scan_code_quality` |
| GitHub Best Practices | Repository structure, CI/CD, security, documentation guidelines | `scan_structure` |
| PyPI Changelogs | Deprecated APIs, breaking changes (fetched on-the-fly) | `check_deprecations` |

---

## Project Structure

```
GithubScanner/
├── .env                          # API keys (not committed)
├── .gitignore
├── config.py                     # Model name, chunk size, chunk overlap
├── chromaStore/                   # ChromaDB persistent storage
├── app.py                        # Streamlit UI
├── agent.py                      # LangChain ReAct agent
├── ingest.py                     # Parse, chunk, embed, store in ChromaDB
├── raw_docs/                     # Pre-scraped source files
│   ├── cve.txt
│   ├── pypi_advisories.txt
│   ├── pep_standards.txt
│   └── github_best_practices.txt
├── tools/
│   ├── scan_structure.py         # GitHub API: repo metadata + secret scanning
│   ├── scan_code_quality.py      # Python ast: imports, functions, docstrings
│   ├── check_vulnerabilities.py  # RAG query: CVE + PyPI matching
│   ├── check_deprecations.py     # On-the-fly changelog analysis
│   └── generate_health_report.py # Synthesize findings + health score
├── utils/
│   └── collection.py             # ChromaDB client utility
├── README.md
└── requirements.txt
```

---

## Setup

```bash
# Clone the repo
git clone https://github.com/your-username/GithubScanner.git
cd GithubScanner

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Add your OPENAI_API_KEY and GITHUB_TOKEN to .env

# Ingest RAG knowledge base (one-time setup)
python ingest.py

# Run the scanner
streamlit run app.py
```

---

## Current Progress

- [x] Project architecture and folder structure
- [x] RAG knowledge base — 4 sources scraped and indexed into ChromaDB
- [x] `ingest.py` — parser, chunker, embedder, ChromaDB storage
- [x] `scan_structure` — GitHub API integration with 6 check types
  - [x] Tree checks (README, LICENSE, .gitignore, CI/CD, tests, .env)
  - [x] Branch checks (total count, stale branch detection)
  - [x] Commit checks (last commit date, days inactive)
  - [x] Contributor checks (count, contribution breakdown)
  - [x] Secret scanning (pattern matching in config files)
- [ ] `scan_code_quality` — Python AST analysis
- [ ] `check_vulnerabilities` — RAG-powered CVE matching
- [ ] `check_deprecations` — on-the-fly changelog analysis
- [ ] `generate_health_report` — synthesis + health scoring
- [ ] `agent.py` — ReAct agent wiring all tools
- [ ] `app.py` — Streamlit UI
- [ ] Evaluation — Precision@K + A/B test K=3 vs K=5

---

## Evaluation Plan

- **Precision@K** on vulnerability retrieval across 10 repos
- **A/B test:** K=3 vs K=5 retrieval precision/recall trade-off
- **Failure cases** documented with explanations

---

## Roadmap

- Currently supports **Python** repositories
- Adding JavaScript support is a 1-day effort — the architecture is language-agnostic
- Shares RAG infrastructure with PromptAutopsy and PR Reviewer

---

*GitHub Health Scanner — Agentic RAG Portfolio Project | Week 2*