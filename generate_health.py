import json
import ast
from config import config
from langchain.tools import tool
from langchain_chroma import Chroma
from langchain_openai import ChatOpenAI
from langchain.schema import SystemMessage
from langchain_openai import OpenAIEmbeddings
from scan_structure import scan_structure
from scan_code_quality import scan_code_quality
from check_vulnerabilites import scan_vulnerabilities_and_deprecations
from dotenv import load_dotenv
from cvss import CVSS3

load_dotenv()
llm = ChatOpenAI(
    model = config["GPT_MODEL"],
    temperature=0
)

embedding = OpenAIEmbeddings(
    model=config["EMBEDDING_MODEL"]
)

pep_db = Chroma(
    collection_name="pep",
    persist_directory="./chromaStore",
    embedding_function=embedding
)

github_db = Chroma(
    collection_name="github",
    persist_directory="./chromaStore",
    embedding_function=embedding
)

output_example = {
    "repo": "owner/repo",
    "health_score": 62,
    "dimension_scores": {
        "security": {"score": 40, "weight": 0.40, "weighted_score": 16.0},
        "code_quality": {"score": 70, "weight": 0.20, "weighted_score": 14.0},
        "documentation": {"score": 30, "weight": 0.10, "weighted_score": 3.0},
        "repo_hygiene": {"score": 55, "weight": 0.15, "weighted_score": 8.25},
        "deprecations": {"score": 45, "weight": 0.15, "weighted_score": 6.75}
    },
    "findings": [
        {
            "severity": "critical",
            "dimension": "security",
            "title": "Hardcoded API keys in config.py",
            "description": "API_KEY found on line 1 of config.py. Hardcoded secrets in source code can be scraped by bots within minutes of being pushed to a public repository.",
            "evidence": "GitHub best practices state: Never commit secrets, API keys, passwords, or tokens to a repository. Use environment variables or secret management tools instead.",
            "recommendation": "Remove the secret from config.py, rotate the exposed key immediately, and use environment variables or a .env file (added to .gitignore) instead."
        },
        {
            "severity": "high",
            "dimension": "deprecations",
            "title": "Flask 1.0.2 is 35 versions behind latest",
            "description": "Flask 1.0.2 was released on 2018-05-02 and is 2849 days old. The latest version is 3.1.3.",
            "evidence": "CVE-2018-18074: The Requests package before 2.20.0 sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect.",
            "recommendation": "Upgrade Flask to 3.1.3. Review the changelog for breaking changes between 1.x and 3.x."
        },
        {
            "severity": "medium",
            "dimension": "code_quality",
            "title": "3 unused imports across 2 files",
            "description": "os, sys, json imported but never used in app.py.",
            "evidence": "PEP 8 states: Imports should be organized and unused imports removed to keep the namespace clean and improve readability.",
            "recommendation": "Remove unused imports from app.py."
        },
        {
            "severity": "medium",
            "dimension": "documentation",
            "title": "Missing README",
            "description": "No README.md found at root level.",
            "evidence": "Every repository should have a README.md file. A repository without a README creates a barrier for new contributors and users.",
            "recommendation": "Add a README.md with project description, installation instructions, and usage examples."
        },
        {
            "severity": "low",
            "dimension": "repo_hygiene",
            "title": "No CI/CD configuration",
            "description": "No GitHub Actions, Travis CI, or other CI config detected.",
            "evidence": "Repositories should have CI configured. A repository without CI means there is no automated verification that code changes don't break existing functionality.",
            "recommendation": "Add a .github/workflows/ci.yml file with basic test and lint steps."
        }
    ],
    "cross_signal_insights": [
        "This repo has a critical CVE in Flask 1.0.2 AND no CI/CD pipeline, making upgrades riskier since there are no automated tests to catch regressions.",
        "Hardcoded secrets are present AND no .gitignore exists, suggesting secrets were committed accidentally with no protection mechanism in place.",
        "High function complexity in scan_structure (complexity: 12) combined with missing docstrings makes the codebase difficult to maintain and onboard new contributors."
    ],
    "deployment_risk_summary": "HIGH RISK: This repository has critical security vulnerabilities including hardcoded API keys and passwords, outdated dependencies with known CVEs (Flask 1.0.2, PyYAML 5.1), and no CI/CD or tests to verify fixes. Deploying as-is exposes the application to credential theft, remote code execution, and denial of service attacks."
}

def get_github_context(query: str) -> dict:
    output = []
    results = github_db.similarity_search(
        query=query,
        k=3
    )

    for doc in results:
        output.append({
            "content": doc.page_content,
            "source": doc.metadata["source"]
        })
    return output

def get_pep_context(query: str) -> dict:
    output = []
    results = pep_db.similarity_search(
        query=query,
        k=3
    )

    for doc in results:
        output.append({
            "content": doc.page_content,
            "source": doc.metadata["pep_id"]
        })
    return output


def get_rag_context(structure_findings: dict, code_quality_findings: list) -> dict:
    context = {}

    # Structure context
    # tree checks
    if not structure_findings["tree_checks"]["readme"]["exists"]:
        context["readme"] = get_github_context("what is the imapct of Readme not present in github?")
    if not structure_findings["tree_checks"]["LICENSE"]["exists"]:
        context["LICENSE"] = get_github_context("what is the imapct of LICENSE not present in github?")
    if not structure_findings["tree_checks"]["gitignore"]["exists"]:
        context["gitignore"] = get_github_context("what is the imapct of gitignore not present in github?")
    if not structure_findings["tree_checks"]["ci_config"]["exists"]:
        context["ci_config"] = get_github_context("what is the imapct of ci config not present in github?")
    if not structure_findings["tree_checks"]["test_directory"]["exists"]:
        context["test_directory"] = get_github_context("what is the imapct of test directory not present in github?")
    if structure_findings["tree_checks"]["env_files"]["exists"]:
        context["env_files"] = get_github_context("what is the imapct of env files present in github?")

    # branch checks
    if structure_findings["branch_checks"]["stale_branches"]["total"] > 0:
        context["stale_branches"] = get_github_context("what is the imapct of having stale branches in github?")

    # commit checks
    if structure_findings["commits"]["days_since_last_commit"] > 365:
        context["commits"] = get_github_context("what is the imapct of not having any recent commits in github?")

    # secret checks
    if structure_findings["secrets_check"]["secrets_found"]:
        context["secrets"] = get_github_context("what is the imapct of having secrets in files in github?")

    # code quality context
    # unused import
    if any(file["findings"].get("unused_imports", []) for file in code_quality_findings):
        context["unused_imports"] = get_pep_context("what is the imapct of having unused imports in Python?")
    
    # dead functions
    if any(file["findings"].get("dead_functions", []) for file in code_quality_findings):
        context["dead_functions"] = get_pep_context("what is the imapct of having dead functions in Python?")

    # missing doc strings
    if any(file["findings"].get("missing_docstrings", []) for file in code_quality_findings):
        context["missing_docstrings"] = get_pep_context("what is the imapct of having missing docstrings in Python?")

    # function analysis
    if any (
        func["function_length"] > 50
        for file in code_quality_findings
        for func in file["findings"].get("function_analysis", [])
    ):
        context["function_length"] = get_pep_context("what is the imapct of having long functions in Python?")

    if any (
        func["function_params"] > 5
        for file in code_quality_findings
        for func in file["findings"].get("function_analysis", [])
    ):
        context["function_params"] = get_pep_context("what is the imapct of having too many function params in Python?")

    if any (
        func["function_depth"] > 4
        for file in code_quality_findings
        for func in file["findings"].get("function_analysis", [])
    ):
        context["function_depth"] = get_pep_context("what is the imapct of having deeper functions in Python?")

    if any (
        func["function_complexity"] >= 10
        for file in code_quality_findings
        for func in file["findings"].get("function_analysis", [])
    ):
        context["function_complexity"] = get_pep_context("what is the imapct of having complex functions in Python?")

    return context

def get_normalized_severity(severity: str) -> str:
    s = severity.upper()

    if "CRITICAL" in s:
        return "critical"
    elif "HIGH" in s:
        return "high"
    elif "MEDIUM" in s:
        return "medium"
    elif "LOW" in s:
        return "low"
    elif "CVSS:3" in s:
        score = CVSS3(severity).base_score
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        else:
            return "low"
    else: return "medium"
        
        

def get_security_scores(structure_findings: dict, vulnerability_findings: dict) -> dict:
    total_score = 100
    if structure_findings["secrets_check"]["secrets_found"]:
        total_score -= 30
    if structure_findings["tree_checks"]["env_files"]["exists"]:
        total_score -= 20
    
    for package in vulnerability_findings["vulnerabilities"]:
        for severity in package["severities"]:
            normalized_severity = get_normalized_severity(severity)
            if normalized_severity == "critical":
                total_score -= 15
            elif normalized_severity == "high":
                total_score -= 10
            elif normalized_severity == "medium":
                total_score -= 5
            elif normalized_severity == "low":
                total_score -= 2
            
            if total_score < 0:
                total_score = 0
                break
        if total_score == 0:
            break
    return total_score

def get_code_quality_score(code_quality_findings):
    unused_imports_deduct = 0
    dead_functions_deduct = 0
    missing_docstrings_deduct = 0
    complexity_deduct = 0
    depth_deduct = 0
    params_deduct = 0
    length_deduct = 0

    for file in code_quality_findings:
        findings = file["findings"]
        unused_imports_deduct += len(findings.get("unused_imports", []))
        dead_functions_deduct += len(findings.get("dead_functions", []))
        missing_docstrings_deduct += len(findings.get("missing_docstrings", []))

        for func in findings.get("function_analysis", []):
            if func["function_complexity"] > 10:
                complexity_deduct += 1
            if func["function_depth"] > 4:
                depth_deduct += 1
            if func["function_params"] > 5:
                params_deduct += 1
            if func["function_length"] > 50:
                length_deduct += 1

    score = 100
    score -= min(unused_imports_deduct, 16)
    score -= min(dead_functions_deduct, 16)
    score -= min(missing_docstrings_deduct, 4)
    score -= min(complexity_deduct, 16)
    score -= min(depth_deduct, 16)
    score -= min(params_deduct, 16)
    score -= min(length_deduct, 16)

    return max(score, 0)


def get_documentation_score(structure_findings, code_quality_findings):
    score = 100

    if not structure_findings["tree_checks"]["readme"]["exists"]:
        score -= 40
    if not structure_findings["tree_checks"]["LICENSE"]["exists"]:
        score -= 40

    docstring_deduct = 0
    for file in code_quality_findings:
        docstring_deduct += len(file["findings"].get("missing_docstrings", []))
    score -= min(docstring_deduct, 20)

    return max(score, 0)


def get_repo_hygiene_score(structure_findings):
    score = 100

    if not structure_findings["tree_checks"]["gitignore"]["exists"]:
        score -= 25
    if not structure_findings["tree_checks"]["ci_config"]["exists"]:
        score -= 25
    if not structure_findings["tree_checks"]["test_directory"]["exists"]:
        score -= 25

    if structure_findings["branch_checks"]["stale_branches"]["total"] > 0:
        score -= 12.5
    if structure_findings["commits"]["days_since_last_commit"] > 365:
        score -= 12.5

    return max(score, 0)


def get_deprecation_score(vulnerability_findings):
    score = 100

    outdated_deduct = 0
    unmaintained_deduct = 0

    for dep in vulnerability_findings.get("deprecations", []):
        if dep["version_gap"] > 0:
            outdated_deduct += 5
        if not dep["is_maintained"]:
            unmaintained_deduct += 5

    score -= min(outdated_deduct, 50)
    score -= min(unmaintained_deduct, 50)

    return max(score, 0)


def calculate_dimension_scores(structure_findings, code_quality_findings, vulnerability_findings):
    security = get_security_scores(structure_findings, vulnerability_findings)
    code_quality = get_code_quality_score(code_quality_findings)
    documentation = get_documentation_score(structure_findings, code_quality_findings)
    repo_hygiene = get_repo_hygiene_score(structure_findings)
    deprecations = get_deprecation_score(vulnerability_findings)

    return {
        "security": {"score": security, "weight": 0.40, "weighted_score": round(security * 0.40, 2)},
        "code_quality": {"score": code_quality, "weight": 0.20, "weighted_score": round(code_quality * 0.20, 2)},
        "documentation": {"score": documentation, "weight": 0.10, "weighted_score": round(documentation * 0.10, 2)},
        "repo_hygiene": {"score": repo_hygiene, "weight": 0.15, "weighted_score": round(repo_hygiene * 0.15, 2)},
        "deprecations": {"score": deprecations, "weight": 0.15, "weighted_score": round(deprecations * 0.15, 2)}
    }


def generate_health_report(structure_findings: dict,
    code_quality_findings: list,
    vulnerability_findings: dict
    ) -> dict:
    findings = {
        "code_structure_findings": structure_findings,
        "code_quality_findings": code_quality_findings,
        "vulnerability_and_deprecation_findings": vulnerability_findings
    }

    if not code_quality_findings:
        findings["skipped_checks"] = findings.get("skipped_checks", [])
        findings["skipped_checks"].append(
            "Code quality analysis skipped — no Python files found in repository"
        )

    if not vulnerability_findings.get("vulnerabilities"):
        findings["skipped_checks"] = findings.get("skipped_checks", [])
        findings["skipped_checks"].append(
            "Vulnerability scan skipped — no requirements.txt found"
        )

    context = get_rag_context(structure_findings,code_quality_findings)
    dimension_scores = calculate_dimension_scores(structure_findings, code_quality_findings, vulnerability_findings)
    health_score = sum(d["weighted_score"] for d in dimension_scores.values())
    # Clean regex patterns from secret findings for LLM readability
    if structure_findings.get("secrets_check", {}).get("findings"):
        for finding in structure_findings["secrets_check"]["findings"]:
            pattern = finding.get("pattern_matched", "")
            # Extract just the keyword (e.g., "API_KEY" from "API_KEY\\s*=\\s*...")
            clean_pattern = pattern.split("\\")[0].split("(")[0].strip()
            finding["pattern_matched"] = clean_pattern

    prompt=f"""You are a senior software engineer reviewing a GitHub repository's health.

    ROLE: Analyze the findings below and produce a structured health report.

    FINDINGS:
    {findings}

    CONTEXT FROM KNOWLEDGE BASE (use as evidence):
    {context}

    DIMENSION SCORES (calculated):
    {dimension_scores}

    HEALTH SCORE (calculate):
    {health_score}

    INSTRUCTIONS:
    1. For each finding, explain WHY it matters using the provided context
    2. Assign severity: critical/high/medium/low
    3. Provide specific, actionable recommendations
    4. Generate cross-signal insights — look for combinations that amplify risk
    5. Write a deployment risk summary — what happens if deployed as-is
    6. For every finding, include specific file names, line numbers, function names, and package versions from the findings data. Never summarize vaguely — be precise.

        Examples of BAD descriptions:
        - "Unused imports found in the code"
        - "Some functions are missing docstrings"

        Examples of GOOD descriptions:
        - "Unused imports in app.py: os (line 1), sys (line 2), json (line 3)"
        - "Missing docstrings: hello() in app.py (line 5), goodbye() in app.py (line 9)"
        - "Hardcoded API_KEY in config.py (line 1), PASSWORD in config.py (line 2)"
    7. For EVIDENCE: Quote the exact source — cite PEP number, CVE ID, or GitHub best practice guideline. Don't say "best practices state..." — say "PEP 257 states..." or "CVE-2020-1747 describes..."
        - BAD: "PEP 257 states that docstrings are important"
        - GOOD: "PEP 257 requires docstrings for all public modules, functions, classes, and methods. A docstring must be the first statement in the function body using triple double quotes. It should describe the function's behavior, arguments, return values, and exceptions raised."
    8. For DESCRIPTION: Include the exact impact — not "this is a security risk" but "an attacker can execute arbitrary code by exploiting the PyYAML deserialization vulnerability, potentially gaining full server access"
        - BAD: "Missing docstrings can make code harder to understand"  
        - GOOD: "5 functions in app.py and 13 functions in test.py lack docstrings. Without docstrings, developers cannot use help() or auto-generated documentation tools. New team members will need to read every function's implementation to understand its purpose."
    9. For RECOMMENDATION: Give step-by-step actions, not vague advice. Not "update dependencies" but "Run: pip install flask==3.1.3. Review breaking changes at https://flask.palletsprojects.com/changes/. Test all routes after upgrade."
        - BAD: "Add docstrings to improve documentation"
        - GOOD: "Add PEP 257 compliant docstrings to hello() in app.py (line 5) and all 13 functions in test.py. Use this format: first line as a summary ending in a period, blank line, then document arguments and return values. Start with the most complex functions: scan_structure (36 lines, complexity 4) and check_tree (46 lines, complexity 7)."
    10. Create a SEPARATE finding for EVERY issue type found. Do not skip any. 
        If there are unused imports — create a finding.
        If there are dead functions — create a finding.
        If there are missing docstrings — create a finding.
        If there are high complexity functions — create a finding.
        Do not combine multiple issue types into one finding.
    
    CRITICAL: If your evidence says "best practices state..." or your recommendation says "update dependencies" without specifics, your output is REJECTED. Be precise or don't include the finding.
    
    IMPORTANT: The CONTEXT section contains full vulnerability descriptions, PEP guidelines, and best practice details retrieved from authoritative sources. Copy the relevant details directly into your evidence — do not summarize them into one sentence.
    
    OUTPUT FORMAT:
    {output_example}
    OUTPUT:
    Return ONLY valid JSON. Use double quotes. No schema definitions. No markdown fences. No extra text.

    RULES:
    - Every claim must trace back to findings or context
    - Do not invent findings not present in the data
    - Sort findings by severity (critical first)

    DIMENSION MAPPING (use these when assigning dimensions to findings):
    - security: hardcoded secrets, .env committed, CVE vulnerabilities
    - code_quality: unused imports, dead functions, high complexity, deep nesting, too many parameters
    - documentation: missing README, missing LICENSE, missing docstrings
    - repo_hygiene: no .gitignore, no CI/CD, no test directory, stale branches, inactive commits
    - deprecations: outdated packages, unmaintained packages
    """

    response = llm.invoke(
        [SystemMessage(content=prompt)]
    )

    try:
        content = response.content.strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        report = json.loads(content)
        report["skipped_checks"] = findings.get("skipped_checks", [])
        return report
    except json.JSONDecodeError:
        try:
            report = json.loads(content.replace("'", '"'))
            report["skipped_checks"] = findings.get("skipped_checks", [])
            return report
        except:
            return {"error": "Failed to parse LLM response", "raw": response.content}
