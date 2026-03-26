"""
Scrape PyPI security advisories from the PyPA advisory database.
Source: https://github.com/pypa/advisory-database

Since cloning the full repo is heavy, we use the GitHub API to fetch
advisory files for our top 50 packages.

Saves results to raw_docs/pypi_advisories.txt

Usage: python scrape_pypi_advisories.py
"""

import requests
import time
import os
import json

TOP_50_PYTHON_PACKAGES = [
    "requests", "flask", "django", "numpy", "pandas",
    "scipy", "matplotlib", "pillow", "sqlalchemy", "celery",
    "boto3", "cryptography", "paramiko", "pyyaml", "jinja2",
    "werkzeug", "urllib3", "certifi", "setuptools", "pip",
    "aiohttp", "fastapi", "uvicorn", "gunicorn", "tornado",
    "beautifulsoup4", "scrapy", "selenium", "pytest", "tox",
    "black", "pylint", "mypy", "pydantic", "httpx",
    "redis", "psycopg2", "pymongo", "docker", "kubernetes",
    "tensorflow", "pytorch", "scikit-learn", "transformers", "nltk",
    "opencv-python", "lxml", "pyopenssl", "markdown", "pygments"
]

# OSV.dev API — aggregates PyPI advisories, free, no auth
OSV_API_URL = "https://api.osv.dev/v1/query"

OUTPUT_FILE = os.path.join("..", "raw_docs", "pypi_advisories.txt")


def fetch_advisories_for_package(package_name):
    """Fetch security advisories for a package from OSV.dev."""
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        }
    }

    try:
        response = requests.post(OSV_API_URL, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data.get("vulns", [])
    except requests.RequestException as e:
        print(f"  Error fetching advisories for {package_name}: {e}")
        return []


def parse_advisory(advisory, package_name):
    """Extract relevant fields from an OSV advisory."""
    advisory_id = advisory.get("id", "UNKNOWN")
    summary = advisory.get("summary", "No summary available")
    details = advisory.get("details", "")
    severity = "UNKNOWN"

    # Extract severity from severity field or database_specific
    severity_list = advisory.get("severity", [])
    if severity_list:
        for s in severity_list:
            if s.get("type") == "CVSS_V3":
                score_str = s.get("score", "")
                severity = score_str

    # Extract affected versions and fix versions
    affected_versions = []
    fix_version = "Not specified"

    for affected in advisory.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() == package_name.lower():
            for version_range in affected.get("ranges", []):
                events = version_range.get("events", [])
                introduced = ""
                fixed = ""
                for event in events:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                if introduced:
                    affected_versions.append(f">={introduced}")
                if fixed:
                    fix_version = fixed
                    affected_versions.append(f"<{fixed}")

    return {
        "id": advisory_id,
        "summary": summary,
        "details": details[:500],  # truncate long details
        "severity": severity,
        "affected_versions": affected_versions,
        "fix_version": fix_version,
        "package_name": package_name
    }


def format_advisory_document(entry):
    """Format a single advisory entry as text for ingestion."""
    versions_str = ", ".join(entry["affected_versions"]) if entry["affected_versions"] else "Not specified"

    doc = f"""--- PYPI ADVISORY ---
Advisory ID: {entry['id']}
Package: {entry['package_name']}
Summary: {entry['summary']}
Severity: {entry['severity']}
Affected Versions: {versions_str}
Fix Version: {entry['fix_version']}
Details: {entry['details']}
--- END PYPI ADVISORY ---
"""
    return doc


def main():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    all_docs = []
    total_advisories = 0

    for i, package in enumerate(TOP_50_PYTHON_PACKAGES):
        print(f"[{i+1}/50] Fetching advisories for: {package}")
        advisories = fetch_advisories_for_package(package)

        for advisory in advisories:
            entry = parse_advisory(advisory, package)
            doc = format_advisory_document(entry)
            all_docs.append(doc)
            total_advisories += 1

        print(f"  Found {len(advisories)} advisories.")
        time.sleep(1)  # gentle rate limiting

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(all_docs))

    print(f"\nDone! Saved {total_advisories} advisories to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()