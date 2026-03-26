"""
Scrape CVE/NVD data for top 50 Python packages.
Saves results to raw_docs/cve.txt

Usage: python scrape_cve.py
"""

import requests
import json
import time
import os

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

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

OUTPUT_FILE = os.path.join("..", "raw_docs", "cve.txt")


def fetch_cves_for_package(package_name):
    """Fetch CVE entries for a single package from NVD API."""
    params = {
        "keywordSearch": f"python {package_name}",
        "resultsPerPage": 10  # top 10 CVEs per package
    }

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except requests.RequestException as e:
        print(f"  Error fetching CVEs for {package_name}: {e}")
        return []


def parse_cve_entry(vuln):
    """Extract relevant fields from a single CVE entry."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    # Get description
    descriptions = cve.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # Get severity from CVSS metrics
    severity = "UNKNOWN"
    score = 0.0
    metrics = cve.get("metrics", {})

    # Try CVSS v3.1 first, then v3.0, then v2.0
    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version_key in metrics and metrics[version_key]:
            cvss_data = metrics[version_key][0].get("cvssData", {})
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
            score = cvss_data.get("baseScore", 0.0)
            break

    # Get affected configurations (packages/versions)
    affected_versions = []
    configurations = cve.get("configurations", [])
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for match in cpe_matches:
                criteria = match.get("criteria", "")
                version_start = match.get("versionStartIncluding", "")
                version_end = match.get("versionEndExcluding", "")
                if version_start or version_end:
                    affected_versions.append(f"{version_start} to {version_end}")

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity,
        "score": score,
        "affected_versions": affected_versions
    }


def format_cve_document(package_name, cve_entry):
    """Format a single CVE entry as a text document for ingestion."""
    versions_str = ", ".join(cve_entry["affected_versions"]) if cve_entry["affected_versions"] else "Not specified"

    doc = f"""--- CVE ENTRY ---
CVE ID: {cve_entry['cve_id']}
Package: {package_name}
Severity: {cve_entry['severity']} ({cve_entry['score']})
Affected Versions: {versions_str}
Description: {cve_entry['description']}
--- END CVE ENTRY ---
"""
    return doc


def main():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    all_docs = []
    total_cves = 0

    for i, package in enumerate(TOP_50_PYTHON_PACKAGES):
        print(f"[{i+1}/50] Fetching CVEs for: {package}")
        vulnerabilities = fetch_cves_for_package(package)

        for vuln in vulnerabilities:
            cve_entry = parse_cve_entry(vuln)
            if cve_entry["description"]:  # skip empty entries
                doc = format_cve_document(package, cve_entry)
                all_docs.append(doc)
                total_cves += 1

        # NVD API rate limit: 5 requests per 30 seconds without API key
        # Be conservative — wait 6 seconds between requests
        print(f"  Found {len(vulnerabilities)} CVEs. Sleeping 6s for rate limit...")
        time.sleep(6)

    # Write all docs to file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(all_docs))

    print(f"\nDone! Saved {total_cves} CVE entries to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()