"""
dependency_analyzer.py

This script analyzes Python dependencies from a requirements.txt file.

Features:
1. Parses requirements and extracts package names + version constraints.
2. Queries a Chroma vector database for known security vulnerabilities.
3. Checks PyPI to determine:
   - Latest version available
   - How outdated the current version is
   - Whether the package appears actively maintained

Environment variables must be configured for OpenAI embeddings.
"""

import os
import re
import json
import requests
from utils import get_file_content
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings
from config import config
from dotenv import load_dotenv
from packaging.version import parse
from datetime import datetime

load_dotenv()

# ---------------------------------------------------------------------
# Vector DB Initialization
# ---------------------------------------------------------------------

embedding = OpenAIEmbeddings(
    model=config["EMBEDDING_MODEL"]
)

db = Chroma(
    collection_name="security",
    persist_directory="./chromaStore",
    embedding_function=embedding
)

# ---------------------------------------------------------------------
# Regex Patterns
# ---------------------------------------------------------------------

# Matches version separators in requirements.txt (==, >=, etc.)
SEPARATORS = re.compile(r"(==|>=|<=|!=|~=|>|<)")

# Extracts operator + version (example: >= 1.2.3)
VERSION_RE = re.compile(r"(==|>=|<=|!=|~=|>|<)\s*([0-9a-zA-Z\.\*]+)")


# ---------------------------------------------------------------------
# Requirements Parsing
# ---------------------------------------------------------------------

def parse_requirements(data: str) -> list:
    """
    Parse raw requirements.txt content into structured dependency objects.

    Each requirement is converted into:
        {
            "name": "package_name",
            "version": "version_specifier"
        }

    Duplicate packages are removed.

    Args:
        data (str): Raw contents of requirements.txt file.

    Returns:
        list: List of dictionaries containing package name and version specifier.
    """
    output = []
    seen = set()

    for line in data.splitlines():
        line = line.strip()

        if should_skip_line(line):
            continue

        requirement = {
            "name": line,
            "version": "Default"
        }

        match = SEPARATORS.search(line)
        if match:
            idx = match.start()
            requirement["name"] = line[:idx].strip()
            requirement["version"] = line[idx:].strip()

        if requirement["name"] in seen:
            continue

        seen.add(requirement["name"])
        output.append(requirement)

    return output


def should_skip_line(line: str) -> bool:
    """
    Determine whether a line in requirements.txt should be ignored.

    Skips:
    - Comments (#)
    - Editable installs (-e)
    - Recursive includes (-r)
    - Empty lines

    Args:
        line (str): A single line from requirements.txt

    Returns:
        bool: True if the line should be skipped, False otherwise.
    """
    SKIPPERS = ['#', '-e', '-r']

    for skip in SKIPPERS:
        if line.startswith(skip):
            return True

    if line.strip() == "":
        return True

    return False


# ---------------------------------------------------------------------
# Security Search via Vector DB
# ---------------------------------------------------------------------

def query_chroma(req: dict) -> dict:
    """
    Query the Chroma vector database for security vulnerabilities.

    The search retrieves the top 3 most relevant security advisories
    for a given package and version constraint.

    Args:
        req (dict): Requirement dictionary with keys:
                    - name
                    - version

    Returns:
        dict: Security analysis result including issues, severity, and fix versions.
    """
    query = f"{req['name']} security vulnerability for {req['version']} version(s)"

    results = db.similarity_search(
        query=query,
        k=3,
        filter={"package": req["name"]}
    )

    issues = []
    sources = []
    severity = []
    fix_versions = []

    for doc in results:
        issues.append(doc.page_content)
        severity.append(doc.metadata["severity"])
        sources.append(doc.metadata.get("advisory_id", doc.metadata.get("cve_id")))
        fix_versions.append(doc.metadata.get("fix_version", "NA"))

    return {
        "package_name": req["name"],
        "version": req["version"],
        "issues": issues,
        "sources": sources,
        "severities": severity,
        "fix_versions": fix_versions
    }


# ---------------------------------------------------------------------
# Deprecation & Maintenance Checker (PyPI API)
# ---------------------------------------------------------------------

def check_deprecations(requirements: str) -> list:
    """
    Check whether dependencies are outdated or unmaintained using PyPI.

    For each package:
        - Fetch latest version from PyPI
        - Calculate version gap
        - Determine how old current version is
        - Determine if package is actively maintained (released within 2 years)

    Args:
        requirements (str): Raw requirements.txt content.

    Returns:
        list: List of package upgrade and maintenance insights.
    """
    requirements = parse_requirements(requirements)
    output = []

    for req in requirements:
        package_name = req["name"]
        current_version = req["version"]

        version_match = VERSION_RE.match(current_version)
        if version_match:
            operator = version_match.group(1)
            current_version = version_match.group(2)
        else:
            continue

        try:
            url = f"https://pypi.org/pypi/{package_name}/json"
            response = requests.get(url=url)
            response.raise_for_status()
            data = response.json()

            latest_version = data["info"]["version"]
            versions = sorted(data["releases"].keys(), key=parse)

            idx1 = versions.index(current_version)
            idx2 = versions.index(latest_version)

            version_gap = idx2 - idx1

            released_date_str = data["releases"][current_version][0]["upload_time"]
            released_date = datetime.fromisoformat(released_date_str.replace('Z', ""))

            latest_release_date_str = data["releases"][latest_version][0]["upload_time"]
            latest_release_date = datetime.fromisoformat(latest_release_date_str.replace('Z', ""))

            version_age = latest_release_date - released_date
            days_since_latest_release = datetime.now() - latest_release_date

            is_maintained = days_since_latest_release.days < 730

            output.append({
                "package_name": package_name,
                "current_version": current_version,
                "current_version_release_date": released_date_str,
                "latest_version": latest_version,
                "version_gap": version_gap,
                "days_since_released": version_age.days,
                "is_maintained": is_maintained
            })

        except requests.exceptions.ConnectionError as e:
            print(f"❌ Connection error for {package_name}: {e}")
        except requests.exceptions.HTTPError:
            print(f"❌ Package not found on PyPI: {package_name}")
        except requests.exceptions.RequestException as e:
            print(f"🌐 Network error for {package_name}: {e}")
        except Exception as e:
            print(f"💥 Unexpected error for {package_name}: {e}")

    return output


# ---------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------

if __name__ == "__main__":
    """
    Program entry point.

    Steps:
    1. Fetch requirements.txt from GitHub repo
    2. Parse dependencies
    3. Query vulnerability database
    4. Check deprecations via PyPI
    5. Print results as JSON
    """
    requirements = get_file_content(
        'bharathvaddineniK',
        'test-unhealthy-repo',
        'requirements.txt'
    )

    vulnerabilities = parse_requirements(requirements)

    vulnerabilities_semantics = []
    for req in vulnerabilities:
        semantics = query_chroma(req)
        vulnerabilities_semantics.append(semantics)

    deprecations = check_deprecations(requirements)

    print(json.dumps(deprecations, indent=2))