"""
GitHub Repository Structure Scanner

This module inspects the structural health of a GitHub repository using the GitHub REST API.

It evaluates:
• Repository tree best practices (README, LICENSE, CI, tests, gitignore)
• Branch activity and stale branches
• Commit recency
• Contributor activity
• Hardcoded secret detection in sensitive files

This is the FIRST stage of the repository health pipeline.
"""

import os
import requests
import re
from datetime import datetime, timezone
from dotenv import load_dotenv
from utils import get_default_branch, get_repo_tree, get_file_content, get_owner_and_repo

load_dotenv()

github_token = os.getenv("GITHUB_TOKEN")

headers = {
    "Authorization": f"Bearer {github_token}",
    "Accept": "application/vnd.github+json"
}


def scan_structure(repo: str) -> dict:
    """
    Main entry point for repository structure scanning.

    This function orchestrates all structural checks:
    - Repository tree inspection
    - Branch health analysis
    - Commit activity analysis
    - Contributor metrics
    - Secret detection

    Args:
        repo (str): GitHub repository URL or "owner/repo".

    Returns:
        dict: Structured repository health findings.
    """
    repo_info = get_owner_and_repo(repo)
    owner = repo_info["owner"]
    repo_name = repo_info["repo"]

    default_branch = get_default_branch(owner, repo_name)
    if default_branch == "":
        return

    repo_tree = get_repo_tree(owner, repo_name, default_branch)
    if len(repo_tree.keys()) < 1:
        return

    tree_checks = check_tree(repo_tree["tree"])
    branch_checks = check_branches(owner, repo_name)
    commits = check_commits(owner, repo_name)
    contributor_checks = check_contributors(owner, repo_name)
    secrets_check = check_secrets(owner, repo_name, repo_tree["tree"])

    return {
        "repo": f"{owner}/{repo_name}",
        "scanned_at": datetime.now(timezone.utc),
        "tree_checks": tree_checks,
        "branch_checks": branch_checks,
        "commits": commits,
        "contributor_checks": contributor_checks,
        "secrets_check": secrets_check
    }


def check_tree(tree: dict) -> dict:
    """
    Inspect repository file tree for best-practice files and directories.

    Checks for:
    - README
    - LICENSE
    - .gitignore
    - CI/CD configuration
    - Test directories
    - Environment files

    Args:
        tree (list): GitHub repository tree.

    Returns:
        dict: Presence indicators for key project files.
    """
    readme_exists = False
    license_exists = False
    gitignore_exists = False
    ci_config_exists = False
    test_directory_exists = False
    env_file_exists = False
    has_python_files = False
    has_requirements_txt = False

    tests_paths = ["tests/", "test/", "spec/", "__tests__/"]
    config_files = [".github/workflows/", ".travis.yml", ".circleci/", "jenkinsfile", ".gitlab-ci.yml"]

    for tree_path in tree:
        path = tree_path["path"].lower()

        if "readme" in path:
            readme_exists = True
        if ".env" in path:
            env_file_exists = True
        if "license" in path:
            license_exists = True
        if "gitignore" in path:
            gitignore_exists = True
        if path.endswith(".py"):
            has_python_files = True
        if path == "requirements.txt":
            has_requirements_txt = True
        if any(test in path for test in tests_paths):
            test_directory_exists = True
        if any(test in path for test in config_files):
            ci_config_exists = True

    return {
        "readme": {"exists": readme_exists},
        "LICENSE": {"exists": license_exists},
        "gitignore": {"exists": gitignore_exists},
        "ci_config": {"exists": ci_config_exists},
        "test_directory": {"exists": test_directory_exists},
        "env_files": {"exists": env_file_exists},
        "python_files": {"exists": has_python_files},
        "requirements_txt": {"exists": has_requirements_txt}
    }


def check_branches(owner: str, repo: str) -> dict:
    """
    Fetch branch list and identify stale branches.

    A branch is considered stale if no commits occurred in the last 60 days.

    Returns:
        dict: Branch metrics and stale branch list.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/branches"
    try:
        response = requests.get(url=url, headers=headers)
        if response.status_code == 404:
            print("❌ Repo not found — check owner/repo name or repo may be private")
            return {}

        data = response.json()
        stale_branches = get_stale_branches(data)

        return {
            "total_branches": len(data),
            "stale_branches": {
                "total": len(stale_branches),
                "branches": stale_branches
            }
        }
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed — check your internet")
        return {}


def get_stale_branches(branches: list) -> list:
    """
    Identify branches inactive for more than 60 days.

    Args:
        branches (list): GitHub branch API response.

    Returns:
        list: Metadata for stale branches.
    """
    stale_branches = []

    for branch in branches:
        url = branch["commit"]["url"]
        try:
            response = requests.get(url=url, headers=headers)
            data = response.json()

            commit_date = data["commit"]["author"]["date"]
            commit_datetime = datetime.fromisoformat(commit_date.replace("Z", "+00:00"))
            days_inactive = (datetime.now(timezone.utc) - commit_datetime).days

            if days_inactive > 60:
                stale_branches.append({
                    "name": branch["name"],
                    "last_commit_date": commit_date,
                    "days_inactive": days_inactive
                })

        except requests.exceptions.ConnectionError:
            print("❌ Connection failed — check your internet")

    return stale_branches


def check_commits(owner: str, repo: str) -> dict:
    """
    Retrieve most recent commit and calculate inactivity period.

    Returns:
        dict: Last commit timestamp and days since last commit.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"

    try:
        response = requests.get(url=url, headers=headers)
        data = response.json()

        last_commit_date = data[0]["commit"]["author"]["date"]
        last_commit_datetime = datetime.fromisoformat(last_commit_date.replace("Z", "+00:00"))
        days_since_last_commit = (datetime.now(timezone.utc) - last_commit_datetime).days

        return {
            "last_commit_date": last_commit_date,
            "days_since_last_commit": days_since_last_commit
        }
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed — check your internet")
        return {}


def check_contributors(owner: str, repo: str) -> dict:
    """
    Fetch contributor statistics.

    Returns:
        dict: Contributor count and contribution breakdown.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/contributors"

    try:
        response = requests.get(url=url, headers=headers)
        data = response.json()

        contributors = [
            {"name": c["login"], "contributions": c["contributions"]}
            for c in data
        ]

        return {
            "contributor_count": len(data),
            "contributors": contributors
        }

    except requests.exceptions.ConnectionError:
        print("❌ Connection failed — check your internet")
        return {}


def check_secrets(owner: str, repo: str, tree: list) -> dict:
    """
    Scan sensitive configuration files for hardcoded secrets.

    Target files include:
    - config.py / settings.py
    - config.json / yaml

    Returns:
        dict: Secret detection results.
    """
    SENSITIVE_FILES = ["config.py", "settings.py", "config.json", "config.yml", "config.yaml"]

    target_files = [
        t["path"] for t in tree
        if t["path"].split('/')[-1].lower() in SENSITIVE_FILES
    ]

    all_findings = []

    for file_path in target_files:
        content = get_file_content(owner, repo, file_path)
        if content:
            all_findings.extend(scan_for_secrets(content, file_path))

    return {
        "scanned_files": target_files,
        "secrets_found": len(all_findings) > 0,
        "findings": all_findings
    }


def scan_for_secrets(content: str, file_path: str) -> list:
    """
    Detect potential hardcoded secrets using regex patterns.

    Searches for API keys, passwords, tokens, AWS credentials, etc.

    Returns:
        list: Secret findings with file and line numbers.
    """
    findings = []
    SECRET_PATTERNS = [
        r'API_KEY\s*=\s*["\']?.{8,}',
        r'SECRET_KEY\s*=\s*["\']?.{8,}',
        r'PASSWORD\s*=\s*["\']?.{8,}',
        r'TOKEN\s*=\s*["\']?.{8,}',
        r'aws_secret_access_key\s*=\s*["\']?.{8,}'
    ]

    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("/"):
            continue

        for pattern in SECRET_PATTERNS:
            if re.search(pattern, stripped, re.IGNORECASE):
                findings.append({
                    "file": file_path,
                    "line": line_number,
                    "pattern_matches": pattern
                })

    return findings