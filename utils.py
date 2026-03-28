"""
utils.py

Helper functions to interact with GitHub repositories via the GitHub REST API.

Features:
- Retrieve the default branch of a repository
- Get the repository file tree recursively
- Fetch the content of a file in the repository
- Get the owenr name and repo name from a given url

Requires a GitHub token stored in the environment variable `GITHUB_TOKEN`.
"""

import requests
import os
import re
import base64
from dotenv import load_dotenv

load_dotenv()
github_token = os.getenv("GITHUB_TOKEN")

headers = {
    "Authorization": f"Bearer {github_token}",
    "Accept": "application/vnd.github+json"
}


def get_default_branch(owner: str, repo: str) -> str:
    """
    Fetch the default branch of a GitHub repository.

    Args:
        owner (str): GitHub username or organization name.
        repo (str): Repository name.

    Returns:
        str: Name of the default branch. Returns an empty string if
             repository is not found or connection fails.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        response = requests.get(url=url, headers=headers)
        if response.status_code == 404:
            print("❌ Repo not found — check owner/repo name or repo may be private")
            return ""
        data = response.json()
        return data["default_branch"]
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed — check your internet")
        return ""


def get_repo_tree(owner: str, repo: str, default_branch: str) -> dict:
    """
    Retrieve the full file tree of a GitHub repository branch recursively.

    Args:
        owner (str): GitHub username or organization name.
        repo (str): Repository name.
        default_branch (str): Branch name to fetch tree from.

    Returns:
        dict: GitHub repository tree JSON. Returns empty dict if repo
              not found or connection fails.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1"
    try:
        response = requests.get(url=url, headers=headers)
        if response.status_code == 404:
            print("❌ Repo not found — check owner/repo name or repo may be private")
            return {}
        data = response.json()
        return data
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed — check your internet")
        return {}


def get_file_content(owner: str, repo: str, file_path: str) -> str:
    """
    Fetch the content of a specific file in a GitHub repository.

    Args:
        owner (str): GitHub username or organization name.
        repo (str): Repository name.
        file_path (str): Path to the file in the repository.

    Returns:
        str: File content as a decoded UTF-8 string. Returns empty string
             if file not found or connection fails.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
    try:
        response = requests.get(url=url, headers=headers)
        if response.status_code == 404:
            print(f"❌ File not found: {file_path}")
            return ""
        data = response.json()
        content = base64.b64decode(data["content"]).decode("utf-8")
        return content
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed — check your internet")
        return ""
    
def get_owner_and_repo(repo: str) -> dict:
    """
    Extract GitHub owner and repository name from multiple input formats.

    Supported formats:
        https://github.com/owner/repo
        https://github.com/owner/repo/
        https://github.com/owner/repo.git
        git@github.com:owner/repo.git
        owner/repo

    Args:
        repo (str): GitHub repo URL or owner/repo string.

    Returns:
        dict: { "owner": str, "repo": str }

    Raises:
        ValueError: If repo format is invalid.
    """

    repo = repo.strip()

    # Handle SSH format: git@github.com:owner/repo.git
    ssh_match = re.search(r'github\.com[:/](.+?)/(.+?)(\.git)?$', repo)
    if ssh_match:
        owner, repo_name = ssh_match.group(1), ssh_match.group(2)
        return {"owner": owner, "repo": repo_name}

    # Remove protocol/domain if present
    if "github.com" in repo:
        repo = repo.split("github.com/")[-1]

    # Remove trailing slash and .git
    repo = repo.strip("/").replace(".git", "")

    parts = repo.split("/")
    if len(parts) != 2:
        raise ValueError(f"Invalid GitHub repository format: {repo}")

    return {
        "owner": parts[0],
        "repo": parts[1]
    }