"""
utils.py

Helper functions to interact with GitHub repositories via the GitHub REST API.

Features:
- Retrieve the default branch of a repository
- Get the repository file tree recursively
- Fetch the content of a file in the repository

Requires a GitHub token stored in the environment variable `GITHUB_TOKEN`.
"""

import requests
import os
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