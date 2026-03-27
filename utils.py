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
