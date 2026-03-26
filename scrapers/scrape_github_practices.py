"""
Scrape GitHub best practices from official docs and opensource.guide.
Saves results to raw_docs/github_best_practices.txt

Usage: python scrape_github_practices.py
"""

import requests
import os
import re

SOURCES = [
    {
        "name": "GitHub Repository Best Practices",
        "url": "https://docs.github.com/en/repositories/creating-and-managing-repositories/best-practices-for-repositories"
    },
    {
        "name": "Open Source Best Practices",
        "url": "https://opensource.guide/best-practices/"
    },
    {
        "name": "Starting an Open Source Project",
        "url": "https://opensource.guide/starting-a-project/"
    }
]

# Fallback: curated best practices if scraping fails
# (GitHub docs sometimes block automated requests)
CURATED_PRACTICES = [
    {
        "category": "README",
        "text": """Every repository should have a README.md file at the root level. A good README includes:
- Project title and description explaining what the project does and why it exists.
- Installation instructions with step-by-step setup guide.
- Usage examples showing how to run and use the project.
- Contributing guidelines explaining how others can contribute.
- License information.
A repository without a README is essentially undocumented and creates a barrier for new contributors and users."""
    },
    {
        "category": "License",
        "text": """Every open source repository must include a LICENSE file. Without a license, the code is under exclusive copyright by default — meaning no one can legally use, copy, or modify it. Common licenses include MIT (permissive), Apache 2.0 (permissive with patent protection), and GPL (copyleft). Choose a license that matches your intent for how others can use your code."""
    },
    {
        "category": ".gitignore",
        "text": """Every repository should have a .gitignore file to prevent committing unnecessary files. Common files to ignore include: compiled bytecode (__pycache__, *.pyc), virtual environments (venv/, .env/), IDE settings (.vscode/, .idea/), OS files (.DS_Store, Thumbs.db), dependency directories (node_modules/), and sensitive files (.env with secrets). Committing these files bloats the repository, may expose secrets, and creates merge conflicts."""
    },
    {
        "category": "Branch Management",
        "text": """Repositories should follow good branch management practices. Stale branches (branches with no commits in 60+ days) should be deleted after merging. The default branch should be protected with branch protection rules requiring pull request reviews before merging. Feature branches should be short-lived and merged regularly. Having many stale branches indicates poor repository hygiene and makes the codebase harder to navigate."""
    },
    {
        "category": "CI/CD",
        "text": """Repositories should have continuous integration (CI) configured. CI automatically runs tests, linting, and other checks on every push or pull request. Common CI tools include GitHub Actions (.github/workflows/), Travis CI (.travis.yml), CircleCI (.circleci/config.yml), and Jenkins (Jenkinsfile). A repository without CI means there's no automated verification that code changes don't break existing functionality."""
    },
    {
        "category": "Security - Secrets",
        "text": """Never commit secrets, API keys, passwords, or tokens to a repository. Common patterns that indicate exposed secrets include: API_KEY=, SECRET_KEY=, PASSWORD=, TOKEN=, private_key, aws_access_key_id, and hardcoded connection strings with credentials. Use environment variables or secret management tools instead. Exposed secrets in public repositories are automatically scraped by bots and can lead to account compromise within minutes."""
    },
    {
        "category": "Security - Dependencies",
        "text": """Keep dependencies up to date and monitor them for known vulnerabilities. Use tools like Dependabot, pip-audit, or safety to scan dependencies. Pin dependency versions in requirements.txt to ensure reproducible builds. Regularly review and update dependencies, especially when security advisories are published. Outdated dependencies with known CVEs are one of the most common attack vectors."""
    },
    {
        "category": "Code Organization",
        "text": """A well-organized repository should have a clear project structure. For Python projects this typically includes: a source directory (src/ or package name), tests directory (tests/), documentation (docs/), configuration files at root (setup.py/pyproject.toml, requirements.txt), and clear separation of concerns. Flat repositories with all files at root level become unmanageable as the project grows."""
    },
    {
        "category": "Testing",
        "text": """Every repository should include tests. A test directory (tests/ or test/) should exist with test files that cover core functionality. Good testing practices include: having a test runner configured (pytest, unittest), maintaining reasonable code coverage, testing edge cases and error handling, and running tests in CI. A repository without tests provides no confidence that the code works as intended or that changes won't introduce regressions."""
    },
    {
        "category": "Documentation",
        "text": """Beyond a README, well-maintained projects include: docstrings for all public functions and classes, a CONTRIBUTING.md file explaining how to contribute, a CHANGELOG.md tracking version changes, inline comments for complex logic, and API documentation for libraries. Undocumented code is a maintenance burden — if the original author leaves, the knowledge leaves with them."""
    },
    {
        "category": "Commit Hygiene",
        "text": """Good commit practices include: writing descriptive commit messages that explain why a change was made, making atomic commits (one logical change per commit), not committing large binary files (use Git LFS instead), and keeping commits reasonably sized for easy code review. Large binary files in repositories bloat the git history permanently since git stores every version of every file."""
    },
    {
        "category": "Repository Activity",
        "text": """Repository health can be partially measured by activity signals. A repository with no commits in over 1-2 years may be abandoned or unmaintained. Key activity indicators include: last commit date, frequency of commits, number of open vs closed issues, response time to issues and PRs, and number of contributors. An abandoned repository with open security issues is a significant risk to depend on."""
    }
]

OUTPUT_FILE = os.path.join("..", "raw_docs", "github_best_practices.txt")


def clean_html(html_text):
    """Basic HTML to text conversion."""
    text = re.sub(r'<script[^>]*>.*?</script>', '', html_text, flags=re.DOTALL)
    text = re.sub(r'<style[^>]*>.*?</style>', '', html_text, flags=re.DOTALL)
    text = re.sub(r'<br\s*/?>', '\n', text)
    text = re.sub(r'</(p|div|h[1-6]|li|tr)>', '\n', text)
    text = re.sub(r'<[^>]+>', '', text)
    text = text.replace('&amp;', '&').replace('&lt;', '<')
    text = text.replace('&gt;', '>').replace('&quot;', '"')
    text = text.replace('&#39;', "'").replace('&nbsp;', ' ')
    text = re.sub(r'\n\s*\n\s*\n', '\n\n', text)
    return text.strip()


def format_practice_document(practice):
    """Format a best practice as a text document for ingestion."""
    doc = f"""--- GITHUB BEST PRACTICE ---
Category: {practice['category']}
Source: GitHub/Open Source Best Practices
Content:
{practice['text']}
--- END GITHUB BEST PRACTICE ---
"""
    return doc


def try_scrape_sources():
    """Attempt to scrape from live URLs."""
    scraped_docs = []

    for source in SOURCES:
        print(f"Fetching: {source['name']}")
        try:
            headers = {"User-Agent": "Mozilla/5.0 (compatible; educational-scraper)"}
            response = requests.get(source["url"], headers=headers, timeout=15)
            response.raise_for_status()

            text = clean_html(response.text)
            if len(text) > 200:
                scraped_docs.append({
                    "category": source["name"],
                    "text": text[:3000]  # cap at reasonable length
                })
                print(f"  Success — {len(text)} chars")
            else:
                print(f"  Too short, skipping")

        except requests.RequestException as e:
            print(f"  Failed: {e}")

    return scraped_docs


def main():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    all_docs = []

    # Try scraping live sources first
    print("Attempting to scrape live sources...")
    scraped = try_scrape_sources()

    for practice in scraped:
        doc = format_practice_document(practice)
        all_docs.append(doc)

    # Always include curated practices — they're structured and reliable
    print(f"\nAdding {len(CURATED_PRACTICES)} curated best practices...")
    for practice in CURATED_PRACTICES:
        doc = format_practice_document(practice)
        all_docs.append(doc)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(all_docs))

    total = len(all_docs)
    print(f"\nDone! Saved {total} best practice documents to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()