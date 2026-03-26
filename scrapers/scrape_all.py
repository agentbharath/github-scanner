"""
Master scraper — runs all scraping scripts in sequence.
Run this from the scrapers/ directory.

Usage: 
    cd scrapers
    python scrape_all.py

Output files created in raw_docs/:
    - cve.txt              (CVE/NVD vulnerability data for top 50 Python packages)
    - pypi_advisories.txt  (PyPI security advisories from OSV.dev)
    - pep_standards.txt    (PEP 8, PEP 257, PEP 20 standards)
    - github_best_practices.txt (Repository best practices)

Note: CVE scraping takes ~5 minutes due to NVD API rate limits (6s between requests).
Total runtime: approximately 8-10 minutes.
"""

import subprocess
import sys
import time

SCRIPTS = [
    ("scrape_pep.py", "PEP Standards (PEP 8, 257, 20)"),
    ("scrape_github_practices.py", "GitHub Best Practices"),
    ("scrape_pypi_advisories.py", "PyPI Security Advisories"),
    ("scrape_cve.py", "CVE/NVD Database (this takes ~5 min)"),
]


def main():
    print("=" * 60)
    print("GitHub Health Scanner — Data Scraper")
    print("=" * 60)

    for script, description in SCRIPTS:
        print(f"\n{'='*60}")
        print(f"Running: {description}")
        print(f"Script:  {script}")
        print(f"{'='*60}\n")

        start = time.time()
        result = subprocess.run(
            [sys.executable, script],
            capture_output=False
        )
        elapsed = time.time() - start

        if result.returncode == 0:
            print(f"\n✓ {description} completed in {elapsed:.1f}s")
        else:
            print(f"\n✗ {description} FAILED (exit code {result.returncode})")
            print("  Continuing with remaining scrapers...")

    print(f"\n{'='*60}")
    print("All scrapers finished!")
    print("Check raw_docs/ for output files.")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()