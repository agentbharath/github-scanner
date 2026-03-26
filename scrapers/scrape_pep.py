"""
Scrape PEP 8 (style guide), PEP 257 (docstrings), PEP 20 (Zen of Python).
Saves results to raw_docs/pep_standards.txt

Usage: python scrape_pep.py
"""

import requests
import os
import re

PEPS = {
    "PEP 8": "https://peps.python.org/pep-0008/",
    "PEP 257": "https://peps.python.org/pep-0257/",
    "PEP 20": "https://peps.python.org/pep-0020/"
}

OUTPUT_FILE = os.path.join("..", "raw_docs", "pep_standards.txt")


def clean_html(html_text):
    """Thorough HTML to text conversion — strips tags, attributes, and leftover noise."""
    from html import unescape

    # Remove script and style blocks
    text = re.sub(r'<script[^>]*>.*?</script>', '', html_text, flags=re.DOTALL)
    text = re.sub(r'<style[^>]*>.*?</style>', '', html_text, flags=re.DOTALL)
    text = re.sub(r'<nav[^>]*>.*?</nav>', '', text, flags=re.DOTALL)
    text = re.sub(r'<header[^>]*>.*?</header>', '', text, flags=re.DOTALL)
    text = re.sub(r'<footer[^>]*>.*?</footer>', '', text, flags=re.DOTALL)

    # Replace common block elements with newlines
    text = re.sub(r'<br\s*/?>', '\n', text)
    text = re.sub(r'</(p|div|h[1-6]|li|tr|pre|blockquote)>', '\n', text)
    text = re.sub(r'<(p|div|h[1-6])[\s>]', '\n', text)

    # Remove ALL HTML tags (including their attributes)
    text = re.sub(r'<[^>]+>', '', text)

    # Remove leftover HTML class/id attribute noise that sometimes leaks through
    # e.g. class="good highlight-default notranslate"
    text = re.sub(r'\bclass="[^"]*"', '', text)
    text = re.sub(r'\bid="[^"]*"', '', text)
    text = re.sub(r'\bhref="[^"]*"', '', text)
    text = re.sub(r'\bstyle="[^"]*"', '', text)

    # Decode all HTML entities (&#32;, &amp;, &#97;, etc.)
    text = unescape(text)

    # Remove any remaining HTML-like fragments
    text = re.sub(r'&[a-zA-Z]+;', '', text)  # catch any missed entities
    text = re.sub(r'&#\d+;', '', text)  # catch any missed numeric entities

    # Clean up whitespace
    text = re.sub(r'[ \t]+', ' ', text)  # collapse horizontal whitespace
    text = re.sub(r'\n\s*\n\s*\n', '\n\n', text)  # collapse multiple blank lines
    text = re.sub(r'^\s+$', '', text, flags=re.MULTILINE)  # remove whitespace-only lines
    text = text.strip()

    return text


def extract_sections(text, pep_id):
    """Split PEP text into sections based on headers."""
    # Split on lines that look like section headers (all caps or title case followed by newline)
    lines = text.split('\n')
    sections = []
    current_section = ""
    current_category = "General"

    for line in lines:
        stripped = line.strip()

        # Detect section headers — lines that are short, not empty, and look like titles
        if (stripped and
            len(stripped) < 80 and
            not stripped.startswith('>>>') and
            (stripped.istitle() or stripped.isupper()) and
            not stripped.endswith('.')):

            # Save previous section
            if current_section.strip():
                sections.append({
                    "pep_id": pep_id,
                    "category": current_category,
                    "text": current_section.strip()
                })
            current_category = stripped
            current_section = ""
        else:
            current_section += line + "\n"

    # Don't forget the last section
    if current_section.strip():
        sections.append({
            "pep_id": pep_id,
            "category": current_category,
            "text": current_section.strip()
        })

    return sections


def format_pep_document(section):
    """Format a PEP section as a text document for ingestion."""
    doc = f"""--- PEP STANDARD ---
PEP ID: {section['pep_id']}
Category: {section['category']}
Content:
{section['text']}
--- END PEP STANDARD ---
"""
    return doc


def main():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    all_docs = []
    total_sections = 0

    for pep_id, url in PEPS.items():
        print(f"Fetching {pep_id} from {url}")

        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            # Extract main content
            html = response.text

            # Try to get just the article content
            article_match = re.search(
                r'<article[^>]*>(.*?)</article>',
                html, re.DOTALL
            )
            if article_match:
                html = article_match.group(1)

            text = clean_html(html)
            sections = extract_sections(text, pep_id)

            for section in sections:
                if len(section["text"]) > 50:  # skip tiny sections
                    doc = format_pep_document(section)
                    all_docs.append(doc)
                    total_sections += 1

            print(f"  Extracted {len(sections)} sections from {pep_id}")

        except requests.RequestException as e:
            print(f"  Error fetching {pep_id}: {e}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(all_docs))

    print(f"\nDone! Saved {total_sections} PEP sections to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()