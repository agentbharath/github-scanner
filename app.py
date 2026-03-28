"""
GitHub Health Scanner — Streamlit UI
Provides a web interface for scanning GitHub repositories and displaying health reports.
"""

import streamlit as st
import json
from agent import github_scanner_agent

# Page config
st.set_page_config(
    page_title="GitHub Health Scanner",
    page_icon="🔍"
)

# Custom CSS
st.markdown("""
<style>
    .health-score-container {
        text-align: center;
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
    }
    .health-score {
        font-size: 72px;
        font-weight: bold;
    }
    .insight-box {
        padding: 12px;
        border-left: 4px solid #1976d2;
        background-color: #e3f2fd;
        margin-bottom: 8px;
        border-radius: 0 4px 4px 0;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.title("🔍 GitHub Health Scanner")
st.markdown("*Point it at any GitHub repo and get a complete health report — grounded in evidence, not guesses.*")

st.divider()

# Input
repo_url = st.text_input(
    "Enter GitHub Repository URL",
    placeholder="https://github.com/owner/repo",
    help="Enter the full GitHub URL or owner/repo format"
)

scan_button = st.button("🚀 Scan Repository", type="primary", use_container_width=True)


def get_score_color(score):
    """Return color based on score value."""
    if score >= 80:
        return "#4caf50"
    elif score >= 60:
        return "#ff9800"
    elif score >= 40:
        return "#ff5722"
    else:
        return "#f44336"


def get_score_label(score):
    """Return human-readable label for a score."""
    if score >= 80:
        return "Healthy"
    elif score >= 60:
        return "Moderate"
    elif score >= 40:
        return "At Risk"
    else:
        return "Unhealthy"


def get_severity_emoji(severity):
    """Return emoji for severity level."""
    emojis = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "🔵"
    }
    return emojis.get(severity, "⚪")


def get_dimension_emoji(dimension):
    """Return emoji for each dimension."""
    emojis = {
        "security": "🛡️",
        "code_quality": "💻",
        "documentation": "📄",
        "repo_hygiene": "🧹",
        "deprecations": "📦"
    }
    return emojis.get(dimension, "⚪")


def display_health_score(report):
    score = report["health_score"]
    color = get_score_color(score)
    label = get_score_label(score)

    st.markdown(f"""
    <div style="text-align:center; padding:20px; border:3px solid {color}; border-radius:10px; margin-bottom:20px;">
        <div style="color:{color}; font-size:72px; font-weight:bold;">{score}</div>
        <div style="font-size:20px; color:#666;">/ 100 — {label}</div>
        <div style="font-size:16px; margin-top:8px;">
            Repository: <strong>{report['repo']}</strong>
        </div>
    </div>
    """, unsafe_allow_html=True)

def get_dimension_explanation(key, score):
    """Return contextual explanation based on dimension and score."""
    if key == "security":
        if score >= 80: return "No major security issues detected"
        elif score >= 40: return "Some security concerns found — review recommended"
        else: return "Critical security risks — secrets exposed or vulnerabilities found"
    elif key == "code_quality":
        if score >= 80: return "Code is clean with minimal issues"
        elif score >= 40: return "Some code quality issues — unused imports or complex functions"
        else: return "Significant code quality problems — dead code, high complexity"
    elif key == "documentation":
        if score >= 80: return "Well documented with README, LICENSE, and docstrings"
        elif score >= 40: return "Partially documented — some key files missing"
        else: return "Poorly documented — missing README, LICENSE, or widespread missing docstrings"
    elif key == "repo_hygiene":
        if score >= 80: return "Good project setup with CI/CD, tests, and proper config"
        elif score >= 40: return "Some infrastructure gaps — missing CI or tests"
        else: return "Poor project hygiene — no CI/CD, no tests, or stale branches"
    elif key == "deprecations":
        if score >= 80: return "Dependencies are up to date"
        elif score >= 40: return "Some packages are outdated — upgrades recommended"
        else: return "Severely outdated dependencies with potential security risks"

def display_dimension_scores(report):
    st.subheader("📊 Dimension Scores")
    st.markdown("Each dimension is scored 0–100. Higher is healthier.")

    dimensions = report["dimension_scores"]
    dimension_info = {
        "security": "Security",
        "code_quality": "Code Quality",
        "documentation": "Documentation",
        "repo_hygiene": "Repo Hygiene",
        "deprecations": "Deprecations"
    }

    for key, data in dimensions.items():
        emoji = get_dimension_emoji(key)
        label = get_score_label(data["score"])
        explanation = get_dimension_explanation(key, data["score"])

        st.markdown(f"**{emoji} {dimension_info[key]}** — {data['score']}/100 ({label})")
        st.progress(data["score"] / 100)
        st.caption(explanation)


def display_findings(report):
    """Display findings sorted by severity."""
    st.subheader("🔎 Findings")

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        report["findings"],
        key=lambda f: severity_order.get(f["severity"], 5)
    )

    for finding in sorted_findings:
        severity = finding["severity"]
        severity_emoji = get_severity_emoji(severity)
        dimension_emoji = get_dimension_emoji(finding["dimension"])

        expander_label = f"{severity_emoji} [{severity.upper()}] {finding['title']}"

        with st.expander(expander_label, expanded=(severity in ["critical", "high"])):
            st.markdown(f"**Dimension:** {dimension_emoji} {finding['dimension'].replace('_', ' ').title()}")
            st.markdown(f"**Description:** {finding['description']}")

            st.info(f"📚 **Evidence:** {finding['evidence']}")
            st.success(f"💡 **Recommendation:** {finding['recommendation']}")


def display_cross_signal_insights(report):
    """Display cross-signal insights."""
    st.subheader("🧠 Cross-Signal Insights")
    st.markdown("These insights connect findings across dimensions to reveal amplified risks.")

    for insight in report.get("cross_signal_insights", []):
        st.markdown(f"""
        <div class="insight-box">
            💡 {insight}
        </div>
        """, unsafe_allow_html=True)


def display_deployment_risk(report):
    """Display deployment risk summary."""
    st.subheader("⚠️ Deployment Risk Summary")

    summary = report.get("deployment_risk_summary", "")

    if "HIGH RISK" in summary.upper():
        st.error(f"🚨 {summary}")
    elif "MEDIUM RISK" in summary.upper():
        st.warning(f"⚠️ {summary}")
    else:
        st.success(f"✅ {summary}")


# Main flow
if scan_button and repo_url:
    with st.spinner("Scanning repository... This may take a minute."):
        try:
            report = github_scanner_agent(repo_url)

            if "error" in report:
                st.error(f"Error generating report: {report['error']}")
                if "raw" in report:
                    with st.expander("Raw LLM Response"):
                        st.code(report["raw"])
            else:
                if report.get("skipped_checks"):
                    st.subheader("⏭️ Skipped Checks")
                    for skip in report["skipped_checks"]:
                        st.warning(skip)

                display_health_score(report)
                st.divider()
                display_dimension_scores(report)
                st.divider()
                display_deployment_risk(report)
                st.divider()
                display_findings(report)
                st.divider()
                display_cross_signal_insights(report)
                st.divider()

                # Raw data toggle
                with st.expander("📄 View Raw Report Data"):
                    st.json(report)

        except Exception as e:
            st.error(f"An error occurred: {str(e)}")
            st.info("Check that the repository URL is correct and the GitHub token is valid.")

elif scan_button:
    st.warning("Please enter a repository URL first.")