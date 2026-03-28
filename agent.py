"""
GitHub Repository Health Scanner Agent

This module defines a LangChain ReAct agent that performs automated health
analysis of a GitHub repository. The agent orchestrates multiple tools that:

1. Scan repository structure and metadata
2. Analyze Python code quality via AST parsing
3. Detect vulnerable and deprecated dependencies

The collected findings are then summarized into a final health report.
"""

import json
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from langchain.agents import create_react_agent, AgentExecutor
from langchain.schema import SystemMessage, HumanMessage, AIMessage
from langchain import hub

from scan_structure import scan_structure
from scan_code_quality import scan_code_quality
from check_vulnerabilites import scan_vulnerabilities_and_deprecations
from config import config
from generate_health import generate_health_report


# Initialize the LLM used by the agent
llm = ChatOpenAI(
    model=config["GPT_MODEL"],
    temperature=0
)


@tool
def scan_structure_tool(repo: str) -> dict:
    """
    LangChain tool: Repository Structure Scanner.

    This tool inspects the high-level structure and metadata of a GitHub repository.

    It retrieves and analyzes:
    - Repository file tree
    - Presence of README
    - Branch list
    - CI/CD configuration
    - Last commit date
    - Contributor count

    Args:
        repo (str): GitHub repository URL.

    Returns:
        dict: Structured findings about repository organization and activity.
    """
    return scan_structure(repo)


@tool
def scan_code_quality_tool(repo: str) -> dict:
    """
    LangChain tool: Python Code Quality Analyzer.

    This tool downloads Python source files and analyzes them using Python's AST.

    It detects:
    - Unused imports
    - Dead functions
    - Function complexity
    - General maintainability signals

    Args:
        repo (str): GitHub repository URL.

    Returns:
        dict: Static analysis findings related to code quality.
    """
    return scan_code_quality(repo)


@tool
def scan_vulnerabilities_and_deprecations_tool(repo: str) -> dict:
    """
    LangChain tool: Dependency Security Scanner.

    This tool checks project dependencies against a RAG index built from:
    - CVE/NVD vulnerability database
    - PyPI security advisories

    It identifies:
    - Known vulnerable packages
    - Deprecated dependencies
    - Severity classifications

    Args:
        repo (str): GitHub repository URL.

    Returns:
        dict: Security and dependency risk findings.
    """
    return scan_vulnerabilities_and_deprecations(repo)


# List of tools available to the agent
TOOLS_AVAILABLE = [
    scan_structure_tool,
    scan_code_quality_tool,
    scan_vulnerabilities_and_deprecations_tool,
]


def run_agent(repo: str) -> dict:
    """
    Execute the ReAct agent to scan a GitHub repository.

    The agent decides which tools to call and in what order.
    Intermediate tool outputs are captured and mapped into a structured
    findings dictionary.

    Args:
        repo (str): GitHub repository URL to analyze.

    Returns:
        dict: Aggregated tool outputs containing:
              - structure_findings
              - code_quality_findings
              - vulnerability_findings
    """
    agent = create_react_agent(
        llm=llm,
        tools=TOOLS_AVAILABLE,
        prompt=hub.pull("hwchase17/react")
    )

    executor = AgentExecutor(
        agent=agent,
        tools=TOOLS_AVAILABLE,
        verbose=True,
        return_intermediate_steps=True,
        handle_parsing_errors=True
    )

    response = executor.invoke({"input": f"Scan this GitHub repo: {repo}"})

    tool_output = {}

    # Extract tool results from intermediate ReAct steps
    for action, result in response["intermediate_steps"]:
        if action.tool == "scan_structure_tool":
            tool_output["structure_findings"] = result
        elif action.tool == "scan_code_quality_tool":
            tool_output["code_quality_findings"] = result
        elif action.tool == "scan_vulnerabilities_and_deprecations_tool":
            tool_output["vulnerability_findings"] = result

    return tool_output


def github_scanner_agent(repo: str) -> dict:
    """
    High-level orchestration function for repository health analysis.

    This function:
    1. Runs the scanning agent
    2. Aggregates all findings
    3. Generates a final health report

    Args:
        repo (str): GitHub repository URL.

    Returns:
        dict: Final health report summarizing repository quality,
              risks, and recommendations.
    """
    findings = run_agent(repo)

    health_report = generate_health_report(
        findings["structure_findings"],
        findings["code_quality_findings"],
        findings["vulnerability_findings"]
    )

    return health_report
