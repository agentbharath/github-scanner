import ast
import os
import requests
import json
from dotenv import load_dotenv
from utils import get_default_branch, get_repo_tree, get_file_content

load_dotenv()

github_token = os.getenv("GITHUB_TOKEN")
headers = {
    "Authorization": f"Bearer {github_token}",
    "Accept": "application/vnd.github+json"
}

# Nodes that increase code depth/complexity
CONTROL_NODES = (ast.If, ast.For, ast.While, ast.With, ast.AsyncWith, ast.Try)


def code_quality(code="", filename=""):
    """
    Analyze Python code for various quality metrics.

    Checks for:
    - Unused imports
    - Dead functions (defined but not called)
    - Missing docstrings
    - Function-level analysis including:
        length, number of parameters, nesting depth, and cyclomatic complexity

    Args:
        code (str): Python source code as a string.
        filename (str): Optional filename for reporting.

    Returns:
        dict: A dictionary containing findings including:
            - unused_imports
            - dead_functions
            - missing_docstrings
            - functions_analysis (metrics for each function)
    """
    tree = ast.parse(code, filename, mode="exec")
    imports = []
    functions = []
    references = []

    unused_imports = []
    dead_functions = []
    functions_analysis = []
    missing_docstrings = []

    for node in ast.walk(tree):
        # Check module-level docstring
        if isinstance(node, ast.Module):
            module_has_docstring = check_docstring(node)
            if not module_has_docstring:
                missing_docstrings.append({
                    "name": "module",
                    "line_number": 1,
                })

        # Analyze functions
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(get_function_info(node))
            has_docstrings = check_docstring(node)
            if not has_docstrings:
                missing_docstrings.append({
                    "name": node.name,
                    "line_number": node.lineno,
                })

            function_analysis = {
                "function_name": node.name,
                "function_length": get_function_length(node),
                "function_params": get_function_params(node),
                "function_depth": get_function_depth(node, 0),
                "function_complexity": get_function_complexity(node),
                "function_lineno": node.lineno
            }
            functions_analysis.append(function_analysis)

        # Track imports and references
        elif isinstance(node, ast.Import):
            imports.append(get_import_info(node))
        elif isinstance(node, ast.ImportFrom):
            imports.append(get_module_info(node))
        elif isinstance(node, ast.Name):
            references.append(get_name_info(node))

    ref_names = [ref["name"] for ref in references]

    # Identify unused imports
    for imp in imports:
        if imp["name"] not in ref_names:
            unused_imports.append(imp)

    # Identify dead functions
    for fun in functions:
        if fun["name"] not in ref_names:
            dead_functions.append(fun)

    findings = {
        "filename": filename,
        "findings": {
            "unused_imports": unused_imports,
            "dead_functions": dead_functions,
            "missing_docstrings": missing_docstrings,
            "functions_analysis": functions_analysis
        }
    }
    return findings


def check_docstring(node: ast.FunctionDef) -> bool:
    """
    Determine whether an AST node has a docstring.

    Args:
        node (ast.FunctionDef | ast.Module): Function or module AST node.

    Returns:
        bool: True if a docstring exists, False otherwise.
    """
    return (
        len(node.body) > 0 and
        isinstance(node.body[0], ast.Expr) and
        isinstance(node.body[0].value, ast.Constant) and
        isinstance(node.body[0].value.value, str)
    )


def get_function_info(node: ast.FunctionDef) -> dict:
    """
    Extract basic information about a function.

    Args:
        node (ast.FunctionDef): AST node representing the function.

    Returns:
        dict: Dictionary with function name and line number.
    """
    return {
        "name": node.name,
        "line_number": node.lineno,
    }


def get_import_info(node: ast.Import) -> dict:
    """
    Extract information about a direct import.

    Args:
        node (ast.Import): AST import node.

    Returns:
        dict: Dictionary with imported module name and line number.
    """
    return {
        "name": node.names[0].name,
        "line_number": node.lineno
    }


def get_module_info(node: ast.ImportFrom) -> dict:
    """
    Extract information about a module-level import (from ... import ...).

    Args:
        node (ast.ImportFrom): AST import-from node.

    Returns:
        dict: Dictionary with module name and line number.
    """
    return {
        "name": node.module,
        "line_number": node.lineno
    }


def get_name_info(node: ast.Name) -> dict:
    """
    Extract the name and line number of a variable reference.

    Args:
        node (ast.Name): AST Name node.

    Returns:
        dict: Dictionary with variable name and line number.
    """
    return {
        "name": node.id,
        "line_number": node.lineno
    }


def get_function_length(node: ast.FunctionDef) -> int:
    """
    Calculate the length of a function in lines.

    Args:
        node (ast.FunctionDef): Function AST node.

    Returns:
        int: Number of lines the function spans.
    """
    return node.end_lineno - node.lineno + 1


def get_function_params(node: ast.FunctionDef) -> int:
    """
    Count the total number of parameters for a function.

    Args:
        node (ast.FunctionDef): Function AST node.

    Returns:
        int: Total count of positional, keyword-only, and positional-only args.
    """
    args = node.args
    return len(args.args) + len(args.posonlyargs) + len(args.kwonlyargs)


def get_function_depth(node: ast.FunctionDef, depth: int = 0) -> int:
    """
    Compute the maximum nesting depth of control structures in a function.

    Args:
        node (ast.FunctionDef): Function AST node.
        depth (int): Current depth during recursion.

    Returns:
        int: Maximum nesting depth.
    """
    max_depth = depth
    for child in ast.iter_child_nodes(node):
        if isinstance(child, CONTROL_NODES):
            child_depth = get_function_depth(child, depth + 1)
        else:
            child_depth = get_function_depth(child, depth)
        max_depth = max(max_depth, child_depth)
    return max_depth


def get_function_complexity(node: ast.FunctionDef) -> int:
    """
    Calculate the cyclomatic complexity of a function.

    Args:
        node (ast.FunctionDef): Function AST node.

    Returns:
        int: Cyclomatic complexity score based on control nodes and boolean operations.
    """
    complexity = 0
    for child in ast.walk(node):
        if isinstance(child, CONTROL_NODES):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            complexity += len(child.values) - 1
    return complexity


if __name__ == "__main__":
    """
    Main entry point for analyzing a GitHub repository.

    Prompts the user for a GitHub repository URL, fetches all Python files,
    runs code quality analysis, and prints a JSON report.
    """
    userInput = input("Enter your github repo name in the format of https://github.com/username/reponame: ")
    userInputSplit = userInput.split('/')
    owner = userInputSplit[-2]
    repo_name = userInputSplit[-1]

    findings = []
    default_branch = get_default_branch(owner, repo_name)
    repo_tree = get_repo_tree(owner, repo_name, default_branch)

    for tree in repo_tree["tree"]:
        path = tree["path"]
        if path.lower().endswith('.py'):
            source_code = get_file_content(owner, repo_name, path)
            code_finding = code_quality(source_code, path)
            findings.append(code_finding)

    print("Findings: ", json.dumps(findings, indent=2))