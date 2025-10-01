#!/usr/bin/env python3
"""
Linting script for TowerIQ using Prospector.
Provides different linting modes for various use cases.
"""

import argparse
import subprocess
import sys
from pathlib import Path


def run_prospector(target_paths=None, strictness="medium", tools=None, output_format="grouped"):
    """Run Prospector with specified configuration."""
    cmd = ["prospector"]
    
    if target_paths:
        cmd.extend(target_paths)
    
    # Add configuration options
    cmd.extend([
        "--strictness", strictness,
        "--output-format", output_format
    ])
    
    if tools:
        cmd.extend(["--uses", ",".join(tools)])
    
    print(f"Running: {' '.join(cmd)}")
    print("-" * 60)
    
    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except FileNotFoundError:
        print("Error: Prospector not found. Please install it with:")
        print("  pip install -r prospector-requirements.txt")
        print("  or")
        print("  poetry install")
        return 1


def main():
    parser = argparse.ArgumentParser(description="Run Prospector linting on TowerIQ codebase")
    parser.add_argument(
        "paths", 
        nargs="*", 
        default=["backend", "scripts", "config"],
        help="Paths to lint (default: backend, scripts, config)"
    )
    parser.add_argument(
        "--strictness", 
        choices=["verylow", "low", "medium", "high", "veryhigh"],
        default="medium",
        help="Linting strictness level (default: medium)"
    )
    parser.add_argument(
        "--tools",
        help="Comma-separated list of tools to use (default: all configured tools)"
    )
    parser.add_argument(
        "--format",
        choices=["grouped", "json", "text", "pylint", "emacs", "vscode", "xunit", "yaml"],
        default="grouped",
        help="Output format (default: grouped)"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick linting with basic tools only"
    )
    parser.add_argument(
        "--security",
        action="store_true",
        help="Focus on security issues with bandit and dodgy"
    )
    parser.add_argument(
        "--type-check",
        action="store_true",
        help="Run type checking with mypy only"
    )
    
    args = parser.parse_args()
    
    # Determine which tools to use based on flags
    tools = None
    if args.tools:
        tools = args.tools.split(",")
    elif args.quick:
        tools = ["pyflakes", "pycodestyle"]
    elif args.security:
        tools = ["bandit", "dodgy"]
    elif args.type_check:
        tools = ["mypy"]
    
    # Validate paths exist
    valid_paths = []
    for path in args.paths:
        path_obj = Path(path)
        if path_obj.exists():
            valid_paths.append(path)
        else:
            print(f"Warning: Path '{path}' does not exist, skipping...")
    
    if not valid_paths:
        print("Error: No valid paths found to lint")
        return 1
    
    return run_prospector(
        target_paths=valid_paths,
        strictness=args.strictness,
        tools=tools,
        output_format=args.format
    )


if __name__ == "__main__":
    sys.exit(main())
