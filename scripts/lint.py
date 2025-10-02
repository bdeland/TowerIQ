#!/usr/bin/env python3
"""
Linting script for TowerIQ using Prospector.
Provides different linting modes for various use cases.
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path


def count_python_files(paths):
    """Count Python files in the given paths."""
    count = 0
    for path in paths:
        path_obj = Path(path)
        if path_obj.is_file() and path_obj.suffix == '.py':
            count += 1
        elif path_obj.is_dir():
            count += len(list(path_obj.rglob('*.py')))
    return count


def run_prospector(target_paths=None, strictness="medium", tools=None, output_format="grouped", verbose=False):
    """Run Prospector with specified configuration and progress reporting."""
    # Use the main source directory as the primary target
    if target_paths:
        # Use the first path (usually src/tower_iq) as the main target
        main_path = target_paths[0]
        cmd = ["prospector", main_path]
        
        # Add any additional paths as ignore patterns or run separately
        additional_paths = target_paths[1:] if len(target_paths) > 1 else []
    else:
        cmd = ["prospector"]
        additional_paths = []

    # Add configuration options
    cmd.extend([
        "--strictness", strictness,
        "--output-format", output_format
    ])

    if tools:
        cmd.extend(["--uses", ",".join(tools)])

    # Count files for progress reporting
    file_count = count_python_files(target_paths or [])
    
    print("=" * 60)
    print("TOWERIQ LINTING PROGRESS")
    print("=" * 60)
    print(f"Main target: {main_path if target_paths else 'default'}")
    if additional_paths:
        print(f"Additional paths: {', '.join(additional_paths)}")
    print(f"Python files found: {file_count}")
    print(f"Strictness level: {strictness}")
    print(f"Tools: {', '.join(tools) if tools else 'all configured tools'}")
    print(f"Output format: {output_format}")
    print(f"Working directory: {Path.cwd()}")
    print("-" * 60)
    print(f"Running: {' '.join(cmd)}")
    print("-" * 60)
    
    if verbose:
        print("Verbose mode: Detailed output enabled")
    
    start_time = time.time()
    
    try:
        # Run with real-time output if verbose
        if verbose:
            print("Starting linting process...")
            print(f"Debug: Executing command: {' '.join(cmd)}")
            try:
                process = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    bufsize=1
                )
                
                # Stream output in real-time
                while True:
                    if process.stdout is None:
                        break
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        print(f"   {output.strip()}")
                
                result = process.poll()
                if result is None:
                    print("WARNING: Process didn't complete properly")
                    result = 1
            except Exception as e:
                print(f"ERROR: Failed to run prospector in verbose mode: {e}")
                return 1
        else:
            # Show progress indicator for non-verbose mode
            print("Running linting analysis...")
            print(f"Debug: Executing command: {' '.join(cmd)}")
            print("   (Use --verbose to see real-time output)")
            try:
                result = subprocess.run(cmd, check=False, timeout=300).returncode  # 5 minute timeout
            except subprocess.TimeoutExpired:
                print("ERROR: Linting timed out after 5 minutes")
                return 124
            except Exception as e:
                print(f"ERROR: Failed to run prospector: {e}")
                return 1
        
        end_time = time.time()
        duration = end_time - start_time
        
        print("-" * 60)
        print("LINTING COMPLETE")
        print("-" * 60)
        print(f"Total execution time: {duration:.2f} seconds")
        print(f"Files processed: {file_count}")
        print(f"Exit code: {result}")
        
        if result == 0:
            print("SUCCESS: No issues found!")
        else:
            print("WARNING: Issues detected - see output above for details")
        
        return result
        
    except FileNotFoundError:
        print("ERROR: Prospector not found. Please install it with:")
        print("   pip install -r prospector-requirements.txt")
        print("   or")
        print("   poetry install")
        return 1
    except KeyboardInterrupt:
        print("\nSTOPPED: Linting interrupted by user")
        return 130


def find_project_root():
    """Find the project root directory by looking for pyproject.toml or README.md."""
    current = Path.cwd()
    for parent in [current] + list(current.parents):
        if (parent / "pyproject.toml").exists() or (parent / "README.md").exists():
            return parent
    return current


def main():
    parser = argparse.ArgumentParser(description="Run Prospector linting on TowerIQ codebase")
    parser.add_argument(
        "paths",
        nargs="*",
        default=None,  # Will be set based on project root
        help="Paths to lint (default: src/tower_iq, scripts, config from project root)"
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
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed real-time output during linting"
    )

    args = parser.parse_args()

    # Find project root and set default paths
    project_root = find_project_root()
    if not args.paths:  # Empty list or None
        # Set default paths relative to project root
        default_paths = ["src/tower_iq", "scripts", "config"]
        args.paths = [str(project_root / path) for path in default_paths]
    else:
        # Make paths absolute if they're relative
        resolved_paths = []
        for path in args.paths:
            path_obj = Path(path)
            if path_obj.is_absolute():
                resolved_paths.append(str(path_obj))
            else:
                # Try relative to project root first, then current directory
                project_path = project_root / path
                if project_path.exists():
                    resolved_paths.append(str(project_path))
                elif path_obj.exists():
                    resolved_paths.append(str(path_obj.absolute()))
                else:
                    resolved_paths.append(str(path_obj))
        args.paths = resolved_paths

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
    print("Debug: Checking paths:")
    print(f"Project root: {project_root}")
    print(f"Resolved paths: {args.paths}")
    for path in args.paths:
        path_obj = Path(path)
        exists = path_obj.exists()
        print(f"   {'[OK]' if exists else '[MISSING]'} {path}")
        if exists:
            valid_paths.append(str(path_obj))
        else:
            print(f"Warning: Path '{path}' does not exist, skipping...")

    if not valid_paths:
        print("Error: No valid paths found to lint")
        print(f"Project root detected: {project_root}")
        print("Available paths:")
        for item in sorted(project_root.iterdir()):
            if item.is_dir() and not item.name.startswith('.'):
                print(f"  - {item.name}/")
        return 1

    return run_prospector(
        target_paths=valid_paths,
        strictness=args.strictness,
        tools=tools,
        output_format=args.format,
        verbose=args.verbose
    )


if __name__ == "__main__":
    sys.exit(main())
