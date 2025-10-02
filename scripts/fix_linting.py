#!/usr/bin/env python3
"""
Automated script to fix common linting issues found by Prospector.
"""

import re
from pathlib import Path
import sys


def fix_trailing_whitespace(content: str) -> str:
    """Remove trailing whitespace from all lines."""
    lines = content.split('\n')
    fixed_lines = [line.rstrip() for line in lines]
    return '\n'.join(fixed_lines)


def fix_missing_final_newline(content: str) -> str:
    """Ensure file ends with a newline."""
    if content and not content.endswith('\n'):
        return content + '\n'
    return content


def fix_trailing_newlines(content: str) -> str:
    """Remove excessive trailing newlines, keep only one."""
    content = content.rstrip('\n')
    if content:
        return content + '\n'
    return content


def fix_unnecessary_comprehension(content: str) -> str:
    """Fix unnecessary list comprehensions like list(iter)."""
    # Pattern: list(something) -> list(something)
    pattern = r'\[(\w+)\s+for\s+\1\s+in\s+([^\]]+)\]'
    replacement = r'list(\2)'
    return re.sub(pattern, replacement, content)


def fix_no_else_return(content: str) -> str:
    """Remove unnecessary else after return (basic cases)."""
    # This is complex and risky to automate, so we'll skip it
    return content


def process_file(file_path: Path, dry_run: bool = False) -> bool:
    """Process a single Python file and apply fixes."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()

        content = original_content

        # Apply fixes in order
        content = fix_trailing_whitespace(content)
        content = fix_unnecessary_comprehension(content)
        content = fix_trailing_newlines(content)
        content = fix_missing_final_newline(content)

        # Check if anything changed
        if content != original_content:
            if not dry_run:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"Fixed: {file_path}")
            else:
                print(f"Would fix: {file_path}")
            return True
        return False

    except Exception as e:
        print(f"Error processing {file_path}: {e}", file=sys.stderr)
        return False


def main():
    """Main function to process all Python files."""
    import argparse

    parser = argparse.ArgumentParser(description="Fix common linting issues")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be fixed without making changes"
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["src/tower_iq", "scripts", "config"],
        help="Paths to process (default: src/tower_iq, scripts, config)"
    )

    args = parser.parse_args()

    # Find all Python files
    python_files = []
    for path_str in args.paths:
        path = Path(path_str)
        if not path.exists():
            print(f"Warning: Path {path} does not exist, skipping")
            continue

        if path.is_file() and path.suffix == '.py':
            python_files.append(path)
        elif path.is_dir():
            python_files.extend(path.rglob('*.py'))

    # Exclude test files and __pycache__
    python_files = [
        f for f in python_files
        if '__pycache__' not in str(f) and not str(f).startswith('tests')
    ]

    print(f"Processing {len(python_files)} Python files...")

    fixed_count = 0
    for file_path in python_files:
        if process_file(file_path, dry_run=args.dry_run):
            fixed_count += 1

    print(f"\nTotal files {'would be' if args.dry_run else ''} fixed: {fixed_count}/{len(python_files)}")


if __name__ == "__main__":
    main()
