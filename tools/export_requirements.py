"""Utility for exporting Poetry's main dependencies to requirements.txt.

This is a minimal drop-in replacement for ``poetry export`` when the
``poetry-plugin-export`` plugin is unavailable (e.g. in offline
environments). The script reads ``poetry.lock`` and writes a
``requirements.txt`` that contains the pinned runtime dependencies from
the ``main`` dependency group while preserving platform markers.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11 or newer is required to parse poetry.lock")

import tomllib


def build_requirements(lock_path: Path) -> list[str]:
    """Return sorted requirement specifiers from a Poetry lock file."""
    data = tomllib.loads(lock_path.read_text())
    lines: list[tuple[str, str]] = []
    for package in data.get("package", []):
        groups = package.get("groups", [])
        if "main" not in groups:
            continue

        marker = package.get("markers")
        if isinstance(marker, dict):
            marker = marker.get("main")

        name = package["name"]
        version = package["version"]
        requirement = f"{name}=={version}"
        if marker:
            requirement = f"{requirement} ; {marker}"

        lines.append((name.lower(), requirement))

    return [entry for _, entry in sorted(lines)]


def write_requirements(requirements: list[str], output_path: Path) -> None:
    header = "# This requirements.txt was generated from poetry.lock.\n"
    output_path.write_text(header + "\n".join(requirements) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lock",
        type=Path,
        default=Path("poetry.lock"),
        help="Path to the Poetry lock file (default: poetry.lock)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("requirements.txt"),
        help="Target requirements.txt file (default: requirements.txt)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    requirements = build_requirements(args.lock)
    write_requirements(requirements, args.output)


if __name__ == "__main__":
    main()
