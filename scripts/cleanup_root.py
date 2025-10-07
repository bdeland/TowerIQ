#!/usr/bin/env python3
"""
TowerIQ Root Directory Cleanup Script
Cleans up build artifacts and temporary files while preserving essential configuration
"""

import os
import shutil
import sys
from pathlib import Path

# Fix Windows console encoding for emojis
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')


def cleanup_root():
    """Clean up root directory"""
    root = Path(__file__).parent.parent
    
    print("🧹 TowerIQ Root Directory Cleanup")
    print("=" * 50)
    
    # Files to remove
    files_to_remove = [
        ".coverage",
        ".prospector.yaml",
        "pyproject.toml.user",
        "requirements.txt",
    ]
    
    # Directories to remove
    dirs_to_remove = [
        "__pycache__",
        "build",
        "_reports",
    ]
    
    # Move TEST_REPORTING.md to docs
    test_reporting = root / "TEST_REPORTING.md"
    if test_reporting.exists():
        target = root / "docs" / "TEST_REPORTING.md"
        if not target.exists():
            print(f"📄 Moving TEST_REPORTING.md to docs/")
            shutil.move(str(test_reporting), str(target))
        else:
            print(f"⚠️  docs/TEST_REPORTING.md already exists, removing root version")
            test_reporting.unlink()
    
    # Remove files
    print("\n🗑️  Removing unnecessary files:")
    for filename in files_to_remove:
        filepath = root / filename
        if filepath.exists():
            print(f"   - {filename}")
            filepath.unlink()
        else:
            print(f"   ✓ {filename} (already removed)")
    
    # Remove directories
    print("\n🗑️  Removing build artifacts and caches:")
    for dirname in dirs_to_remove:
        dirpath = root / dirname
        if dirpath.exists():
            print(f"   - {dirname}/")
            shutil.rmtree(dirpath)
        else:
            print(f"   ✓ {dirname}/ (already removed)")
    
    # Handle dist/ specially - keep the latest backend
    dist_dir = root / "dist"
    if dist_dir.exists():
        backend_exe = dist_dir / "toweriq-backend.exe"
        if backend_exe.exists():
            print(f"\n⚠️  dist/ contains toweriq-backend.exe")
            print(f"   This is needed for Tauri builds!")
            print(f"   Keeping dist/ directory")
        else:
            # Check for old backend name
            old_backend = dist_dir / "TowerIQ-Backend.exe"
            if old_backend.exists():
                print(f"\n🔄 Renaming old backend: TowerIQ-Backend.exe → toweriq-backend.exe")
                old_backend.rename(backend_exe)
            else:
                print(f"\n⚠️  dist/ exists but no backend found")
                response = input("   Remove dist/ directory? (y/N): ")
                if response.lower() == 'y':
                    shutil.rmtree(dist_dir)
                    print(f"   Removed dist/")
    
    # Info about logs and memory
    print("\n📝 Optional cleanup (not automatically removed):")
    
    logs_dir = root / "logs"
    if logs_dir.exists():
        log_files = list(logs_dir.glob("*.log*"))
        print(f"   - logs/ ({len(log_files)} log files)")
        print(f"     To remove: Remove-Item logs -Recurse -Force")
    
    memory_dir = root / "memory"
    if memory_dir.exists():
        memory_files = list(memory_dir.glob("*.jsonl"))
        print(f"   - memory/ ({len(memory_files)} memory files)")
        print(f"     To remove: Remove-Item memory -Recurse -Force")
    
    node_modules = root / "node_modules"
    if node_modules.exists():
        print(f"   - node_modules/ (root-level, for monorepo)")
        print(f"     To remove: Remove-Item node_modules -Recurse -Force")
        print(f"     Restore with: npm install")
    
    print("\n✅ Cleanup complete!")
    print("\n📋 Configuration files kept (required in root):")
    essential_files = [
        "poetry.lock", "pyproject.toml",
        "package.json", "package-lock.json",
        "pytest.ini", "pyrightconfig.json",
        "jest.config.js", ".python-version",
        ".gitignore", ".gitattributes"
    ]
    for filename in essential_files:
        if (root / filename).exists():
            print(f"   ✓ {filename}")
    
    print("\n💡 Tip: Add these to your .gitignore:")
    print("   .coverage")
    print("   pyproject.toml.user")
    print("   .prospector.yaml")


if __name__ == "__main__":
    try:
        cleanup_root()
    except Exception as e:
        print(f"\n❌ Error during cleanup: {e}")
        import traceback
        traceback.print_exc()

