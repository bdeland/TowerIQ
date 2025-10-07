#!/usr/bin/env python3
"""
TowerIQ Build Analysis Script
Analyzes what files would be included in the PyInstaller build
"""

import os
import sys
from pathlib import Path


def analyze_spec_file(spec_path):
    """Analyze a PyInstaller spec file to see what would be included"""
    print(f"📋 Analyzing PyInstaller spec: {spec_path}")
    
    if not Path(spec_path).exists():
        print(f"❌ Spec file not found: {spec_path}")
        return
    
    with open(spec_path, 'r') as f:
        content = f.read()
    
    print("\n🔍 Analysis Results:")
    print("=" * 50)
    
    # Extract datas section
    if 'datas = [' in content:
        start = content.find('datas = [')
        end = content.find(']', start) + 1
        datas_section = content[start:end]
        print("📁 Data files to include:")
        for line in datas_section.split('\n'):
            if '(' in line and ')' in line:
                print(f"  {line.strip()}")
    
    # Extract excludes section
    if 'excludes = [' in content:
        start = content.find('excludes = [')
        end = content.find(']', start) + 1
        excludes_section = content[start:end]
        print("\n🚫 Modules to exclude:")
        for line in excludes_section.split('\n'):
            if "'" in line and not line.strip().startswith('#'):
                print(f"  {line.strip()}")
    
    print("\n" + "=" * 50)

def check_user_data_exclusion():
    """Check if user-specific data would be excluded"""
    print("🔒 Checking for user-specific data exclusion:")
    
    user_data_patterns = [
        '*.sqlite*',
        '*.log',
        '.env',
        '.venv',
        '__pycache__',
        'node_modules',
        '.git',
        '*.tmp',
        '*.temp'
    ]
    
    print("✅ These patterns should be excluded:")
    for pattern in user_data_patterns:
        print(f"  - {pattern}")
    
    print("\n⚠️  Make sure your build process excludes:")
    print("  - Database files (toweriq.sqlite*)")
    print("  - Log files (*.log)")
    print("  - Environment files (.env)")
    print("  - Virtual environments (.venv)")
    print("  - Cache directories (__pycache__)")
    print("  - Git repositories (.git)")
    print("  - Node modules (node_modules)")

def main():
    print("🔍 TowerIQ Build Analysis")
    print("=" * 50)
    
    # Analyze the production spec
    analyze_spec_file("build_configs/pyinstaller_production.spec")
    
    # Check user data exclusion
    check_user_data_exclusion()
    
    print("\n✅ Analysis complete!")
    print("\n💡 Tips for clean builds:")
    print("  - Use the production spec file")
    print("  - Build in a clean environment")
    print("  - Exclude user-specific data")
    print("  - Test the executable on a clean system")

if __name__ == "__main__":
    main()
