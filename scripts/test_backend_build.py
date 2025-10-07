#!/usr/bin/env python3
"""
Test TowerIQ Backend Build
Tests just the backend build process without frontend dependencies
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path


def test_backend_build():
    """Test the backend build process"""
    print("🧪 Testing TowerIQ Backend Build")
    print("=" * 50)
    
    root_dir = Path(__file__).parent.parent
    build_dir = root_dir / "build"
    dist_dir = root_dir / "dist"
    
    # Clean previous builds
    print("🧹 Cleaning previous builds...")
    for dir_path in [build_dir, dist_dir]:
        if dir_path.exists():
            shutil.rmtree(dir_path)
        dir_path.mkdir(parents=True, exist_ok=True)
    
    # Create clean build environment
    print("🔧 Creating clean build environment...")
    temp_build_dir = root_dir / "temp_build"
    if temp_build_dir.exists():
        shutil.rmtree(temp_build_dir)
    temp_build_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy only essential files
    essential_dirs = ["src", "config", "resources", "build_configs"]
    for dir_name in essential_dirs:
        src_dir = root_dir / dir_name
        if src_dir.exists():
            dst_dir = temp_build_dir / dir_name
            shutil.copytree(src_dir, dst_dir, ignore=shutil.ignore_patterns(
                '*.pyc', '__pycache__', '.git', '.venv', 'node_modules',
                '*.log', '*.sqlite*', '.env', '*.tmp', '*.temp'
            ))
    
    try:
        # Change to temp build directory
        os.chdir(temp_build_dir)
        
        # Build with PyInstaller
        print("🐍 Building backend with PyInstaller...")
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--clean",
            "--noconfirm",
            "build_configs/pyinstaller_production.spec"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"❌ Backend build failed: {result.stderr}")
            return False
        
        # Check if executable was created
        built_exe = temp_build_dir / "dist" / "toweriq-backend.exe"
        if built_exe.exists():
            # Copy to main dist directory
            target_exe = dist_dir / "toweriq-backend.exe"
            shutil.copy2(built_exe, target_exe)
            print("✅ Backend executable created successfully!")
            print(f"📁 Location: {target_exe}")
            
            # Also copy to Tauri binaries folder with platform-specific name
            tauri_binaries = root_dir / "frontend" / "src-tauri" / "binaries"
            if tauri_binaries.exists():
                platform_exe = tauri_binaries / "toweriq-backend-x86_64-pc-windows-msvc.exe"
                shutil.copy2(built_exe, platform_exe)
                print(f"📁 Copied to Tauri binaries: {platform_exe}")
            
            # Check file size
            file_size = target_exe.stat().st_size
            print(f"📊 File size: {file_size / (1024*1024):.1f} MB")
            
            return True
        else:
            print("❌ Backend executable not found after build")
            return False
            
    except Exception as e:
        print(f"❌ Build failed: {e}")
        return False
    finally:
        # Return to original directory
        os.chdir(root_dir)
        # Clean up temp build directory
        if temp_build_dir.exists():
            try:
                shutil.rmtree(temp_build_dir)
            except PermissionError:
                print("⚠️ Could not clean temp build directory")

def main():
    success = test_backend_build()
    if success:
        print("\n🎉 Backend build test completed successfully!")
        print("\n💡 Next steps:")
        print("  - Test the executable: dist/toweriq-backend.exe")
        print("  - Build Tauri app: cd frontend && npm run tauri build")
        print("  - Verify installer doesn't include user-specific data")
        print("  - Test on a clean system")
    else:
        print("\n❌ Backend build test failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
