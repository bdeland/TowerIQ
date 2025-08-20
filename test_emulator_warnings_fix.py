#!/usr/bin/env python3
"""
Test script to verify emulator service warning fixes.
"""

import sys
import asyncio
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from tower_iq.core.config import ConfigurationManager
from tower_iq.core.logging_config import setup_logging
from tower_iq.services.emulator_service import EmulatorService, _SERVICE_PATTERNS, _FAILURE_PATTERNS
import structlog

async def test_package_filtering():
    """Test that the package filtering works correctly."""
    print("Testing package filtering improvements...")
    
    # Test packages that should be filtered out
    test_packages = [
        "com.android.inputmethod.latin",
        "com.android.systemui", 
        "com.bluestacks.BstCommandProcessor",
        "com.android.phone",
        "android.ext.services",
        "com.google.android.gms.persistent",
        "com.android.chrome",
        "com.uncube.launcher3",
        "com.google.android.gms",
        "com.bluestacks.home",
        "com.google.process.gapps",
        "com.android.vending",
        "com.google.android.gms.unstable",
        "com.android.vending:background",
        "com.android.chrome:webview_service",
        "com.android.vending:quick_launch",
        "com.android.vending:instant_app_installer",
        "com.google.android.gms.ui",
        "com.android.defcontainer",
        "com.android.gallery3d",
        "android.process.media",
        "com.TechTreeGames.TheTower",  # This should NOT be filtered
    ]
    
    # Initialize service
    app_root = Path(__file__).parent
    config = ConfigurationManager(str(app_root / 'config' / 'main_config.yaml'))
    setup_logging(config)
    logger = structlog.get_logger(__name__)
    
    service = EmulatorService(config, logger)
    
    print("\nTesting _is_valid_package_name method:")
    for package in test_packages:
        is_valid = service._is_valid_package_name(package)
        is_system = service._is_system_package(package)
        status = "✓ FILTERED" if not is_valid else "✗ NOT FILTERED"
        print(f"  {package:<40} {status} (system: {is_system})")
    
    print("\nTesting _is_system_package method:")
    for package in test_packages:
        is_system = service._is_system_package(package)
        status = "SYSTEM" if is_system else "USER"
        print(f"  {package:<40} {status}")
    
    print("\nPattern matching test:")
    print(f"  Service patterns: {len(_SERVICE_PATTERNS)}")
    print(f"  Failure patterns: {len(_FAILURE_PATTERNS)}")
    
    # Test specific patterns
    test_cases = [
        ("com.android.chrome", True, "Should be filtered (com.android.)"),
        ("com.google.android.gms", True, "Should be filtered (com.google.android.)"),
        ("com.bluestacks.home", True, "Should be filtered (com.bluestacks.)"),
        ("com.TechTreeGames.TheTower", False, "Should NOT be filtered (user app)"),
        ("com.android.vending:background", True, "Should be filtered (:background)"),
        ("com.android.chrome:webview_service", True, "Should be filtered (:webview_service)"),
    ]
    
    print("\nDetailed pattern testing:")
    for package, expected_filtered, description in test_cases:
        is_valid = service._is_valid_package_name(package)
        is_system = service._is_system_package(package)
        result = "✓ PASS" if (not is_valid) == expected_filtered else "✗ FAIL"
        print(f"  {package:<35} {result} - {description}")

if __name__ == "__main__":
    asyncio.run(test_package_filtering())
