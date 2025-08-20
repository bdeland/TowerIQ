#!/usr/bin/env python3
"""
TowerIQ Logging Debug Script

This script tests the logging configuration to help diagnose logging issues.
Run this to see if logging is working properly.
"""

import sys
import os
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from tower_iq.core.config import ConfigurationManager
from tower_iq.core.logging_config import setup_logging
import structlog

def main():
    """Test the logging configuration."""
    print("=== TowerIQ Logging Debug ===")
    
    # Initialize configuration
    app_root = Path(__file__).parent
    config_path = app_root / 'config' / 'main_config.yaml'
    
    print(f"Config path: {config_path}")
    print(f"Config exists: {config_path.exists()}")
    
    if not config_path.exists():
        print("ERROR: Configuration file not found!")
        return 1
    
    try:
        config = ConfigurationManager(str(config_path))
        print("✓ Configuration loaded successfully")
        
        # Check logging settings
        console_enabled = config.get('logging.console.enabled', True)
        console_level = config.get('logging.console.level', 'INFO')
        file_enabled = config.get('logging.file.enabled', True)
        
        print(f"Console logging: {console_enabled} (level: {console_level})")
        print(f"File logging: {file_enabled}")
        
        # Set up logging
        setup_logging(config)
        print("✓ Logging configured successfully")
        
        # Test logging
        logger = structlog.get_logger()
        
        print("\n=== Testing Log Levels ===")
        logger.debug("This is a DEBUG message")
        logger.info("This is an INFO message")
        logger.warning("This is a WARNING message")
        logger.error("This is an ERROR message")
        
        print("\n=== Testing Different Sources ===")
        test_logger = structlog.get_logger().bind(source="TestSource")
        test_logger.info("This is a test message from TestSource")
        
        emulator_logger = structlog.get_logger().bind(source="EmulatorService")
        emulator_logger.info("This is a test message from EmulatorService")
        
        print("\n=== Logging Test Complete ===")
        print("If you can see the colored log messages above, logging is working correctly!")
        
        return 0
        
    except Exception as e:
        print(f"ERROR: Failed to initialize logging: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
