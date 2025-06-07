#!/usr/bin/env python3
"""
TowerIQ Foundation Test Script

This script tests the basic functionality of the foundational components
to ensure they work correctly before building the rest of the application.
"""

import asyncio
import sys
import os
from pathlib import Path

# Add src to path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent / "src"))

from tower_iq.core.config import ConfigurationManager
from tower_iq.core.logging_config import setup_logging
from tower_iq.core.session import SessionManager
from tower_iq.services.docker_service import DockerService
from tower_iq.services.database_service import DatabaseService

import structlog


async def test_configuration():
    """Test the configuration manager."""
    print("Testing Configuration Manager...")
    
    try:
        config_path = Path(__file__).parent / "config" / "main_config.yaml"
        env_path = Path(__file__).parent / ".env"
        
        config = ConfigurationManager(str(config_path), str(env_path))
        config.load_and_validate()
        
        # Test some basic config access
        app_name = config.get('app.name')
        log_level = config.get('logging.level')
        
        print(f"✓ Configuration loaded successfully")
        print(f"  App Name: {app_name}")
        print(f"  Log Level: {log_level}")
        
        return config
        
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return None


def test_logging(config):
    """Test the logging system."""
    print("\nTesting Logging System...")
    
    try:
        setup_logging(config)
        
        # Get a logger and test it
        logger = structlog.get_logger()
        logger = logger.bind(source="TestScript")
        
        logger.info("Logging system test message")
        logger.debug("Debug message")
        logger.warning("Warning message")
        
        print("✓ Logging system initialized successfully")
        return logger
        
    except Exception as e:
        import traceback
        print(f"✗ Logging test failed: {e}")
        print("Full traceback:")
        traceback.print_exc()
        return None


def test_session_manager():
    """Test the session manager."""
    print("\nTesting Session Manager...")
    
    try:
        session = SessionManager()
        
        # Test basic operations
        run_id = session.start_new_run()
        print(f"✓ Started new run: {run_id}")
        
        session.game_version = "1.0.0"
        session.is_emulator_connected = True
        
        status = session.get_status_summary()
        print(f"✓ Session status: {status}")
        
        session.end_run()
        print("✓ Session manager working correctly")
        
        return session
        
    except Exception as e:
        print(f"✗ Session manager test failed: {e}")
        return None


async def test_docker_service(config, logger):
    """Test the Docker service (basic initialization only)."""
    print("\nTesting Docker Service...")
    
    try:
        docker_service = DockerService(config, logger)
        
        # Just test initialization - don't actually start Docker
        print("✓ Docker service initialized successfully")
        
        # Test health check (will likely fail if Docker isn't running)
        try:
            healthy = await docker_service.is_healthy()
            print(f"  Docker health status: {healthy}")
        except Exception as e:
            print(f"  Docker health check failed (expected if Docker not running): {e}")
        
        return docker_service
        
    except Exception as e:
        print(f"✗ Docker service test failed: {e}")
        return None


async def test_database_service(config, logger):
    """Test the Database service (basic initialization only)."""
    print("\nTesting Database Service...")
    
    try:
        db_service = DatabaseService(config, logger)
        
        print("✓ Database service initialized successfully")
        
        # Don't actually connect to databases in this test
        # as they may not be available
        
        return db_service
        
    except Exception as e:
        print(f"✗ Database service test failed: {e}")
        return None


async def main():
    """Main test function."""
    print("TowerIQ Foundation Test")
    print("=" * 50)
    
    # Test configuration
    config = await test_configuration()
    if not config:
        print("\n❌ Foundation test failed - configuration issues")
        return 1
    
    # Test logging
    logger = test_logging(config)
    if not logger:
        print("\n❌ Foundation test failed - logging issues")
        return 1
    
    # Test session manager
    session = test_session_manager()
    if not session:
        print("\n❌ Foundation test failed - session manager issues")
        return 1
    
    # Test Docker service
    docker_service = await test_docker_service(config, logger)
    if not docker_service:
        print("\n❌ Foundation test failed - Docker service issues")
        return 1
    
    # Test Database service
    db_service = await test_database_service(config, logger)
    if not db_service:
        print("\n❌ Foundation test failed - Database service issues")
        return 1
    
    print("\n" + "=" * 50)
    print("✅ All foundation tests passed!")
    print("The TowerIQ foundation is ready for further development.")
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1) 