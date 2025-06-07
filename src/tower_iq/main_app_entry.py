"""
TowerIQ Main Application Entry Point

This module provides the main entry point for the TowerIQ application.
It initializes all core components and starts the application.
"""

import sys
import os
import asyncio
from pathlib import Path
from typing import Optional

import structlog

from .core.config import ConfigurationManager
from .core.logging_config import setup_logging
from .core.session import SessionManager
from .services.docker_service import DockerService
from .services.database_service import DatabaseService
from .main_controller import MainController


def get_config_paths() -> tuple[str, str]:
    """
    Get the paths to configuration files.
    
    Returns:
        Tuple of (yaml_path, env_path)
    """
    # Get the project root directory
    project_root = Path(__file__).parent.parent.parent
    
    yaml_path = project_root / "config" / "main_config.yaml"
    env_path = project_root / ".env"
    
    return str(yaml_path), str(env_path)


async def initialize_application() -> Optional[MainController]:
    """
    Initialize all application components.
    
    Returns:
        Initialized MainController instance or None if initialization failed
    """
    try:
        # Get configuration file paths
        yaml_path, env_path = get_config_paths()
        
        # Initialize configuration manager
        config = ConfigurationManager(yaml_path, env_path)
        config.load_and_validate()
        
        # Setup logging system
        setup_logging(config)
        
        # Get logger for this module
        logger = structlog.get_logger()
        logger = logger.bind(source="MainApp")
        
        logger.info("Starting TowerIQ application", version=config.get('app.version'))
        
        # Initialize session manager
        session_manager = SessionManager()
        
        # Initialize services
        docker_service = DockerService(config, logger)
        database_service = DatabaseService(config, logger)
        
        # Connect to databases
        await database_service.connect()
        
        # Initialize main controller
        main_controller = MainController(
            config=config,
            session_manager=session_manager,
            docker_service=docker_service,
            database_service=database_service,
            logger=logger
        )
        
        logger.info("Application initialization completed successfully")
        return main_controller
        
    except Exception as e:
        # If logging isn't set up yet, fall back to print
        try:
            logger = structlog.get_logger()
            logger.error("Failed to initialize application", error=str(e))
        except:
            print(f"FATAL: Failed to initialize application: {e}")
        
        return None


async def shutdown_application(main_controller: MainController) -> None:
    """
    Gracefully shutdown the application.
    
    Args:
        main_controller: The main controller instance to shutdown
    """
    logger = structlog.get_logger()
    logger = logger.bind(source="MainApp")
    
    try:
        logger.info("Shutting down TowerIQ application")
        
        # Shutdown main controller
        await main_controller.shutdown()
        
        logger.info("Application shutdown completed successfully")
        
    except Exception as e:
        logger.error("Error during application shutdown", error=str(e))


async def main_async() -> int:
    """
    Main async entry point for the application.
    
    Returns:
        Exit code (0 for success, 1 for error)
    """
    main_controller = None
    
    try:
        # Initialize application
        main_controller = await initialize_application()
        if not main_controller:
            return 1
        
        # Start the application
        await main_controller.start()
        
        # Keep the application running
        # In a real GUI application, this would be handled by the GUI event loop
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger = structlog.get_logger()
            logger.info("Received shutdown signal")
        
        return 0
        
    except Exception as e:
        try:
            logger = structlog.get_logger()
            logger.error("Unhandled exception in main", error=str(e))
        except:
            print(f"FATAL: Unhandled exception: {e}")
        return 1
        
    finally:
        # Ensure cleanup happens
        if main_controller:
            await shutdown_application(main_controller)


def main() -> int:
    """
    Main entry point for the application.
    
    Returns:
        Exit code (0 for success, 1 for error)
    """
    # Check Python version
    if sys.version_info < (3, 11):
        print("ERROR: TowerIQ requires Python 3.11 or higher")
        return 1
    
    # Set up asyncio event loop policy for Windows
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    # Run the async main function
    try:
        return asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        return 0
    except Exception as e:
        print(f"FATAL: Failed to start application: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 